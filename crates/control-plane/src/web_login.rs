use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, header},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{ControlPlane, Error, Id, Result, account_network, credential_digest, proof, random};

const LOGIN: &str = "__Host-howl-login";
const OWNER: &str = "__Host-howl-owner";
const CALLBACK: &str = "/login/github/callback";

pub(crate) fn routes() -> Router<Arc<ControlPlane>> {
    Router::new()
        .route("/login/github", get(start))
        .route(CALLBACK, get(callback))
        .route("/logout", post(logout))
        .route("/api/session", get(session))
        .layer(middleware::map_response(
            |mut response: Response| async move {
                response.headers_mut().insert(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                );
                response
            },
        ))
}

fn origin(control: &ControlPlane) -> Result<&str> {
    control.web_origin.as_deref().ok_or(Error::Unauthorized)
}

pub(crate) fn same_origin(control: &ControlPlane, headers: &HeaderMap) -> Result<()> {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if origins.next().map(HeaderValue::as_bytes) != Some(origin(control)?.as_bytes())
        || origins.next().is_some()
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for item in header.to_str().map_err(|_| Error::Unauthorized)?.split(';') {
            let Some((key, value)) = item.trim().split_once('=') else {
                continue;
            };
            if key != name {
                continue;
            }
            if found.is_some() || value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit())
            {
                return Err(Error::Unauthorized);
            }
            found = Some(value);
        }
    }
    found.ok_or(Error::Unauthorized)
}

fn set_cookie(response: &mut Response, name: &str, value: &str, lifetime: u32) -> Result<()> {
    let policy = if name == LOGIN { "Lax" } else { "Strict" };
    let mut value = HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite={policy}; Max-Age={lifetime}"
    ))
    .map_err(|_| Error::Internal)?;
    value.set_sensitive(true);
    response.headers_mut().append(header::SET_COOKIE, value);
    Ok(())
}

async fn start(State(control): State<Arc<ControlPlane>>) -> Result<Response> {
    let redirect = format!("{}{CALLBACK}", origin(&control)?);
    let state = random()?;
    let verifier = Zeroizing::new(hex::encode(random()?));
    let digest = proof::hash(verifier.as_bytes());
    let target = control.github.authorize_url(
        &redirect,
        &hex::encode(state),
        &URL_SAFE_NO_PAD.encode(digest),
    )?;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    tx.execute(
        "DELETE FROM howl_control.web_logins WHERE expires_at <= now()",
        &[],
    )
    .await?;
    tx.execute(
        "INSERT INTO howl_control.web_logins (state_digest,verifier_digest,expires_at)
         VALUES ($1,$2,now()+interval '10 minutes')",
        &[&&proof::hash(&state)[..], &&digest[..]],
    )
    .await?;
    tx.commit().await?;
    let mut response = Redirect::to(&target).into_response();
    set_cookie(&mut response, LOGIN, &verifier, 600)?;
    Ok(response)
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: String,
}

async fn callback(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Query(params): Query<Callback>,
) -> Result<Response> {
    let redirect = format!("{}{CALLBACK}", origin(&control)?);
    let state = credential_digest(&params.state).map_err(|_| Error::Unauthorized)?;
    let verifier = cookie(&headers, LOGIN)?;
    let consumed = control
        .pool
        .get()
        .await?
        .execute(
            "DELETE FROM howl_control.web_logins WHERE state_digest=$1 AND verifier_digest=$2
         AND expires_at > now()",
            &[&&state[..], &&proof::hash(verifier.as_bytes())[..]],
        )
        .await?;
    if consumed != 1 {
        return Err(Error::Unauthorized);
    }
    let Some(code) = params.code.filter(|v| !v.is_empty() && v.len() <= 256) else {
        let mut response = Redirect::to("/devices").into_response();
        set_cookie(&mut response, LOGIN, "", 0)?;
        return Ok(response);
    };
    let user = control.github.web_user(&code, &redirect, verifier).await?;
    let github_id = user.id;
    let mut connection = control.pool.get().await?;
    let tx = connection.transaction().await?;
    account_network::ensure(&control, &tx, github_id).await?;
    tx.execute(
        "UPDATE howl_control.networks SET github_login=$2
         WHERE github_id=$1 AND github_login IS DISTINCT FROM $2",
        &[&github_id, &user.login],
    )
    .await?;
    if let Ok(old) = session_digest(&headers) {
        tx.execute(
            "DELETE FROM howl_control.web_sessions WHERE token_digest=$1",
            &[&&old[..]],
        )
        .await?;
    }
    tx.execute(
        "DELETE FROM howl_control.web_sessions WHERE expires_at <= now()",
        &[],
    )
    .await?;
    let token = Zeroizing::new(random()?);
    tx.execute(
        "INSERT INTO howl_control.web_sessions (token_digest,github_id,expires_at)
         VALUES ($1,$2,now()+interval '12 hours')",
        &[&&proof::hash(&token[..])[..], &github_id],
    )
    .await?;
    tx.commit().await?;
    let mut response = Redirect::to("/devices").into_response();
    set_cookie(&mut response, LOGIN, "", 0)?;
    set_cookie(&mut response, OWNER, &hex::encode(&token[..]), 43_200)?;
    Ok(response)
}

fn session_digest(headers: &HeaderMap) -> Result<Id> {
    credential_digest(cookie(headers, OWNER)?).map_err(|_| Error::Unauthorized)
}

pub(crate) async fn owner(control: &ControlPlane, headers: &HeaderMap) -> Result<i64> {
    origin(control)?;
    let digest = session_digest(headers)?;
    let row = control.pool.get().await?.query_opt(
        "SELECT github_id FROM howl_control.web_sessions WHERE token_digest=$1 AND expires_at > now()",
        &[&&digest[..]],
    ).await?.ok_or(Error::Unauthorized)?;
    Ok(row.get(0))
}

#[derive(serde::Serialize)]
struct OwnerSession {
    github_id: i64,
}

async fn session(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> Result<axum::Json<OwnerSession>> {
    Ok(axum::Json(OwnerSession {
        github_id: owner(&control, &headers).await?,
    }))
}

async fn logout(State(control): State<Arc<ControlPlane>>, headers: HeaderMap) -> Result<Response> {
    same_origin(&control, &headers)?;
    let digest = session_digest(&headers)?;
    control
        .pool
        .get()
        .await?
        .execute(
            "DELETE FROM howl_control.web_sessions WHERE token_digest=$1",
            &[&&digest[..]],
        )
        .await?;
    let mut response = Redirect::to("/devices").into_response();
    set_cookie(&mut response, OWNER, "", 0)?;
    set_cookie(&mut response, LOGIN, "", 0)?;
    Ok(response)
}
