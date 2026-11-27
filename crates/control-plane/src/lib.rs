use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use zeroize::Zeroizing;

mod github;
mod login;
pub mod mailbox;
mod proof;
mod sessions;

pub use github::GitHub;
pub use proof::{Id, Proof, credential_digest, signing_bytes};
pub use sessions::{Credentials, PendingSession};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Configuration,
    Invalid,
    Unauthorized,
    Wait,
    Upstream,
    Internal,
}

impl From<tokio_postgres::Error> for Error {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::Internal
    }
}

impl From<deadpool_postgres::PoolError> for Error {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::Internal
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Configuration | Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Wait => (StatusCode::TOO_MANY_REQUESTS, "wait_for_poll_interval"),
            Self::Upstream => (StatusCode::BAD_GATEWAY, "github_unavailable"),
        };
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

pub struct ControlPlane {
    pool: Pool,
    github: GitHub,
    audience: Id,
    state_key: Zeroizing<Id>,
}

impl ControlPlane {
    pub fn new(pool: Pool, github: GitHub, audience: Id, state_key: Zeroizing<Id>) -> Result<Self> {
        if audience == [0; 32] || *state_key == [0; 32] {
            return Err(Error::Configuration);
        }
        Ok(Self {
            pool,
            github,
            audience,
            state_key,
        })
    }

    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/healthz", get(health))
            .route("/v1/login/device", post(begin_login))
            .route("/v1/login/device/{id}/poll", post(poll_login))
            .route("/v1/auth/challenge", post(challenge))
            .route("/v1/auth/session", get(session))
            .route("/v1/auth/refresh", post(refresh))
            .route("/v1/auth/revoke", post(revoke))
            .layer(DefaultBodyLimit::max(4096))
            .layer(middleware::from_fn(no_cache))
            .with_state(self)
    }
}

pub async fn migrate(pool: &Pool) -> Result<()> {
    let mut connection = pool.get().await?;
    let tx = connection.transaction().await?;
    tx.query_one("SELECT pg_advisory_xact_lock(4983033826038031201)", &[])
        .await?;
    tx.batch_execute(include_str!("../migrations/001_auth.sql"))
        .await?;
    tx.commit().await?;
    Ok(())
}

fn random() -> Result<Id> {
    let mut result = [0; 32];
    getrandom::fill(&mut result).map_err(|_| Error::Internal)?;
    Ok(result)
}

fn id(row: &Row, column: usize) -> Result<Id> {
    row.try_get::<_, &[u8]>(column)?
        .try_into()
        .map_err(|_| Error::Internal)
}

async fn health(State(control): State<Arc<ControlPlane>>) -> StatusCode {
    match control.pool.get().await {
        Ok(connection) if connection.query_one("SELECT 1", &[]).await.is_ok() => {
            StatusCode::NO_CONTENT
        }
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn no_cache(request: axum::extract::Request, next: middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

async fn begin_login(
    State(control): State<Arc<ControlPlane>>,
    Json(candidate): Json<login::Candidate>,
) -> Result<Json<login::Login>> {
    control.begin_login(candidate).await.map(Json)
}

async fn poll_login(
    State(control): State<Arc<ControlPlane>>,
    Path(id): Path<String>,
    Json(proof): Json<Proof>,
) -> Result<Json<login::LoginStatus>> {
    control
        .poll_login(proof::decode(&id)?, &proof)
        .await
        .map(Json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    operation: String,
    login: Option<String>,
}

#[derive(Serialize)]
struct Nonce {
    nonce: String,
}

async fn challenge(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Json(request): Json<Challenge>,
) -> Result<Json<Nonce>> {
    let nonce = match (request.operation.as_str(), request.login) {
        ("poll", Some(login)) => control.login_challenge(&login).await?,
        (_, None) => {
            control
                .session_challenge(&request.operation, bearer(&headers)?)
                .await?
        }
        _ => return Err(Error::Invalid),
    };
    Ok(Json(Nonce {
        nonce: hex::encode(nonce),
    }))
}

async fn session(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
) -> Result<Json<PendingSession>> {
    let token = bearer(&headers)?;
    let proof = Proof {
        nonce: header_value(&headers, "howl-nonce")?.into(),
        signature: header_value(&headers, "howl-signature")?.into(),
    };
    control
        .authorize("session", token, &proof, b"")
        .await
        .map(Json)
}

async fn refresh(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Json(proof): Json<Proof>,
) -> Result<Json<Credentials>> {
    control.refresh(bearer(&headers)?, &proof).await.map(Json)
}

async fn revoke(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    Json(proof): Json<Proof>,
) -> Result<StatusCode> {
    control.revoke(bearer(&headers)?, &proof).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    header_value(headers, "authorization")?
        .strip_prefix("Bearer ")
        .filter(|token| token.len() == 64)
        .ok_or(Error::Unauthorized)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::Unauthorized)
}
