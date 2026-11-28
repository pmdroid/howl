use std::collections::HashMap;

use axum::{
    Form,
    http::{HeaderValue, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Url, redirect::Policy};

use super::*;

const ORIGIN: &str = "https://howl.example";

fn cookie_pair(response: &Response, name: &str) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().unwrap().split(';').next())
        .find(|pair| pair.split_once('=').unwrap().0 == name)
        .unwrap()
        .to_owned()
}

async fn exchange(Form(fields): Form<HashMap<String, String>>) -> Json<Value> {
    assert_eq!(fields["client_id"], "fixtureapp");
    assert_eq!(fields["client_secret"], "fixture_secret");
    assert_eq!(
        fields["redirect_uri"],
        format!("{ORIGIN}/login/github/callback")
    );
    assert_eq!(fields["code"], "code-from-github");
    assert_eq!(fields["code_verifier"].len(), 64);
    Json(json!({"access_token": GH_TOKEN}))
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL roles"]
async fn browser_login_binds_callback_and_revokes_owner_session() {
    let admin = pool("HOWL_TEST_CONTROL_DATABASE_OWNER");
    migrate(&admin).await.unwrap();
    let id = i64::from_be_bytes(crate::random().unwrap()[..8].try_into().unwrap())
        .saturating_abs()
        .max(1);
    let policy = Arc::new(Provider::default());
    let provider = serve(
        Router::new()
            .route("/login/oauth/access_token", post(exchange))
            .route(
                "/user",
                get(move |headers| async move { github_user(headers, id) }),
            )
            .route("/applications/fixtureapp/grant", delete(upstream_revoke))
            .with_state(policy.clone()),
    )
    .await;
    let github = GitHub::new("fixtureapp".into(), Zeroizing::new("fixture_secret".into()))
        .unwrap()
        .fixture(provider.url.clone());
    let mut control = ControlPlane::new(
        pool("HOWL_TEST_CONTROL_DATABASE_RUNTIME"),
        github,
        AUDIENCE,
        Zeroizing::new([3; 32]),
    )
    .unwrap();
    control.web_origin = Some(ORIGIN.into());
    let control = Arc::new(control);
    let server = serve(control.clone().router()).await;
    let http = Client::builder().redirect(Policy::none()).build().unwrap();
    let start = http
        .get(format!("{}/login/github", server.url))
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let auth_url = Url::parse(start.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(auth_url.path(), "/login/oauth/authorize");
    let query = auth_url.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(
        query["redirect_uri"],
        format!("{ORIGIN}/login/github/callback")
    );
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["scope"], "");
    let binding = cookie_pair(&start, "__Host-howl-login");
    let verifier = binding.split_once('=').unwrap().1;
    assert_eq!(
        query["code_challenge"],
        URL_SAFE_NO_PAD.encode(proof::hash(verifier.as_bytes()))
    );
    assert!(
        start.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Secure; HttpOnly; SameSite=Lax")
    );
    let callback = format!(
        "{}/login/github/callback?code=code-from-github&state={}",
        server.url, query["state"]
    );
    for wrong in [
        String::new(),
        format!("__Host-howl-login={}", hex::encode([11; 32])),
        format!("{binding}; {binding}"),
    ] {
        assert_eq!(
            http.get(&callback)
                .header(header::COOKIE, wrong)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let db = admin.get().await.unwrap();
    assert!(
        db.query_opt(
            "SELECT 1 FROM howl_control.networks WHERE github_id=$1",
            &[&id]
        )
        .await
        .unwrap()
        .is_none()
    );
    let logged_in = http
        .get(&callback)
        .header(header::COOKIE, &binding)
        .send()
        .await
        .unwrap();
    assert_eq!(logged_in.status(), StatusCode::SEE_OTHER);
    assert_eq!(logged_in.headers()[header::LOCATION], "/devices");
    assert_eq!(policy.revoked.load(Ordering::SeqCst), 1);
    assert_eq!(
        db.query_one(
            "SELECT github_login FROM howl_control.networks WHERE github_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "fixture-renameable"
    );
    let session = cookie_pair(&logged_in, "__Host-howl-owner");
    assert!(
        logged_in
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|h| h
                .to_str()
                .unwrap()
                .contains("Secure; HttpOnly; SameSite=Strict"))
    );
    let dashboard = success(
        http.get(format!("{}/api/devices", server.url))
            .header(header::COOKIE, &session)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(dashboard["account_managed"], true);
    assert_eq!(dashboard["pending"], json!([]));
    assert_eq!(dashboard["approved"], json!([]));
    assert_eq!(
        hex::decode(dashboard["network"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, HeaderValue::from_str(&session).unwrap());
    assert_eq!(
        crate::web_login::owner(&control, &headers).await.unwrap(),
        id
    );
    assert_eq!(
        http.get(&callback)
            .header(header::COOKIE, &binding)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let logout = format!("{}/logout", server.url);
    assert_eq!(
        http.post(&logout)
            .header(header::COOKIE, &session)
            .header(header::ORIGIN, "https://another.example")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        crate::web_login::owner(&control, &headers).await.unwrap(),
        id
    );
    assert_eq!(
        http.post(&logout)
            .header(header::COOKIE, &session)
            .header(header::ORIGIN, ORIGIN)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SEE_OTHER
    );
    assert!(matches!(
        crate::web_login::owner(&control, &headers).await,
        Err(crate::Error::Unauthorized)
    ));
}
