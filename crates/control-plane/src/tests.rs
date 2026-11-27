use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
};
use deadpool_postgres::{Manager, Pool};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::{Client, Response};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_postgres::NoTls;
use zeroize::Zeroizing;

use crate::{ControlPlane, GitHub, Id, credential_digest, migrate, proof, signing_bytes};

const AUDIENCE: Id = [2; 32];
const DEVICE: Id = [4; 32];
const DEVICE_CODE: &str = "0123456789012345678901234567890123456789";
const GH_TOKEN: &str = "ghu_fixture_only";

#[derive(Default)]
struct Provider {
    polls: AtomicUsize,
    revoked: AtomicUsize,
}

struct Server {
    url: String,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(router: Router) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    Server {
        url: format!("http://{address}"),
        task: tokio::spawn(async move { axum::serve(listener, router).await.unwrap() }),
    }
}

async fn start(form: String) -> Json<Value> {
    assert_eq!(form, "client_id=fixtureapp");
    Json(json!({
        "device_code": DEVICE_CODE, "user_code": "ABCD-EFGH",
        "verification_uri": "https://github.com/login/device", "interval": 1, "expires_in": 900,
    }))
}

async fn upstream_poll(State(provider): State<Arc<Provider>>, form: String) -> Json<Value> {
    assert!(form.contains(&format!("device_code={DEVICE_CODE}")));
    assert!(form.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"));
    assert!(!form.contains("client_secret") && !form.contains("scope="));
    match provider.polls.fetch_add(1, Ordering::SeqCst) {
        0 => Json(json!({"error":"authorization_pending"})),
        1 => Json(json!({"error":"slow_down","interval":8})),
        _ => Json(json!({"access_token":GH_TOKEN,"refresh_token":"ghr_fixture_only"})),
    }
}

async fn user(headers: HeaderMap) -> Json<Value> {
    assert_eq!(
        headers["authorization"].to_str().unwrap(),
        format!("Bearer {GH_TOKEN}")
    );
    Json(json!({"id":1234567,"login":"fixture-renameable"}))
}

async fn upstream_revoke(
    State(provider): State<Arc<Provider>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> StatusCode {
    assert!(
        headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Basic ")
    );
    assert_eq!(request, json!({"access_token":GH_TOKEN}));
    provider.revoked.fetch_add(1, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

fn pool(name: &str) -> Pool {
    Pool::builder(Manager::new(
        std::env::var(name).unwrap().parse().unwrap(),
        NoTls,
    ))
    .max_size(4)
    .build()
    .unwrap()
}

async fn success(response: Response) -> Value {
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "unexpected status {status}: {body}");
    assert!(
        !body.contains(DEVICE_CODE)
            && !body.contains(GH_TOKEN)
            && !body.contains("ghr_fixture_only")
    );
    serde_json::from_str(&body).unwrap()
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn sign(key: &SigningKey, subject: &str, op: &str, nonce: &str, token: Option<&str>) -> Value {
    let bytes = signing_bytes(
        AUDIENCE,
        proof::decode(subject).unwrap(),
        op,
        proof::decode(nonce).unwrap(),
        token
            .map(|token| credential_digest(token).unwrap())
            .unwrap_or_default(),
        b"",
    );
    json!({ "nonce": nonce, "signature": hex::encode(key.sign(&bytes).to_bytes()) })
}

async fn challenge(http: &Client, url: &str, op: &str, token: &str) -> String {
    let result = success(
        http.post(format!("{url}/v1/auth/challenge"))
            .bearer_auth(token)
            .json(&json!({"operation":op}))
            .send()
            .await
            .unwrap(),
    )
    .await;
    string(&result, "nonce").to_owned()
}

async fn allow_poll(pool: &Pool) {
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE howl_control.pending_logins SET next_poll = clock_timestamp()",
            &[],
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance with owner and runtime fixture roles"]
async fn device_login_rejects_replays_and_rotates_or_revokes_device_bound_credentials() {
    let owner = pool("HOWL_TEST_CONTROL_DATABASE_OWNER");
    migrate(&owner).await.unwrap();
    migrate(&owner).await.unwrap();
    let runtime = pool("HOWL_TEST_CONTROL_DATABASE_RUNTIME");
    assert!(
        runtime
            .get()
            .await
            .unwrap()
            .execute("CREATE TABLE howl_control.denied (id integer)", &[])
            .await
            .is_err()
    );
    let upstream = Arc::new(Provider::default());
    let provider = serve(
        Router::new()
            .route("/login/device/code", post(start))
            .route("/login/oauth/access_token", post(upstream_poll))
            .route("/user", get(user))
            .route("/applications/fixtureapp/grant", delete(upstream_revoke))
            .with_state(upstream.clone()),
    )
    .await;
    let github = GitHub::new("fixtureapp".into(), Zeroizing::new("fixture_secret".into()))
        .unwrap()
        .fixture(provider.url.clone());
    let control = Arc::new(
        ControlPlane::new(runtime.clone(), github, AUDIENCE, Zeroizing::new([3; 32])).unwrap(),
    );
    let server = serve(control.router()).await;
    let http = Client::new();
    let url = &server.url;
    let key = SigningKey::from_bytes(&[9; 32]);
    let wrong_key = SigningKey::from_bytes(&[10; 32]);
    let start = success(http.post(format!("{url}/v1/login/device")).json(&json!({
        "device_id":hex::encode(DEVICE), "signing_key":hex::encode(key.verifying_key().to_bytes()),
    })).send().await.unwrap()).await;
    assert_eq!(start["user_code"], "ABCD-EFGH");
    let row = owner
        .get()
        .await
        .unwrap()
        .query_one("SELECT provider_code FROM howl_control.pending_logins", &[])
        .await
        .unwrap();
    assert!(
        !row.get::<_, Vec<u8>>(0)
            .windows(DEVICE_CODE.len())
            .any(|bytes| bytes == DEVICE_CODE.as_bytes())
    );
    let login = string(&start, "login");
    let poll = format!("{url}/v1/login/device/{login}/poll");
    let initial_nonce = string(&start, "nonce");
    let wrong = sign(&wrong_key, login, "poll", initial_nonce, None);
    assert_eq!(
        http.post(&poll).json(&wrong).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let signed = sign(&key, login, "poll", initial_nonce, None);
    assert_eq!(
        http.post(&poll)
            .json(&signed)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(upstream.polls.load(Ordering::SeqCst), 0);
    allow_poll(&owner).await;
    let pending = success(http.post(&poll).json(&signed).send().await.unwrap()).await;
    assert_eq!(pending["state"], "pending");
    assert_eq!(
        http.post(&poll)
            .json(&signed)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    allow_poll(&owner).await;
    let slow = success(
        http.post(&poll)
            .json(&sign(&key, login, "poll", string(&pending, "nonce"), None))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(slow["interval"], 8);
    allow_poll(&owner).await;
    let logged_in = success(
        http.post(&poll)
            .json(&sign(&key, login, "poll", string(&slow, "nonce"), None))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(logged_in["state"], "verified");
    assert_eq!(upstream.revoked.load(Ordering::SeqCst), 1);
    let credentials = &logged_in["credentials"];
    let session = &credentials["session"];
    assert_eq!(session["github_id"], 1234567);
    assert_eq!(session["device_id"], hex::encode(DEVICE));
    assert!(session.get("trusted").is_none());
    let subject = string(session, "id");
    let access = string(credentials, "access_token");
    let refresh = string(credentials, "refresh_token");
    let session_nonce = challenge(&http, url, "session", access).await;
    let prove = sign(&key, subject, "session", &session_nonce, Some(access));
    let session_url = format!("{url}/v1/auth/session");
    let session_request = || {
        http.get(&session_url)
            .bearer_auth(access)
            .header("howl-nonce", &session_nonce)
            .header("howl-signature", string(&prove, "signature"))
    };
    assert_eq!(
        success(session_request().send().await.unwrap()).await,
        *session
    );
    assert_eq!(
        session_request().send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let rotate = format!("{url}/v1/auth/refresh");
    let nonce = challenge(&http, url, "refresh", refresh).await;
    let refresh_proof = sign(&key, subject, "refresh", &nonce, Some(refresh));
    let request = || {
        http.post(&rotate)
            .bearer_auth(refresh)
            .json(&refresh_proof)
            .send()
    };
    let (a, b) = tokio::join!(request(), request());
    let (a, b) = (a.unwrap(), b.unwrap());
    let (winner, loser) = if a.status().is_success() {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(loser.status(), StatusCode::UNAUTHORIZED);
    let rotated = success(winner).await;
    let next_refresh = string(&rotated, "refresh_token");
    assert_ne!(refresh, next_refresh);
    let revoke_nonce = challenge(&http, url, "revoke", next_refresh).await;
    let spent_nonce = challenge(&http, url, "refresh", refresh).await;
    assert_eq!(
        http.post(&rotate)
            .bearer_auth(refresh)
            .json(&sign(
                &wrong_key,
                subject,
                "refresh",
                &spent_nonce,
                Some(refresh)
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let revoked = http
        .post(format!("{url}/v1/auth/revoke"))
        .bearer_auth(next_refresh)
        .json(&sign(
            &key,
            subject,
            "revoke",
            &revoke_nonce,
            Some(next_refresh),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let denied = http
        .post(format!("{url}/v1/auth/challenge"))
        .bearer_auth(access)
        .json(&json!({"operation":"session"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let mut fixture = runtime.get().await.unwrap();
    let tx = fixture.transaction().await.unwrap();
    let replay = crate::sessions::begin(&tx, 1234567, DEVICE, key.verifying_key().to_bytes())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let nonce = challenge(&http, url, "refresh", &replay.refresh_token).await;
    let rotated = success(
        http.post(&rotate)
            .bearer_auth(&replay.refresh_token)
            .json(&sign(
                &key,
                &replay.session.id,
                "refresh",
                &nonce,
                Some(&replay.refresh_token),
            ))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let spent = challenge(&http, url, "refresh", &replay.refresh_token).await;
    assert_eq!(
        http.post(&rotate)
            .bearer_auth(&replay.refresh_token)
            .json(&sign(
                &key,
                &replay.session.id,
                "refresh",
                &spent,
                Some(&replay.refresh_token)
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.post(format!("{url}/v1/auth/challenge"))
            .bearer_auth(string(&rotated, "access_token"))
            .json(&json!({"operation": "session"}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
