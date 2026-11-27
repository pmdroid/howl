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

async fn allow_poll(pool: &Pool, login: &[u8; 32]) {
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE howl_control.pending_logins SET next_poll = clock_timestamp() WHERE id = $1",
            &[&&login[..]],
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
    let login = string(&start, "login");
    let login_id = proof::decode::<32>(login).unwrap();
    let row = owner
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT provider_code FROM howl_control.pending_logins WHERE id = $1",
            &[&&login_id[..]],
        )
        .await
        .unwrap();
    assert!(
        !row.get::<_, Vec<u8>>(0)
            .windows(DEVICE_CODE.len())
            .any(|bytes| bytes == DEVICE_CODE.as_bytes())
    );
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
    allow_poll(&owner, &login_id).await;
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
    allow_poll(&owner, &login_id).await;
    let slow = success(
        http.post(&poll)
            .json(&sign(&key, login, "poll", string(&pending, "nonce"), None))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(slow["interval"], 8);
    allow_poll(&owner, &login_id).await;
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

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance with owner and runtime fixture roles"]
async fn hosted_enrollment_requires_a_current_independent_pin_and_pairing_certificate() {
    use crate::{EnrollmentPin, pin_enrollment};
    use howl::enrollment::{Authority, AuthorityRecord, Designation, Floor};

    let owner = pool("HOWL_TEST_CONTROL_DATABASE_OWNER");
    migrate(&owner).await.unwrap();
    let runtime = pool("HOWL_TEST_CONTROL_DATABASE_RUNTIME");
    let temp = tempfile::tempdir().unwrap();
    let device_path = temp.path().join("device");
    let identity = enrollment_identity(&device_path, [20, 21, 22, 23]);
    let device_key = SigningKey::from_bytes(&[21; 32]);
    let peer = identity.certificate();
    let root = SigningKey::from_bytes(&[24; 32]);
    let recovery = SigningKey::from_bytes(&[25; 32]);
    let membership = SigningKey::from_bytes(&[26; 32]);
    let genesis = AuthorityRecord::genesis(&root, &recovery);
    let account = genesis.digest();
    let head = Authority::import([genesis.clone()], account, account)
        .unwrap()
        .head()
        .unwrap();
    let designation = Designation::issue(head, 1, &root, &membership, &[]).unwrap();
    let material = enrollment_material(
        &temp.path().join("owner"),
        &identity,
        &genesis,
        &designation,
        &membership,
    );
    let encoded = serde_json::to_vec(&material).unwrap();
    let github_id = 7654321;
    let mut connection = runtime.get().await.unwrap();
    let tx = connection.transaction().await.unwrap();
    let credentials = crate::sessions::begin(
        &tx,
        github_id,
        *peer.device_id(),
        device_key.verifying_key().to_bytes(),
    )
    .await
    .unwrap();
    let other_key = SigningKey::from_bytes(&[27; 32]);
    let substitute = crate::sessions::begin(
        &tx,
        github_id,
        [28; 32],
        other_key.verifying_key().to_bytes(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    drop(connection);
    let github = GitHub::new("fixtureapp".into(), Zeroizing::new("fixture_secret".into())).unwrap();
    let control = Arc::new(
        ControlPlane::new(runtime.clone(), github, AUDIENCE, Zeroizing::new([3; 32])).unwrap(),
    );
    let server = serve(control.clone().router()).await;
    let http = Client::new();
    let endpoint = format!("{}/v1/enrollment/device", server.url);
    let pin = || EnrollmentPin {
        github_id,
        account_id: account,
        authority_head: head.digest,
        designation_digest: designation.digest(),
    };
    let send = |nonce: String, signature: String, credential: &str, bytes: Vec<u8>| {
        http.post(&endpoint)
            .bearer_auth(credential)
            .header("howl-nonce", nonce)
            .header("howl-signature", signature)
            .body(bytes)
            .send()
    };
    let proof = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "enrollment",
        &encoded,
    )
    .await;
    assert_eq!(
        send(
            proof.nonce,
            proof.signature,
            &credentials.access_token,
            encoded.clone()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(pin_enrollment(&runtime, pin()).await.is_err());
    pin_enrollment(&owner, pin()).await.unwrap();

    let wrong = enrollment_proof(
        &http,
        &server.url,
        &substitute,
        &other_key,
        "enrollment",
        &encoded,
    )
    .await;
    assert_eq!(
        send(
            wrong.nonce,
            wrong.signature,
            &substitute.access_token,
            encoded.clone()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let proof = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "enrollment",
        &encoded,
    )
    .await;
    assert_eq!(
        send(
            proof.nonce.clone(),
            proof.signature.clone(),
            &credentials.access_token,
            encoded.clone()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(
            proof.nonce,
            proof.signature,
            &credentials.access_token,
            encoded.clone()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );

    let read = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "enrollment-read",
        peer.device_id(),
    )
    .await;
    let public = http
        .get(format!("{endpoint}/{}", credentials.session.device_id))
        .bearer_auth(&credentials.access_token)
        .header("howl-nonce", read.nonce)
        .header("howl-signature", read.signature)
        .send()
        .await
        .unwrap();
    assert_eq!(success(public).await, material);
    let trusted = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "mailbox",
        b"",
    )
    .await;
    assert_eq!(
        control
            .authorize_enrolled("mailbox", &credentials.access_token, &trusted, b"")
            .await
            .unwrap()
            .account_id(),
        account
    );

    let other_path = temp.path().join("other-device");
    let other_identity = enrollment_identity(&other_path, [28, 27, 29, 30]);
    let other_material = enrollment_material(
        &temp.path().join("owner"),
        &other_identity,
        &genesis,
        &designation,
        &membership,
    );
    let other_material = serde_json::to_vec(&other_material).unwrap();
    let proof = enrollment_proof(
        &http,
        &server.url,
        &substitute,
        &other_key,
        "enrollment",
        &other_material,
    )
    .await;
    assert_eq!(
        send(
            proof.nonce,
            proof.signature,
            &substitute.access_token,
            other_material
        )
        .await
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );

    let discovery = format!("{}/v1/discovery/hints", server.url);
    let issued = howl::discovery::now().unwrap();
    let latest = signed_hint(&peer, &device_key, issued, 4101);
    let stale = signed_hint(&peer, &device_key, issued - 1, 4100);
    let conflict = signed_hint(&peer, &device_key, issued, 4102);
    let published = send_hint(
        &http,
        &server.url,
        &credentials,
        &device_key,
        &peer,
        &latest,
    )
    .await;
    assert_eq!(published, StatusCode::NO_CONTENT);
    assert_eq!(
        send_hint(
            &http,
            &server.url,
            &credentials,
            &device_key,
            &peer,
            &latest
        )
        .await,
        StatusCode::NO_CONTENT
    );
    for rejected in [&stale, &conflict] {
        assert_eq!(
            send_hint(
                &http,
                &server.url,
                &credentials,
                &device_key,
                &peer,
                rejected
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
    }
    let mut tampered = latest;
    tampered[99] ^= 1;
    assert_eq!(
        send_hint(
            &http,
            &server.url,
            &credentials,
            &device_key,
            &peer,
            &tampered
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    let lookup = format!("{discovery}/{}", credentials.session.device_id);
    let proof = enrollment_proof(
        &http,
        &server.url,
        &substitute,
        &other_key,
        "discovery-read",
        peer.device_id(),
    )
    .await;
    let returned = http
        .get(&lookup)
        .bearer_auth(&substitute.access_token)
        .header("howl-nonce", &proof.nonce)
        .header("howl-signature", &proof.signature)
        .send()
        .await
        .unwrap();
    assert_eq!(returned.status(), StatusCode::OK);
    assert_eq!(
        returned.headers()["content-type"],
        "application/octet-stream"
    );
    assert_eq!(&returned.bytes().await.unwrap()[..], &latest);
    let wrong = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "discovery-read",
        &[128; 32],
    )
    .await;
    let mismatched = http
        .get(&lookup)
        .bearer_auth(&credentials.access_token)
        .header("howl-nonce", wrong.nonce)
        .header("howl-signature", wrong.signature)
        .send()
        .await
        .unwrap();
    assert_eq!(mismatched.status(), StatusCode::UNAUTHORIZED);

    let updated = Designation::issue(
        head,
        2,
        &root,
        &membership,
        &[Floor {
            device: *peer.device_id(),
            sequence: 1,
        }],
    )
    .unwrap();
    pin_enrollment(
        &owner,
        EnrollmentPin {
            designation_digest: updated.digest(),
            ..pin()
        },
    )
    .await
    .unwrap();
    let trusted = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "mailbox",
        b"",
    )
    .await;
    assert!(
        control
            .authorize_enrolled("mailbox", &credentials.access_token, &trusted, b"")
            .await
            .is_err()
    );
    let proof = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "discovery-read",
        peer.device_id(),
    )
    .await;
    let denied = http
        .get(&lookup)
        .bearer_auth(&credentials.access_token)
        .header("howl-nonce", proof.nonce)
        .header("howl-signature", proof.signature)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let old = enrollment_proof(
        &http,
        &server.url,
        &credentials,
        &device_key,
        "enrollment",
        &encoded,
    )
    .await;
    assert_eq!(
        send(old.nonce, old.signature, &credentials.access_token, encoded)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

async fn enrollment_proof(
    http: &Client,
    url: &str,
    credentials: &crate::Credentials,
    key: &SigningKey,
    operation: &str,
    body: &[u8],
) -> crate::Proof {
    let nonce = challenge(http, url, operation, &credentials.access_token).await;
    let bytes = signing_bytes(
        AUDIENCE,
        proof::decode(&credentials.session.id).unwrap(),
        operation,
        proof::decode(&nonce).unwrap(),
        credential_digest(&credentials.access_token).unwrap(),
        body,
    );
    crate::Proof {
        nonce,
        signature: hex::encode(key.sign(&bytes).to_bytes()),
    }
}

fn signed_hint(
    peer: &howl::identity::PeerCertificate,
    key: &SigningKey,
    issued: u64,
    port: u16,
) -> [u8; howl::discovery::HINT_LEN] {
    let mut record = [0; howl::discovery::HINT_LEN];
    record[0] = 1;
    record[1..33].copy_from_slice(peer.device_id());
    record[33..65].copy_from_slice(&peer.fingerprint());
    record[65..73].copy_from_slice(&issued.to_be_bytes());
    record[73..81].copy_from_slice(&(issued + 60_000).to_be_bytes());
    record[81..86].copy_from_slice(&[4, 192, 0, 2, 1]);
    record[98..100].copy_from_slice(&port.to_be_bytes());
    let signed = [b"howl/peer-address/v1\0".as_slice(), &record[..100]].concat();
    record[100..].copy_from_slice(&key.sign(&signed).to_bytes());
    record
}

async fn send_hint(
    http: &Client,
    url: &str,
    credentials: &crate::Credentials,
    key: &SigningKey,
    peer: &howl::identity::PeerCertificate,
    hint: &[u8],
) -> StatusCode {
    let bytes = [peer.as_bytes().as_slice(), hint].concat();
    let proof = enrollment_proof(http, url, credentials, key, "discovery-write", &bytes).await;
    http.post(format!("{url}/v1/discovery/hints"))
        .bearer_auth(&credentials.access_token)
        .header("howl-nonce", proof.nonce)
        .header("howl-signature", proof.signature)
        .body(bytes)
        .send()
        .await
        .unwrap()
        .status()
}

fn enrollment_identity(path: &std::path::Path, material: [u8; 4]) -> howl::identity::LocalIdentity {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    let record = [
        vec![1],
        material.into_iter().flat_map(|byte| [byte; 32]).collect(),
    ]
    .concat();
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("device-v1"))
        .unwrap()
        .write_all(&record)
        .unwrap();
    howl::identity::LocalIdentity::load_or_create(path).unwrap()
}

fn enrollment_material(
    state: &std::path::Path,
    identity: &howl::identity::LocalIdentity,
    genesis: &howl::enrollment::AuthorityRecord,
    designation: &howl::enrollment::Designation,
    membership: &SigningKey,
) -> Value {
    use howl::enrollment::{Enroll, PairingTicket};
    let peer = identity.certificate();
    let (ticket, offer) =
        PairingTicket::create(designation, membership, &peer, peer.fingerprint(), 1, 100).unwrap();
    let response = offer
        .respond(designation, identity, ticket.invitation_secret(), 110)
        .unwrap();
    let certificate = ticket
        .enroll(Enroll {
            state,
            designation,
            signer: membership,
            peer: &peer,
            offer: &offer,
            response: &response,
            now: 110,
        })
        .unwrap();
    json!({"authority":[hex::encode(genesis.as_bytes())], "designation":hex::encode(designation.as_bytes()),
        "certificate":hex::encode(certificate.as_bytes())})
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL roles and HOWL_TEST_CONTROL_CLI pointing to the built Howl binary"]
async fn native_login_persists_private_credentials_and_enrolls_through_refresh() {
    use crate::{EnrollmentPin, pin_enrollment};
    use howl::enrollment::{Authority, AuthorityRecord, AuthorityStore, Designation};
    use std::{fs, os::unix::fs::PermissionsExt};

    let binary = std::env::var_os("HOWL_TEST_CONTROL_CLI").unwrap();
    let owner = pool("HOWL_TEST_CONTROL_DATABASE_OWNER");
    migrate(&owner).await.unwrap();
    let runtime = pool("HOWL_TEST_CONTROL_DATABASE_RUNTIME");
    let upstream = Arc::new(Provider {
        polls: AtomicUsize::new(2),
        revoked: AtomicUsize::new(0),
    });
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
    let control =
        Arc::new(ControlPlane::new(runtime, github, AUDIENCE, Zeroizing::new([3; 32])).unwrap());
    let server = serve(control.router()).await;
    let root = tempfile::tempdir().unwrap();
    let device = root.path().join("device");
    let identity = enrollment_identity(&device, [61, 62, 63, 64]);
    let root_key = SigningKey::from_bytes(&[65; 32]);
    let recovery = SigningKey::from_bytes(&[66; 32]);
    let membership = SigningKey::from_bytes(&[67; 32]);
    let genesis = AuthorityRecord::genesis(&root_key, &recovery);
    let account = genesis.digest();
    let head = Authority::import([genesis.clone()], account, account)
        .unwrap()
        .head()
        .unwrap();
    let designation = Designation::issue(head, 1, &root_key, &membership, &[]).unwrap();
    pin_enrollment(
        &owner,
        EnrollmentPin {
            github_id: 1234567,
            account_id: account,
            authority_head: head.digest,
            designation_digest: designation.digest(),
        },
    )
    .await
    .unwrap();
    let authority = root.path().join("authority");
    AuthorityStore::open(&authority)
        .unwrap()
        .initialize(std::slice::from_ref(&genesis), account, head.digest)
        .unwrap();
    let material = enrollment_material(
        &root.path().join("pairing"),
        &identity,
        &genesis,
        &designation,
        &membership,
    );
    let designation_file = root.path().join("designation.bin");
    let certificate_file = root.path().join("certificate.bin");
    fs::write(
        &designation_file,
        hex::decode(string(&material, "designation")).unwrap(),
    )
    .unwrap();
    fs::write(
        &certificate_file,
        hex::decode(string(&material, "certificate")).unwrap(),
    )
    .unwrap();

    let mut login = tokio::process::Command::new(&binary);
    login
        .args(["control", "login"])
        .arg(&device)
        .env("HOWL_CONTROL_URL", &server.url)
        .env("HOWL_CONTROL_AUDIENCE", hex::encode(AUDIENCE));
    let login = login.output().await.unwrap();
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    let stdout = String::from_utf8(login.stdout).unwrap();
    assert!(stdout.contains("ABCD-EFGH") && stdout.contains("https://github.com/login/device"));
    assert_eq!(upstream.revoked.load(Ordering::SeqCst), 1);
    let record = device.join("credentials");
    assert_eq!(
        fs::metadata(&record).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut before: Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    let credentials = &before["credentials"];
    assert!(!stdout.contains(string(credentials, "access_token")));
    assert!(!stdout.contains(string(credentials, "refresh_token")));
    before["access_expires"] = json!(1);
    fs::write(&record, serde_json::to_vec(&before).unwrap()).unwrap();
    let mut enroll = tokio::process::Command::new(&binary);
    enroll
        .args(["control", "enroll"])
        .arg(&device)
        .arg(&authority)
        .arg(&designation_file)
        .arg(&certificate_file)
        .env_remove("HOWL_CONTROL_URL")
        .env_remove("HOWL_CONTROL_AUDIENCE")
        .env_remove("HOWL_CONTROL_SESSION_ID")
        .env_remove("HOWL_CONTROL_ACCESS_TOKEN");
    let enrolled = enroll.output().await.unwrap();
    assert!(
        enrolled.status.success(),
        "{}",
        String::from_utf8_lossy(&enrolled.stderr)
    );
    let after: Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    assert_ne!(
        after["credentials"]["refresh_token"],
        before["credentials"]["refresh_token"]
    );
    let row = owner
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT records FROM howl_control.enrolled_devices WHERE device_id = $1",
            &[&&identity.certificate().device_id()[..]],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, Value>(0), material);
}
