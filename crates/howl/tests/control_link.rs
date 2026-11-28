use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use ed25519_dalek::{Signature, VerifyingKey};
use howl::{control_proof::signing_bytes, identity::LocalIdentity};
use serde_json::{Value, json};
use tokio::{net::TcpListener, process::Command};

#[tokio::test]
async fn advertised_link_recovers_its_nonce_and_reports_owner_denial() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("device");
    let peer = LocalIdentity::load_or_create(&state).unwrap().certificate();
    let expected_peer = hex::encode(peer.as_bytes());
    let calls = Arc::new(AtomicUsize::new(0));
    let polled = calls.clone();
    let key = VerifyingKey::from_bytes(&peer.signing_public()).unwrap();
    let config = || async {
        Json(json!({
            "audience": hex::encode([1; 32]),
            "browser_link_origin": "https://howl.test"
        }))
    };
    let begin = move |Json(input): Json<Value>| async move {
        assert_eq!(input["peer"], expected_peer);
        assert!(input.get("name").is_none());
        Json(json!({
            "id": hex::encode([2; 32]),
            "secret": hex::encode([3; 32]),
            "nonce": hex::encode([4; 32]),
            "expires_in": 600
        }))
    };
    let challenge = || async { Json(json!({"nonce":hex::encode([5;32])})) };
    let poll = move |Json(input): Json<Value>| {
        let count = polled.fetch_add(1, Ordering::SeqCst);
        async move {
            let nonce = if count == 0 { [4; 32] } else { [5; 32] };
            assert_eq!(input["nonce"], hex::encode(nonce));
            assert!(input.get("candidate").is_none());
            let signature = hex::decode(input["signature"].as_str().unwrap()).unwrap();
            let message = signing_bytes([1; 32], [2; 32], "device-link", nonce, [0; 32], b"");
            key.verify_strict(&message, &Signature::from_slice(&signature).unwrap())
                .unwrap();
            if count == 0 {
                StatusCode::UNAUTHORIZED.into_response()
            } else {
                Json(json!({"state":"denied"})).into_response()
            }
        }
    };
    let api = Router::new()
        .route("/v1/auth/config", get(config))
        .route("/v1/device-links", post(begin))
        .route("/v1/device-links/{id}/challenge", get(challenge))
        .route("/v1/device-links/{id}/poll", post(poll));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async { axum::serve(listener, api).await.unwrap() });
    let output = Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(["control", "login"])
        .arg(&state)
        .env("HOWL_CONTROL_URL", origin)
        .env("HOWL_CONTROL_AUDIENCE", hex::encode([1; 32]))
        .env("HOWL_NO_BROWSER", "1")
        .output()
        .await
        .unwrap();
    server.abort();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("denied this device link")
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(&format!(
        "Open https://howl.test/link#{}",
        hex::encode([3; 32])
    )));
    assert!(text.contains(&format!("Fingerprint {}", hex::encode(peer.fingerprint()))));
    assert!(!text.contains("github.com"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!state.join("credentials").exists());
    assert!(!state.join("hosted-designation").exists());
}

#[tokio::test]
async fn web_enabled_servers_keep_manual_and_explicit_device_code_routes() {
    let config = || async {
        Json(json!({
            "audience":hex::encode([1;32]),
            "browser_link_origin":"https://howl.test"
        }))
    };
    let (observed, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let start = move |uri: axum::http::Uri| {
        observed.send(uri.path().to_owned()).unwrap();
        async {
            Json(json!({
                "login": hex::encode([2;32]),
                "verification_uri": "https://github.com/login/device",
                "user_code": "ABCD-EFGH",
                "expires_in": 1,
                "interval": 1
            }))
        }
    };
    let api = Router::new()
        .route("/v1/auth/config", get(config))
        .route("/v1/login/device", post(start.clone()))
        .route("/v1/network/login/device", post(start));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async { axum::serve(listener, api).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let manual = directory.path().join("enrolled");
    LocalIdentity::load_or_create(&manual).unwrap();
    std::fs::write(manual.join("mesh.lock"), []).unwrap();
    let fresh = directory.path().join("fresh");
    for (state, flags, route) in [
        (&manual, &[][..], "/v1/login/device"),
        (&fresh, &["--device-code"][..], "/v1/network/login/device"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_howl"))
            .args(["control", "login"])
            .args(flags)
            .arg(state)
            .env("HOWL_CONTROL_URL", &origin)
            .env_remove("HOWL_CONTROL_AUDIENCE")
            .env("HOWL_NO_BROWSER", "1")
            .output()
            .await
            .unwrap();
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("https://github.com/login/device")
        );
        assert_eq!(requests.try_recv().unwrap(), route);
    }
    server.abort();
}

#[tokio::test]
async fn named_links_send_the_displayed_name_and_default_to_the_hostname() {
    let config = || async {
        Json(json!({
            "audience":hex::encode([1;32]),
            "browser_link_origin":"https://howl.test",
            "device_names":true
        }))
    };
    let (observed, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let begin = move |Json(input): Json<Value>| {
        observed.send(input).unwrap();
        async {
            Json(json!({
                "id": hex::encode([2;32]),
                "secret": hex::encode([3;32]),
                "nonce": hex::encode([4;32]),
                "expires_in": 600
            }))
        }
    };
    let api = Router::new()
        .route("/v1/auth/config", get(config))
        .route("/v1/device-links", post(begin))
        .route(
            "/v1/device-links/{id}/poll",
            post(|| async { Json(json!({"state":"denied"})) }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async { axum::serve(listener, api).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let hostname = rustix::system::uname();
    let default_name = hostname
        .nodename()
        .to_str()
        .ok()
        .and_then(|s| howl::control_client::device_name(s).ok());
    for (flags, expected) in [
        (&["--name", "  Studio Mac  "][..], Some("Studio Mac")),
        (&[][..], default_name),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_howl"))
            .args(["control", "login"])
            .args(flags)
            .arg(directory.path().join("device"))
            .env("HOWL_CONTROL_URL", &origin)
            .env_remove("HOWL_CONTROL_AUDIENCE")
            .env("HOWL_NO_BROWSER", "1")
            .output()
            .await
            .unwrap();
        let body = requests.try_recv().unwrap();
        assert_eq!(body.get("name").and_then(Value::as_str), expected);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.lines().nth(1).unwrap().starts_with("Fingerprint "));
        assert_eq!(
            text.lines().nth(2),
            expected.map(|n| format!("Name {n}")).as_deref()
        );
    }
    server.abort();
}

#[tokio::test]
async fn invalid_device_name_is_refused_before_creating_local_state() {
    let directory = tempfile::tempdir().unwrap();
    let device = directory.path().join("invalid");
    let output = Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(["control", "login", "--name", "Work\nLaptop"])
        .arg(&device)
        .env_remove("HOWL_CONTROL_URL")
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Device names must contain")
    );
    assert!(!device.exists());
}
