use std::{
    fs::symlink_metadata,
    os::unix::fs::symlink,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use tokio::net::TcpListener;

use super::*;

fn raw_endpoint(url: &str, allow_private_ips: Vec<IpAddr>) -> EndpointConfig {
    EndpointConfig {
        name: "receiver".into(),
        url: url.into(),
        signing_secret: hex::encode([0x42; 32]),
        channels: vec![hex::encode([0x20; 32])],
        events: vec![WebhookEventKind::MessageReceived],
        enabled: true,
        include_content: false,
        allow_private_ips,
    }
}

#[test]
fn standard_signature_matches_independent_hmac_vector() {
    assert_eq!(
        signature(
            &[0x42; 32],
            "evt_example",
            1_700_000_000,
            r#"{"ready":true}"#
        ),
        "v1,bh6k0uaZ0TBcfuXr/Mwo4/f/4ancSQLVUwTt148RKGE="
    );
}

#[test]
fn protected_config_rejects_symlinks_unknown_fields_and_unconsented_plaintext() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("endpoints.json");
    let raw = raw_endpoint("https://receiver.example.net/hook", Vec::new());
    let value = serde_json::json!({ "endpoints": [raw] });
    let save = |value: &serde_json::Value| {
        std::fs::write(&config, value.to_string()).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    save(&value);
    assert_eq!(load_config(&config).unwrap().len(), 1);
    let symlink_path = temp.path().join("linked.json");
    symlink(&config, &symlink_path).unwrap();
    assert!(
        symlink_metadata(&symlink_path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(load_config(&symlink_path).is_err());
    let mut disabled = value;
    disabled["endpoints"][0]["enabled"] = false.into();
    save(&disabled);
    assert!(load_config(&config).unwrap().is_empty());
    disabled["endpoints"][0]["unrecognized"] = true.into();
    save(&disabled);
    assert!(load_config(&config).is_err());
    let local = raw_endpoint("http://127.0.0.1/receiver", Vec::new());
    assert!(Endpoint::compile(local, [1; 32]).is_err());
    let remote = raw_endpoint(
        "http://192.168.1.2/receiver",
        vec!["192.168.1.2".parse().unwrap()],
    );
    assert!(Endpoint::compile(remote, [1; 32]).is_err());
}

#[tokio::test]
async fn validates_all_dns_answers_before_pinning_any_address() {
    let endpoint = Endpoint::compile(
        raw_endpoint("https://receiver.example.net/hook", Vec::new()),
        [1; 32],
    )
    .unwrap();
    let first: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let second: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
    let pin = pinned_destination(&endpoint, |host, port| async move {
        assert_eq!(host, "receiver.example.net");
        assert_eq!(port, 443);
        Ok(vec![first, second])
    })
    .await
    .ok()
    .unwrap();
    assert_eq!(pin.addresses, [first, second]);
    for reserved in [
        "0.0.0.0",
        "127.0.0.1",
        "100.64.35.48",
        "169.254.169.254",
        "172.16.30.40",
        "192.0.2.33",
        "::",
        "::1",
        "::ffff:10.0.0.1",
        "fc00::4",
        "fe80::2",
        "64:ff9b::a00:1",
        "2001:db8::4",
        "2002:a00:1::1",
        "3fff::4",
    ] {
        let private = SocketAddr::new(reserved.parse().unwrap(), 443);
        let result = pinned_destination(&endpoint, |_, _| async { Ok(vec![first, private]) }).await;
        assert!(
            matches!(result, Err(WebhookOutcome::DestinationBlocked)),
            "{reserved}"
        );
    }
    let consented = Endpoint::compile(
        raw_endpoint(
            "https://receiver.example.net/hook",
            vec!["10.20.30.40".parse().unwrap()],
        ),
        [1; 32],
    )
    .unwrap();
    let exact = "10.20.30.40:443".parse().unwrap();
    assert!(
        pinned_destination(&consented, |_, _| async { Ok(vec![first, exact]) })
            .await
            .is_ok()
    );
    let adjacent = "10.20.30.41:443".parse().unwrap();
    assert!(matches!(
        pinned_destination(&consented, |_, _| async {
            Ok(vec![first, exact, adjacent])
        })
        .await,
        Err(WebhookOutcome::DestinationBlocked)
    ));
}

#[tokio::test]
async fn explicit_loopback_delivery_is_signed_and_refuses_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap();
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let router =
        Router::new()
            .route(
                "/verified",
                post(
                    |State(calls): State<Arc<Mutex<Vec<String>>>>,
                     headers: HeaderMap,
                     body: String| async move {
                        assert_eq!(headers["webhook-id"], "evt_example");
                        assert_eq!(headers["webhook-timestamp"], "1700000000");
                        assert_eq!(
                            headers["webhook-signature"],
                            "v1,bh6k0uaZ0TBcfuXr/Mwo4/f/4ancSQLVUwTt148RKGE="
                        );
                        assert_eq!(body, r#"{"ready":true}"#);
                        calls.lock().unwrap().push(body);
                        StatusCode::NO_CONTENT
                    },
                ),
            )
            .route(
                "/redirect",
                post(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, "/verified")],
                    )
                        .into_response()
                }),
            )
            .with_state(Arc::clone(&calls));
    let task = tokio::spawn(async move { axum::serve(listener, router).await });
    for (path, delivered) in [("redirect", false), ("verified", true)] {
        let endpoint = Endpoint::compile(
            raw_endpoint(&format!("http://{authority}/{path}"), vec![authority.ip()]),
            [1; 32],
        )
        .unwrap();
        let pinned = pinned_destination(&endpoint, |_, _| async {
            panic!("literal destination should bypass DNS")
        })
        .await
        .ok()
        .unwrap();
        let status = send(
            &endpoint,
            pinned,
            "evt_example",
            1_700_000_000,
            r#"{"ready":true}"#,
        )
        .await;
        if delivered {
            assert!(matches!(status, WebhookOutcome::Delivered));
        } else {
            assert!(matches!(status, WebhookOutcome::Rejected));
            assert!(calls.lock().unwrap().is_empty());
        }
    }
    assert_eq!(calls.lock().unwrap().len(), 1);
    task.abort();
}
