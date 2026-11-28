use super::*;
use howl::identity::PeerCertificate;

async fn named_link(
    owner: &Owner,
    server: &Server,
    peer: &PeerCertificate,
    label: &str,
) -> Response {
    owner
        .http
        .post(format!("{}/v1/device-links", server.url))
        .json(&json!({"peer":hex::encode(peer.as_bytes()),"name":label}))
        .send()
        .await
        .unwrap()
}

async fn claim(owner: &Owner, server: &Server, secret: &str) -> Response {
    owner
        .http
        .post(format!("{}/api/device-links/view", server.url))
        .header("cookie", &owner.cookie)
        .header("origin", WEB_ORIGIN)
        .json(&json!({"secret":secret}))
        .send()
        .await
        .unwrap()
}

async fn read(owner: &Owner, server: &Server, device: &str) -> Response {
    owner
        .http
        .get(format!("{}/api/devices/{device}", server.url))
        .header("cookie", &owner.cookie)
        .send()
        .await
        .unwrap()
}

async fn rename(
    owner: &Owner,
    server: &Server,
    device: &str,
    fingerprint: &str,
    name: &str,
) -> Response {
    owner
        .http
        .post(format!("{}/api/devices/{device}/name", server.url))
        .header("cookie", &owner.cookie)
        .header("origin", WEB_ORIGIN)
        .json(&json!({"fingerprint":fingerprint,"name":name}))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL roles"]
async fn named_device_details_stay_with_the_owner() {
    let (control, server, account) = account_control().await;
    let (owner, foreign) = tokio::join!(
        Owner::sign_in(&control, account),
        Owner::sign_in(&control, account + 1)
    );
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("device");
    let peer = enrollment_identity(&state, [41, 42, 43, 44]).certificate();
    let device = hex::encode(peer.device_id());
    let fingerprint = hex::encode(peer.fingerprint());
    for invalid in ["", "a\nb", &"🚀".repeat(81)] {
        assert_eq!(
            named_link(&owner, &server, &peer, invalid).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let link = success(named_link(&owner, &server, &peer, "  Guest Mac  ").await).await;
    let secret = string(&link, "secret");
    assert_eq!(
        read(&owner, &server, &device).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        success(claim(&owner, &server, secret).await).await["name"],
        "Guest Mac"
    );
    let initial = success(read(&owner, &server, &device).await).await;
    assert_eq!(initial["state"], "pending");
    assert_eq!(initial["name"], "Guest Mac");
    assert!(string(&initial, "requested_at").ends_with('Z'));
    assert!(initial.get("approved_at").is_none());
    assert!(initial.get("last_route_at").is_none());
    let unknown = hex::encode([253u8; 32]);
    for target in [&device, &unknown] {
        assert_eq!(
            read(&foreign, &server, target).await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            rename(&foreign, &server, target, &fingerprint, "Other")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        rename(&owner, &server, &device, &unknown, "Other")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        rename(&owner, &server, &device, &fingerprint, "x\ty")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let updated =
        success(rename(&owner, &server, &device, &fingerprint, "  Studio 🚀  ").await).await;
    assert_eq!(updated["name"], "Studio 🚀");
    assert_eq!(updated["requested_at"], initial["requested_at"]);
    let second = success(named_link(&owner, &server, &peer, "another suggestion").await).await;
    assert_eq!(
        success(claim(&owner, &server, string(&second, "secret")).await).await["name"],
        updated["name"]
    );
    assert_eq!(
        owner.view(&server).await["pending"][0]["name"],
        updated["name"]
    );
    let foreign_link = success(named_link(&foreign, &server, &peer, "Other account").await).await;
    let foreign_claim =
        success(claim(&foreign, &server, string(&foreign_link, "secret")).await).await;
    assert_eq!(foreign_claim["name"], "Other account");
    assert_eq!(
        success(read(&foreign, &server, &device).await).await["name"],
        "Other account"
    );
    assert_eq!(
        owner.decide(&server, "approve", &updated).await,
        StatusCode::NO_CONTENT
    );
    let allowed = success(read(&owner, &server, &device).await).await;
    assert_eq!(allowed["state"], "approved");
    assert!(string(&allowed, "approved_at").ends_with('Z'));
    assert!(allowed.get("last_route_at").is_none());
    let key = SigningKey::from_bytes(&[42; 32]);
    let native = Device::login(&control.pool, account, *peer.device_id(), key.clone()).await;
    let view = native.view(&server).await;
    let records = serde_json::from_value::<Vec<String>>(view["authority"].clone()).unwrap();
    let candidate = hosted::candidate(&state, &records, string(&view, "designation")).unwrap();
    assert_eq!(
        native
            .post(
                &server,
                "/v1/network/devices",
                "network-register",
                &candidate
            )
            .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(success(read(&owner, &server, &device).await).await, allowed);
    let issued = howl::discovery::now().unwrap();
    assert_eq!(
        send_hint(
            &owner.http,
            &server.url,
            &native.session,
            &key,
            &peer,
            &signed_hint(&peer, &key, issued, 4101)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let published = success(read(&owner, &server, &device).await).await;
    assert!(string(&published, "last_route_at").ends_with('Z'));
    assert_ne!(published["last_route_at"], Value::Null);
    assert_eq!(
        owner.view(&server).await["approved"][0]["name"],
        "Studio 🚀"
    );
    assert_eq!(
        foreign.decide(&server, "deny", &updated).await,
        StatusCode::NO_CONTENT
    );
    let denied = success(read(&foreign, &server, &device).await).await;
    assert_eq!(denied["state"], "denied");
    assert!(denied.get("approved_at").is_none());
    assert!(denied.get("last_route_at").is_none());
    let admin = pool("HOWL_TEST_CONTROL_DATABASE_OWNER");
    admin
        .get()
        .await
        .unwrap()
        .execute(
            "DELETE FROM howl_control.device_details WHERE github_id=$1 AND device_id=$2",
            &[&account, &&peer.device_id()[..]],
        )
        .await
        .unwrap();
    let old = success(read(&owner, &server, &device).await).await;
    assert_eq!(old["name"], format!("Device {}", &device[..12]));
    assert!(old.get("requested_at").is_none());
    assert!(old.get("approved_at").is_none());
    assert_eq!(old["last_route_at"], published["last_route_at"]);
}
