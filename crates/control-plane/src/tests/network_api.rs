use super::*;
use axum::http::Method;
use howl::enrollment::hosted;

struct Device {
    key: SigningKey,
    session: crate::Credentials,
}

impl Device {
    async fn login(runtime: &Pool, account: i64, id: Id, key: SigningKey) -> Self {
        let mut connection = runtime.get().await.unwrap();
        let tx = connection.transaction().await.unwrap();
        let signing = key.verifying_key().to_bytes();
        crate::network::reserve(&tx, account, &id, &signing)
            .await
            .unwrap();
        let session = crate::sessions::begin(&tx, account, id, signing)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        Self { key, session }
    }

    async fn call(
        &self,
        server: &Server,
        method: Method,
        path: &str,
        op: &str,
        body: Vec<u8>,
    ) -> Response {
        let http = Client::new();
        let proof = enrollment_proof(&http, &server.url, &self.session, &self.key, op, &body).await;
        http.request(method, format!("{}{path}", server.url))
            .bearer_auth(&self.session.access_token)
            .header("howl-nonce", proof.nonce)
            .header("howl-signature", proof.signature)
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn view(&self, server: &Server) -> Value {
        success(
            self.call(
                server,
                Method::GET,
                "/v1/network",
                "network-read",
                Vec::new(),
            )
            .await,
        )
        .await
    }

    async fn post(
        &self,
        server: &Server,
        route: &str,
        op: &str,
        value: &impl serde::Serialize,
    ) -> StatusCode {
        self.call(
            server,
            Method::POST,
            route,
            op,
            serde_json::to_vec(value).unwrap(),
        )
        .await
        .status()
    }
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance with owner and runtime fixture roles"]
async fn approvals_bind_the_registered_device_and_isolate_other_accounts() {
    let owner = pool("HOWL_TEST_CONTROL_DATABASE_OWNER");
    migrate(&owner).await.unwrap();
    let runtime = pool("HOWL_TEST_CONTROL_DATABASE_RUNTIME");
    let account = (i64::from_be_bytes(crate::random().unwrap()[..8].try_into().unwrap())
        & (i64::MAX - 1))
        .max(2);
    let github = GitHub::new("fixtureapp".into(), Zeroizing::new("fixture_secret".into())).unwrap();
    let server = serve(
        Arc::new(
            ControlPlane::new(runtime.clone(), github, AUDIENCE, Zeroizing::new([3; 32])).unwrap(),
        )
        .router(),
    )
    .await;
    let config = reqwest::get(format!("{}/v1/auth/config", server.url))
        .await
        .unwrap();
    assert_eq!(
        success(config).await,
        json!({"audience":hex::encode(AUDIENCE)})
    );
    let temp = tempfile::tempdir().unwrap();
    let founder_state = temp.path().join("founder");
    let member_state = temp.path().join("member");
    let founder_id = *enrollment_identity(&founder_state, [11, 12, 13, 14])
        .certificate()
        .device_id();
    let member_id = *enrollment_identity(&member_state, [21, 22, 23, 24])
        .certificate()
        .device_id();
    let founder = Device::login(
        &runtime,
        account,
        founder_id,
        SigningKey::from_bytes(&[12; 32]),
    )
    .await;
    let member = Device::login(
        &runtime,
        account,
        member_id,
        SigningKey::from_bytes(&[22; 32]),
    )
    .await;
    let outsider = Device::login(
        &runtime,
        account + 1,
        member_id,
        SigningKey::from_bytes(&[22; 32]),
    )
    .await;
    let impersonator = Device::login(
        &runtime,
        account,
        founder_id,
        SigningKey::from_bytes(&[32; 32]),
    )
    .await;
    let first = founder.view(&server).await;
    let channel = proof::decode::<32>(string(&first, "network")).unwrap();
    let network = hosted::bootstrap(&founder_state, channel).unwrap();
    let register = "/v1/network/devices";
    let approve = "/v1/network/approve";
    let denied = StatusCode::UNAUTHORIZED;
    let ok = StatusCode::NO_CONTENT;
    assert_eq!(first["state"], "founder");
    assert_eq!(
        impersonator
            .call(&server, Method::GET, "/v1/network", "network-read", vec![])
            .await
            .status(),
        denied
    );
    assert_ne!(outsider.view(&server).await["network"], first["network"]);
    assert_eq!(
        member
            .post(&server, approve, "network-approve", &network)
            .await,
        denied
    );
    assert_eq!(
        outsider
            .post(&server, approve, "network-approve", &network)
            .await,
        denied
    );
    assert_eq!(
        founder
            .post(&server, approve, "network-approve", &network)
            .await,
        ok
    );
    let candidate =
        hosted::candidate(&member_state, &network.authority, &network.designation).unwrap();
    let next = hosted::approve(&founder_state, channel, &network, &candidate).unwrap();
    assert_eq!(
        founder
            .post(&server, approve, "network-approve", &next)
            .await,
        denied
    );
    assert_eq!(
        member
            .post(&server, register, "network-register", &candidate)
            .await,
        ok
    );
    assert_eq!(
        member
            .post(&server, register, "network-register", &candidate)
            .await,
        ok
    );
    let pending = member.view(&server).await;
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["pending"], json!([]));
    assert!(pending["snapshot"].is_null());
    assert!(outsider.view(&server).await["snapshot"].is_null());
    assert_eq!(founder.view(&server).await["pending"], json!([candidate]));
    assert_eq!(
        member
            .post(&server, approve, "network-approve", &next)
            .await,
        denied
    );
    assert_eq!(
        founder
            .post(&server, approve, "network-approve", &next)
            .await,
        ok
    );
    assert_eq!(
        founder
            .post(&server, approve, "network-approve", &next)
            .await,
        ok
    );
    assert_eq!(
        founder
            .post(&server, approve, "network-approve", &network)
            .await,
        denied
    );
    assert_eq!(member.view(&server).await["state"], "approved");
    assert_eq!(founder.view(&server).await["pending"], json!([]));
    assert!(outsider.view(&server).await["snapshot"].is_null());
    let deny = "/v1/network/deny";
    let member_request = json!({
        "device": hex::encode(member_id),
        "fingerprint": hex::encode(candidate.identity().unwrap().fingerprint()),
    });
    assert_eq!(
        founder
            .post(&server, deny, "network-deny", &member_request)
            .await,
        denied
    );
    let rejected_state = temp.path().join("rejected");
    let rejected_peer = enrollment_identity(&rejected_state, [41, 42, 43, 44]).certificate();
    let rejected = Device::login(
        &runtime,
        account,
        *rejected_peer.device_id(),
        SigningKey::from_bytes(&[42; 32]),
    )
    .await;
    let rejected_candidate =
        hosted::candidate(&rejected_state, &network.authority, &network.designation).unwrap();
    let decision = json!({
        "device": hex::encode(rejected_peer.device_id()),
        "fingerprint": hex::encode(rejected_peer.fingerprint()),
    });
    assert_eq!(
        rejected
            .post(&server, register, "network-register", &rejected_candidate)
            .await,
        ok
    );
    assert_eq!(
        member.post(&server, deny, "network-deny", &decision).await,
        denied
    );
    assert_eq!(
        outsider
            .post(&server, deny, "network-deny", &decision)
            .await,
        denied
    );
    let mut wrong = decision.clone();
    wrong["fingerprint"] = member_request["fingerprint"].clone();
    assert_eq!(
        founder.post(&server, deny, "network-deny", &wrong).await,
        denied
    );
    assert_eq!(
        founder.view(&server).await["pending"],
        json!([rejected_candidate])
    );
    assert_eq!(
        founder.post(&server, deny, "network-deny", &decision).await,
        ok
    );
    let stale_approval =
        hosted::approve(&founder_state, channel, &next, &rejected_candidate).unwrap();
    assert_eq!(
        founder
            .post(&server, approve, "network-approve", &stale_approval)
            .await,
        denied
    );
    owner.get().await.unwrap().execute(
        "UPDATE howl_control.network_requests SET expires_at = clock_timestamp() - interval '1 day' WHERE github_id = $1 AND device_id = $2",
        &[&account, &&rejected_peer.device_id()[..]],
    ).await.unwrap();
    let relogin = Device::login(
        &runtime,
        account,
        *rejected_peer.device_id(),
        SigningKey::from_bytes(&[42; 32]),
    )
    .await;
    assert_eq!(
        relogin
            .post(&server, register, "network-register", &rejected_candidate)
            .await,
        denied
    );
    let rejected_view = relogin.view(&server).await;
    assert_eq!(rejected_view["state"], "denied");
    assert!(rejected_view["snapshot"].is_null());
    assert_eq!(rejected_view["authority"], json!([]));
    assert_eq!(rejected_view["pending"], json!([]));
    assert_eq!(
        founder.post(&server, deny, "network-deny", &decision).await,
        ok
    );
    assert_eq!(founder.view(&server).await["pending"], json!([]));
    let (left, right) = tokio::join!(
        Device::login(
            &runtime,
            account - 1,
            founder_id,
            SigningKey::from_bytes(&[12; 32])
        ),
        Device::login(
            &runtime,
            account - 1,
            member_id,
            SigningKey::from_bytes(&[22; 32])
        )
    );
    let (left, right) = tokio::join!(left.view(&server), right.view(&server));
    assert_eq!(left["network"], right["network"]);
    assert_eq!(left["founder"], right["founder"]);
    assert_ne!(left["state"], right["state"]);
    crate::pin_enrollment(
        &owner,
        crate::EnrollmentPin {
            github_id: account + 1,
            account_id: crate::random().unwrap(),
            authority_head: crate::random().unwrap(),
            designation_digest: crate::random().unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(outsider.view(&server).await["state"], "legacy");
}

pub(super) const WEB_ORIGIN: &str = "https://howl.test";

pub(super) struct Owner {
    pub(super) cookie: String,
    http: Client,
}

impl Owner {
    pub(super) async fn sign_in(control: &ControlPlane, account: i64) -> Self {
        let mut conn = control.pool.get().await.unwrap();
        let tx = conn.transaction().await.unwrap();
        crate::account_network::ensure(control, &tx, account)
            .await
            .unwrap();
        let secret = crate::random().unwrap();
        tx.execute(
            "INSERT INTO howl_control.web_sessions (token_digest,github_id,expires_at)
            VALUES ($1,$2,now()+interval '1 hour')",
            &[&&proof::hash(&secret)[..], &account],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Self {
            cookie: format!("__Host-howl-owner={}", hex::encode(secret)),
            http: Client::new(),
        }
    }

    async fn view(&self, server: &Server) -> Value {
        success(
            self.http
                .get(format!("{}/api/devices", server.url))
                .header("cookie", &self.cookie)
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    async fn decide(&self, server: &Server, action: &str, device: &Value) -> StatusCode {
        self.http
            .post(format!("{}/api/devices/{action}", server.url))
            .header("origin", WEB_ORIGIN)
            .header("cookie", &self.cookie)
            .json(&json!({"device":device["id"],"fingerprint":device["fingerprint"]}))
            .send()
            .await
            .unwrap()
            .status()
    }
}

async fn account_control() -> (Arc<ControlPlane>, Server, i64) {
    migrate(&pool("HOWL_TEST_CONTROL_DATABASE_OWNER"))
        .await
        .unwrap();
    let control = Arc::new(
        ControlPlane::new(
            pool("HOWL_TEST_CONTROL_DATABASE_RUNTIME"),
            GitHub::new("fixtureapp".into(), Zeroizing::new("fixture_secret".into())).unwrap(),
            AUDIENCE,
            Zeroizing::new([3; 32]),
        )
        .unwrap()
        .with_web_origin(WEB_ORIGIN)
        .unwrap(),
    );
    let server = serve(control.clone().router()).await;
    let account = (i64::from_be_bytes(crate::random().unwrap()[..8].try_into().unwrap())
        & (i64::MAX - 1))
        .max(2);
    (control, server, account)
}

async fn request_device(
    control: &ControlPlane,
    server: &Server,
    account: i64,
    path: &std::path::Path,
    seeds: [u8; 4],
) -> (Device, Value) {
    let peer = enrollment_identity(path, seeds).certificate();
    let client = Device::login(
        &control.pool,
        account,
        *peer.device_id(),
        SigningKey::from_bytes(&[seeds[1]; 32]),
    )
    .await;
    let view = client.view(server).await;
    assert_eq!(view["state"], "pending");
    let candidate = hosted::candidate(
        path,
        &serde_json::from_value::<Vec<String>>(view["authority"].clone()).unwrap(),
        string(&view, "designation"),
    )
    .unwrap();
    assert_eq!(
        client
            .post(
                server,
                "/v1/network/devices",
                "network-register",
                &candidate
            )
            .await,
        StatusCode::NO_CONTENT
    );
    (
        client,
        json!({"id":hex::encode(peer.device_id()),"fingerprint":hex::encode(peer.fingerprint())}),
    )
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance with owner and runtime fixture roles"]
async fn account_owner_decides_devices_with_all_native_agents_offline() {
    let (control, server, account) = account_control().await;
    let (owner, again) = tokio::join!(
        Owner::sign_in(&control, account),
        Owner::sign_in(&control, account)
    );
    let outsider = Owner::sign_in(&control, account + 1).await;
    let empty = owner.view(&server).await;
    assert_eq!(empty["approved"], json!([]));
    assert_eq!(empty["pending"], json!([]));
    assert_eq!(empty["account_managed"], true);
    assert_ne!(empty["network"], outsider.view(&server).await["network"]);
    assert_eq!(empty, again.view(&server).await);
    let states = tempfile::tempdir().unwrap();
    let (first, first_id) = request_device(
        &control,
        &server,
        account,
        &states.path().join("first"),
        [61, 62, 63, 64],
    )
    .await;
    assert_eq!(
        owner.decide(&server, "approve", &first_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(first.view(&server).await["state"], "approved");
    drop(first);
    std::fs::remove_dir_all(states.path().join("first")).unwrap();
    let (second, second_id) = request_device(
        &control,
        &server,
        account,
        &states.path().join("second"),
        [71, 72, 73, 74],
    )
    .await;
    let (rejected, rejected_id) = request_device(
        &control,
        &server,
        account,
        &states.path().join("rejected"),
        [81, 82, 83, 84],
    )
    .await;
    let pending = owner.view(&server).await;
    assert!(pending["pending"].as_array().unwrap().contains(&second_id));
    assert!(
        pending["pending"]
            .as_array()
            .unwrap()
            .contains(&rejected_id)
    );
    let unseen = outsider.view(&server).await;
    assert_eq!(unseen["pending"], json!([]));
    assert_eq!(unseen["approved"], json!([]));
    let mut stale = second_id.clone();
    stale["fingerprint"] = rejected_id["fingerprint"].clone();
    for action in ["approve", "deny"] {
        assert_eq!(
            outsider.decide(&server, action, &second_id).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            owner.decide(&server, action, &stale).await,
            StatusCode::NOT_FOUND
        );
    }
    let (approved, denied) = tokio::join!(
        owner.decide(&server, "approve", &second_id),
        again.decide(&server, "deny", &rejected_id)
    );
    assert_eq!(
        (approved, denied),
        (StatusCode::NO_CONTENT, StatusCode::NO_CONTENT)
    );
    assert_eq!(
        owner.decide(&server, "approve", &second_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        owner.decide(&server, "deny", &rejected_id).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        owner.decide(&server, "approve", &rejected_id).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(second.view(&server).await["state"], "approved");
    assert_eq!(rejected.view(&server).await["state"], "denied");
    let final_view = owner.view(&server).await;
    assert_eq!(final_view["pending"], json!([]));
    assert_eq!(final_view["approved"], json!([first_id, second_id]));
    assert_eq!(unseen, outsider.view(&server).await);
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance with owner and runtime fixture roles"]
async fn account_transfer_preserves_pins_and_disables_native_decisions() {
    let (control, server, account) = account_control().await;
    let states = tempfile::tempdir().unwrap();
    let state = states.path().join("founder");
    let peer = enrollment_identity(&state, [11, 12, 13, 14]).certificate();
    let founder = Device::login(
        &control.pool,
        account,
        *peer.device_id(),
        SigningKey::from_bytes(&[12; 32]),
    )
    .await;
    let channel = proof::decode(string(&founder.view(&server).await, "network")).unwrap();
    let genesis = hosted::bootstrap(&state, channel).unwrap();
    assert_eq!(
        founder
            .post(&server, "/v1/network/approve", "network-approve", &genesis)
            .await,
        StatusCode::NO_CONTENT
    );
    let owner = Owner::sign_in(&control, account).await;
    let before = owner.view(&server).await;
    assert_eq!(before["account_managed"], false);
    let (pending, request) = request_device(
        &control,
        &server,
        account,
        &states.path().join("second"),
        [21, 22, 23, 24],
    )
    .await;
    let transfer = "/v1/network/transfer";
    let op = "network-transfer";
    let signed =
        json!({"signer":hex::encode(std::fs::read(state.join("enrollment-signer-key")).unwrap())});
    assert_eq!(
        founder
            .post(&server, transfer, op, &json!({"signer":"00".repeat(32)}))
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        pending.post(&server, transfer, op, &signed).await,
        StatusCode::UNAUTHORIZED
    );
    for _ in 0..2 {
        assert_eq!(
            founder.post(&server, transfer, op, &signed).await,
            StatusCode::NO_CONTENT
        );
    }
    let after = owner.view(&server).await;
    assert_eq!(after["account_managed"], true);
    assert_eq!(after["network"], before["network"]);
    assert_eq!(after["approved"], before["approved"]);
    assert_eq!(after["pending"], json!([request]));
    assert_eq!(
        founder
            .post(&server, "/v1/network/approve", "network-approve", &genesis)
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        founder
            .post(
                &server,
                "/v1/network/deny",
                "network-deny",
                &json!({"device":request["id"],"fingerprint":request["fingerprint"]})
            )
            .await,
        StatusCode::UNAUTHORIZED
    );
    drop(founder);
    std::fs::remove_dir_all(state).unwrap();
    assert_eq!(
        owner.decide(&server, "approve", &request).await,
        StatusCode::NO_CONTENT
    );
    let view = pending.view(&server).await;
    assert_eq!(view["state"], "approved");
    let next: hosted::Network = serde_json::from_value(view["snapshot"].clone()).unwrap();
    assert_eq!(genesis.pin().unwrap(), next.pin().unwrap());
    assert!(next.rosters.starts_with(&genesis.rosters));
    next.verify(channel).unwrap();
}

#[path = "device_links.rs"]
mod device_links;
