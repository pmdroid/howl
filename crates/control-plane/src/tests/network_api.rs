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
