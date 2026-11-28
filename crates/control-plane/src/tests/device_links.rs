use super::*;
use howl::identity::LocalIdentity;

struct Link {
    path: String,
    id: Id,
    secret: String,
    nonce: String,
    peer: howl::identity::PeerCertificate,
    key: SigningKey,
}

impl Link {
    async fn create(server: &Server, identity: &LocalIdentity, key: u8) -> Self {
        let peer = identity.certificate();
        let path = format!("{}/v1/device-links", server.url);
        let reply = success(
            Client::new()
                .post(&path)
                .json(&json!({"peer":hex::encode(peer.as_bytes())}))
                .send()
                .await
                .unwrap(),
        )
        .await;
        let id = string(&reply, "id");
        let secret = string(&reply, "secret");
        assert_ne!(id, secret);
        assert_eq!(reply["url"], format!("{WEB_ORIGIN}/link#{secret}"));
        Self {
            path: format!("{path}/{id}"),
            id: proof::decode(id).unwrap(),
            secret: secret.to_owned(),
            nonce: string(&reply, "nonce").to_owned(),
            peer,
            key: SigningKey::from_bytes(&[key; 32]),
        }
    }

    async fn poll(
        &self,
        nonce: &str,
        candidate: Option<&hosted::Candidate>,
        key: &SigningKey,
    ) -> Response {
        let body = candidate
            .map(serde_json::to_vec)
            .transpose()
            .unwrap()
            .unwrap_or_default();
        let signed = signing_bytes(
            AUDIENCE,
            self.id,
            "device-link",
            proof::decode(nonce).unwrap(),
            [0; 32],
            &body,
        );
        let mut data = json!({"nonce":nonce,"signature":hex::encode(key.sign(&signed).to_bytes())});
        if let Some(candidate) = candidate {
            data["candidate"] = json!(candidate);
        }
        Client::new()
            .post(format!("{}/poll", self.path))
            .json(&data)
            .send()
            .await
            .unwrap()
    }

    async fn browser(&self, owner: &Owner, server: &Server, decision: Option<&str>) -> Response {
        let (route, body) = if let Some(decision) = decision {
            (
                "decide",
                json!({"secret":self.secret,"device":hex::encode(self.peer.device_id()),"fingerprint":hex::encode(self.peer.fingerprint()),"decision":decision}),
            )
        } else {
            ("view", json!({"secret":self.secret}))
        };
        owner
            .http
            .post(format!("{}/api/device-links/{route}", server.url))
            .header("cookie", &owner.cookie)
            .header("origin", WEB_ORIGIN)
            .json(&body)
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL roles"]
async fn device_link_redeems_exact_owner_approval_once() {
    let (control, server, account) = account_control().await;
    let (owner, outsider) = tokio::join!(
        Owner::sign_in(&control, account),
        Owner::sign_in(&control, account + 1)
    );
    let states = tempfile::tempdir().unwrap();
    let state = states.path().join("new");
    let identity = enrollment_identity(&state, [71, 72, 73, 74]);
    let link = Link::create(&server, &identity, 72).await;
    let duplicate = Link::create(&server, &identity, 72).await;
    assert_eq!(owner.view(&server).await["pending"], json!([]));
    let waiting = success(link.poll(&link.nonce, None, &link.key).await).await;
    assert_eq!(waiting["state"], "waiting");
    assert!(waiting.get("authority").is_none());
    assert!(waiting.get("credentials").is_none());
    let claimed = success(link.browser(&owner, &server, None).await).await;
    assert_eq!(claimed["state"], "pending");
    assert!(claimed.get("nonce").is_none());
    assert!(claimed.get("id").is_none());
    assert_eq!(
        success(duplicate.browser(&owner, &server, None).await).await,
        claimed
    );
    let pending = json!({"id":claimed["device"],"fingerprint":claimed["fingerprint"]});
    assert_eq!(owner.view(&server).await["pending"], json!([pending]));
    assert_eq!(outsider.view(&server).await["pending"], json!([]));
    for action in [None, Some("approve"), Some("deny")] {
        assert_eq!(
            link.browser(&outsider, &server, action).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        outsider.decide(&server, "approve", &pending).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        link.poll(&link.nonce, None, &link.key).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let bound = success(link.poll(string(&waiting, "nonce"), None, &link.key).await).await;
    let records = serde_json::from_value::<Vec<String>>(bound["authority"].clone()).unwrap();
    let candidate = hosted::candidate(&state, &records, string(&bound, "designation")).unwrap();
    let foreign = hosted::candidate(
        &states.path().join("other"),
        &records,
        string(&bound, "designation"),
    )
    .unwrap();
    let nonce = string(&bound, "nonce");
    assert_eq!(
        link.poll(nonce, Some(&candidate), &SigningKey::from_bytes(&[99; 32]))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        link.poll(nonce, Some(&foreign), &link.key).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let still_waiting = success(link.poll(nonce, Some(&candidate), &link.key).await).await;
    assert_eq!(still_waiting["state"], "waiting");
    assert!(still_waiting.get("credentials").is_none());
    assert_eq!(
        owner.decide(&server, "approve", &pending).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(owner.view(&server).await["approved"], json!([]));
    assert_eq!(
        duplicate
            .browser(&owner, &server, Some("deny"))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let redeemed = success(
        link.poll(string(&still_waiting, "nonce"), Some(&candidate), &link.key)
            .await,
    )
    .await;
    assert_eq!(redeemed["state"], "approved");
    assert_eq!(redeemed["credentials"]["session"]["github_id"], account);
    assert_eq!(
        redeemed["credentials"]["session"]["device_id"],
        claimed["device"]
    );
    assert_eq!(owner.view(&server).await["approved"], json!([pending]));
    assert_eq!(owner.view(&server).await["pending"], json!([]));
    assert_eq!(
        link.poll(string(&still_waiting, "nonce"), Some(&candidate), &link.key)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let current = success(
        reqwest::get(format!("{}/challenge", link.path))
            .await
            .unwrap(),
    )
    .await;
    let again = success(
        link.poll(string(&current, "nonce"), Some(&candidate), &link.key)
            .await,
    )
    .await;
    assert!(redeemed == again);
    let reject_peer = enrollment_identity(&states.path().join("reject"), [81, 82, 83, 84]);
    let reject = Link::create(&server, &reject_peer, 82).await;
    assert_eq!(
        success(reject.browser(&owner, &server, None).await).await["state"],
        "pending"
    );
    assert_eq!(
        reject.browser(&owner, &server, Some("deny")).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        success(reject.poll(&reject.nonce, None, &reject.key).await).await,
        json!({"state":"denied"})
    );
    let retry = Link::create(&server, &reject_peer, 82).await;
    assert_eq!(
        success(retry.browser(&owner, &server, None).await).await["state"],
        "denied"
    );
    assert_eq!(owner.view(&server).await["pending"], json!([]));
    assert_eq!(
        retry
            .browser(&owner, &server, Some("approve"))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    pool("HOWL_TEST_CONTROL_DATABASE_OWNER")
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE howl_control.device_links SET expires_at=now()-interval '1 minute' WHERE id=$1",
            &[&&link.id[..]],
        )
        .await
        .unwrap();
    assert_eq!(
        link.browser(&owner, &server, None).await.status(),
        StatusCode::NOT_FOUND
    );
}
