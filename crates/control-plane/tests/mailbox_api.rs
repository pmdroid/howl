use std::{
    env,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::StatusCode;
use deadpool_postgres::{Manager, Pool};
use ed25519_dalek::{Signer, SigningKey};
use howl_control_plane::{
    ControlPlane, EnrollmentPin, GitHub, Id, Proof, credential_digest, migrate, pin_enrollment,
    signing_bytes,
};
use howl_envelope::{Body, DeviceAddress, Recipient, Routing, seal};
use reqwest::{Client, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_postgres::{Config, NoTls};
use zeroize::Zeroizing;

const AUDIENCE: Id = [1; 32];
const CHANNEL: Id = [2; 32];

struct Device {
    account: Id,
    id: Id,
    session: Id,
    token: String,
    key: SigningKey,
}

impl Device {
    async fn fixture(owner: &Pool, github: i64, id: u8, enrolled: bool) -> Self {
        let fixture = Self {
            account: [github as u8; 32],
            id: [id; 32],
            session: [id + 32; 32],
            token: hex::encode([id + 64; 32]),
            key: SigningKey::from_bytes(&[id + 96; 32]),
        };
        let client = owner.get().await.unwrap();
        let signing = fixture.key.verifying_key().to_bytes();
        client.execute(
            "INSERT INTO howl_control.pending_sessions (id, github_id, device_id, signing_key, expires_at)
             VALUES ($1, $2, $3, $4, clock_timestamp() + interval '1 hour')",
            &[&fixture.session.as_slice(), &github, &fixture.id.as_slice(), &signing.as_slice()],
        ).await.unwrap();
        client
            .execute(
                "INSERT INTO howl_control.tokens (digest, session_id, refresh, expires_at)
             VALUES ($1, $2, false, clock_timestamp() + interval '1 hour')",
                &[
                    &credential_digest(&fixture.token).unwrap().as_slice(),
                    &fixture.session.as_slice(),
                ],
            )
            .await
            .unwrap();
        if enrolled {
            client.execute(
                "INSERT INTO howl_control.enrolled_devices
                    (account_id, device_id, signing_key, authority_head, designation_digest, sequence, records)
                 SELECT account_id, $2, $3, authority_head, designation_digest, $4, '{}'::jsonb
                 FROM howl_control.enrollment_pins WHERE github_id = $1",
                &[&github, &fixture.id.as_slice(), &signing.as_slice(), &1_u64.to_be_bytes().as_slice()],
            ).await.unwrap();
        }
        fixture
    }

    fn address(&self) -> DeviceAddress {
        DeviceAddress {
            account: self.account,
            device: self.id,
        }
    }
}

struct Server {
    client: Client,
    url: String,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn proof(&self, actor: &Device, operation: &str, body: &[u8]) -> Proof {
        let challenge: Value = self
            .client
            .post(format!("{}/v1/auth/challenge", self.url))
            .bearer_auth(&actor.token)
            .json(&json!({ "operation": operation }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let nonce = challenge["nonce"].as_str().unwrap().to_owned();
        let nonce_id = hex::decode(&nonce).unwrap().try_into().unwrap();
        let signature = actor.key.sign(&signing_bytes(
            AUDIENCE,
            actor.session,
            operation,
            nonce_id,
            credential_digest(&actor.token).unwrap(),
            body,
        ));
        Proof {
            nonce,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    async fn request(
        &self,
        actor: &Device,
        endpoint: &str,
        body: Vec<u8>,
        proof: &Proof,
    ) -> Response {
        self.client
            .post(format!("{}/v1/mailbox/{endpoint}", self.url))
            .bearer_auth(&actor.token)
            .header("howl-nonce", &proof.nonce)
            .header("howl-signature", &proof.signature)
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn send(&self, actor: &Device, endpoint: &str, request: Value) -> Response {
        let body = serde_json::to_vec(&request).unwrap();
        let proof = self
            .proof(actor, &format!("mailbox-{endpoint}"), &body)
            .await;
        self.request(actor, endpoint, body, &proof).await
    }
}

fn pool(config: Config) -> Pool {
    Pool::builder(Manager::new(config, NoTls))
        .max_size(8)
        .build()
        .unwrap()
}

fn envelope(sender: &Device, receiver: &Device) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signing = howl_envelope::SigningKey::from_bytes(&sender.key.to_bytes());
    seal(
        Routing {
            channel: CHANNEL,
            sender: sender.address(),
            epoch: 1,
            sequence: 2,
            created_at: now,
            expires_at: 0,
        },
        Body::Chat(&"opaque fixture data".repeat(400)),
        &signing,
        &[Recipient {
            address: receiver.address(),
            encryption_key: [0x34; 32],
        }],
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database named howl_mailbox_api_test"]
async fn enrolled_http_mailbox_retains_fetch_and_requires_exact_authorized_ack() {
    let url = env::var("HOWL_MAILBOX_API_DATABASE_URL").expect("set the disposable PostgreSQL URL");
    let mut config: Config = url.parse().unwrap();
    assert_eq!(config.get_dbname(), Some("howl_mailbox_api_test"));
    let owner = pool(config.clone());
    owner
        .get()
        .await
        .unwrap()
        .batch_execute("CREATE ROLE howl_control_runtime LOGIN")
        .await
        .unwrap();
    migrate(&owner).await.unwrap();
    migrate(&owner).await.unwrap();
    for github in [10, 11] {
        pin_enrollment(
            &owner,
            EnrollmentPin {
                github_id: github,
                account_id: [github as u8; 32],
                authority_head: [12; 32],
                designation_digest: [13; 32],
            },
        )
        .await
        .unwrap();
    }
    let alice = Device::fixture(&owner, 10, 21, true).await;
    let bob = Device::fixture(&owner, 10, 22, true).await;
    let pending = Device::fixture(&owner, 10, 23, false).await;
    let outside = Device::fixture(&owner, 11, 24, true).await;
    config.user("howl_control_runtime");
    let github = GitHub::new("fixtureapp".into(), Zeroizing::new("fixture_secret".into())).unwrap();
    let control = Arc::new(
        ControlPlane::new(pool(config), github, AUDIENCE, Zeroizing::new([3; 32])).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        client: Client::new(),
        url: format!("http://{}", listener.local_addr().unwrap()),
        task: tokio::spawn(async move { axum::serve(listener, control.router()).await.unwrap() }),
    };

    let frame = envelope(&alice, &bob);
    let contents = hex::encode(&frame);
    let message = hex::encode(
        howl_envelope::inspect_unverified(&frame)
            .unwrap()
            .message_id,
    );
    let digest = hex::encode(Sha256::digest(&frame));
    let deposit = json!({ "recipient": hex::encode(bob.id), "ciphertext": contents });
    let deposit_body = serde_json::to_vec(&deposit).unwrap();
    assert!(deposit_body.len() > 4096);
    let proof = server.proof(&alice, "mailbox-deposit", &deposit_body).await;
    let changed = serde_json::to_vec(
        &json!({ "recipient": hex::encode(pending.id), "ciphertext": contents }),
    )
    .unwrap();
    assert_eq!(
        server
            .request(&alice, "deposit", changed, &proof)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .send(
                &alice,
                "deposit",
                json!({ "recipient": hex::encode(outside.id), "ciphertext": contents })
            )
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .send(&pending, "deposit", deposit.clone())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server
            .request(&alice, "deposit", deposit_body.clone(), &proof)
            .await
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        server
            .request(&alice, "deposit", deposit_body, &proof)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let fetch = json!({ "after": 0, "limit": 4 });
    assert_eq!(
        server.send(&pending, "fetch", fetch.clone()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let unauthorized_inbox: Value = server
        .send(&outside, "fetch", fetch.clone())
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unauthorized_inbox["envelopes"], json!([]));
    let first = server
        .send(&bob, "fetch", fetch.clone())
        .await
        .error_for_status()
        .unwrap();
    assert_eq!(first.headers()["cache-control"], "no-store");
    drop(first);
    let replay: Value = server
        .send(&bob, "fetch", fetch.clone())
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let record = &replay["envelopes"][0];
    assert_eq!(record["ciphertext"], contents);
    assert_eq!(record["message"], message);
    assert_eq!(record["digest"], digest);
    let range: Value = server.send(&bob, "range", json!({ "channel": hex::encode(CHANNEL), "sender": hex::encode(alice.id), "epoch": 1, "first": 1, "last": 3, "limit": 4 })).await.error_for_status().unwrap().json().await.unwrap();
    assert_eq!(range["missing"], json!([[1, 1], [3, 3]]));

    let ack = json!({ "message": message, "digest": digest });
    assert_eq!(
        server.send(&alice, "ack", ack.clone()).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server
            .send(
                &bob,
                "ack",
                json!({ "message": message, "digest": hex::encode([0xff; 32]) })
            )
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server.send(&bob, "ack", ack.clone()).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.send(&bob, "ack", ack).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.send(&alice, "deposit", deposit).await.status(),
        StatusCode::NO_CONTENT
    );
    let final_inbox: Value = server
        .send(&bob, "fetch", fetch.clone())
        .await
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(final_inbox["envelopes"], json!([]));

    pin_enrollment(
        &owner,
        EnrollmentPin {
            github_id: 10,
            account_id: alice.account,
            authority_head: [14; 32],
            designation_digest: [13; 32],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        server.send(&bob, "fetch", fetch).await.status(),
        StatusCode::UNAUTHORIZED
    );
}
