use std::path::{Path, PathBuf};

use howl_envelope::{AgentRole, Body, Recipient, Routing, SigningKey, seal};
use rusqlite::Connection;
use zeroize::Zeroizing;

use super::*;
use crate::{
    channel::Channel,
    delivery::DeliveryStore,
    identity::{PeerCertificate, PeerTrust},
    workflow,
};

struct Pair {
    alice: LocalIdentity,
    bob: LocalIdentity,
    state: PathBuf,
    channel: Id,
}

impl Pair {
    fn new(root: &Path) -> Self {
        let alice_state = root.join("alice");
        let state = root.join("bob");
        let alice = LocalIdentity::load_or_create(&alice_state).unwrap();
        let bob = LocalIdentity::load_or_create(&state).unwrap();
        pin(&alice_state, &bob.certificate());
        pin(&state, &alice.certificate());
        let channel =
            Channel::create(&alice_state, &alice, &[*bob.certificate().device_id()]).unwrap();
        Channel::join(&state, &bob, channel.manifest()).unwrap();
        Self {
            alice,
            bob,
            state,
            channel: *channel.id(),
        }
    }

    fn delivery(&self) -> DeliveryStore {
        node::open_delivery(
            &self.state,
            &StateDirectory::open(&self.state).unwrap(),
            &self.bob.certificate(),
        )
        .unwrap()
    }

    fn frame(
        &self,
        sender: &LocalIdentity,
        sequence: u64,
        created_at: u64,
        expires_at: u64,
        body: Body<&str>,
    ) -> Vec<u8> {
        let receiver = self.bob.certificate();
        let key = Zeroizing::new(sender.signing_key().to_bytes());
        seal(
            Routing {
                channel: self.channel,
                epoch: 1,
                sender: address(&sender.certificate()),
                sequence,
                created_at,
                expires_at,
            },
            body,
            &SigningKey::from_bytes(&key),
            &[Recipient {
                address: address(&receiver),
                encryption_key: receiver.encryption_public(),
            }],
        )
        .unwrap()
    }

    fn database(&self) -> Connection {
        let connection = Connection::open(self.state.join("delivery.db")).unwrap();
        let key = StateDirectory::open(&self.state)
            .unwrap()
            .key("delivery.key")
            .unwrap();
        let encoded = Zeroizing::new(format!("x'{}'", hex::encode(key.as_slice())));
        connection
            .pragma_update(None, "key", encoded.as_str())
            .unwrap();
        connection
    }
}

fn address(certificate: &PeerCertificate) -> DeviceAddress {
    DeviceAddress {
        account: certificate.manual_account_id(),
        device: *certificate.device_id(),
    }
}

fn pin(state: &Path, certificate: &PeerCertificate) {
    PeerTrust::open(state)
        .unwrap()
        .pin(certificate, &certificate.fingerprint())
        .unwrap();
}

fn mailbox_row(ciphertext: &[u8]) -> MailboxEnvelope<'_> {
    let metadata = howl_envelope::inspect_unverified(ciphertext).unwrap();
    MailboxEnvelope {
        channel: metadata.routing.channel,
        epoch: metadata.routing.epoch,
        sender: metadata.routing.sender,
        sequence: metadata.routing.sequence,
        message: metadata.message_id,
        sent_at: metadata.routing.created_at,
        digest: Sha256::digest(ciphertext).into(),
        ciphertext,
    }
}

#[test]
fn receipt_waits_for_commit_and_retries_without_duplicate_history() {
    let root = tempfile::tempdir().unwrap();
    let pair = Pair::new(root.path());
    let now = node::unix_time().unwrap();
    let frame = pair.frame(&pair.alice, 1, now, 0, Body::Chat("held until durable"));
    let row = mailbox_row(&frame);
    drop(pair.delivery());
    pair.database()
        .execute_batch(
            "CREATE TABLE fail_commit (
                 missing INTEGER REFERENCES inbox(id) DEFERRABLE INITIALLY DEFERRED
             );
             CREATE TRIGGER fail_mailbox_commit AFTER INSERT ON inbox
             BEGIN INSERT INTO fail_commit VALUES (-1); END;",
        )
        .unwrap();

    assert!(ingest(&pair.state, mailbox_row(&frame)).is_err());
    assert!(
        pair.delivery()
            .channel_history(pair.channel, 10)
            .unwrap()
            .is_empty()
    );
    pair.database()
        .execute_batch("DROP TRIGGER fail_mailbox_commit; DROP TABLE fail_commit")
        .unwrap();

    let receipt = ingest(&pair.state, mailbox_row(&frame)).unwrap();
    assert!(receipt.inserted());
    assert_eq!(receipt.message(), row.message);
    assert_eq!(receipt.digest(), row.digest);
    assert_eq!(
        receipt.acknowledgment().recipient(),
        node::device(&pair.bob.certificate())
    );
    let replay = ingest(&pair.state, mailbox_row(&frame)).unwrap();
    assert!(!replay.inserted());
    assert_eq!(replay.acknowledgment(), receipt.acknowledgment());
    let history = pair.delivery().channel_history(pair.channel, 10).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, Body::Chat("held until durable".to_owned()));
}

#[test]
fn forged_mailbox_rows_and_nonmembers_never_receive_acknowledgments() {
    let root = tempfile::tempdir().unwrap();
    let pair = Pair::new(root.path());
    let now = node::unix_time().unwrap();
    let frame = pair.frame(&pair.alice, 1, now, 0, Body::Chat("authentic frame"));
    let changed = MailboxEnvelope {
        sequence: 2,
        ..mailbox_row(&frame)
    };
    assert!(ingest(&pair.state, changed).is_err());
    let mut tampered = frame.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(ingest(&pair.state, mailbox_row(&tampered)).is_err());

    let outsider = LocalIdentity::load_or_create(&root.path().join("outsider")).unwrap();
    pin(&pair.state, &outsider.certificate());
    let frame = pair.frame(&outsider, 1, now, 0, Body::Chat("outside the channel"));
    assert!(ingest(&pair.state, mailbox_row(&frame)).is_err());
    assert!(
        pair.delivery()
            .channel_history(pair.channel, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn hosted_wakes_stay_in_history_even_with_a_current_direct_grant() {
    let root = tempfile::tempdir().unwrap();
    let pair = Pair::new(root.path());
    let now = node::unix_time().unwrap();
    let target = AgentRole::Architect.agent_id(pair.bob.certificate().device_id());
    let mut db = pair.delivery();
    db.set_epoch(pair.channel, 1).unwrap();
    db.establish_wake_time(now).unwrap();
    db.enable_network_wake_target(
        pair.channel,
        node::device(&pair.alice.certificate()),
        target,
        1,
    )
    .unwrap();
    drop(db);

    let stale = pair.frame(
        &pair.alice,
        1,
        now - 120,
        now - 60,
        Body::Wake {
            session: target,
            text: "expired request",
        },
    );
    let fresh = pair.frame(
        &pair.alice,
        2,
        now,
        now + 120,
        Body::Wake {
            session: target,
            text: "mailbox request",
        },
    );
    assert!(ingest(&pair.state, mailbox_row(&stale)).unwrap().inserted());
    assert!(ingest(&pair.state, mailbox_row(&fresh)).unwrap().inserted());
    let mut db = pair.delivery();
    let history = db.channel_history(pair.channel, 10).unwrap();
    assert_eq!(history.len(), 2);
    for (message, text) in history.iter().zip(["mailbox request", "expired request"]) {
        assert_eq!(
            message.body,
            Body::Wake {
                session: target,
                text: text.to_owned()
            }
        );
        assert!(
            db.channel_message(pair.channel, message.sender, message.message)
                .unwrap()
                .is_none()
        );
    }
    assert!(
        workflow::claim(&pair.state, pair.channel, AgentRole::Architect)
            .unwrap()
            .is_none()
    );
    let source = pair.alice.certificate();
    let replay = node::accept_envelope(
        &pair.state,
        &pair.bob,
        &mut db,
        &fresh,
        howl_envelope::inspect_unverified(&fresh).unwrap(),
        EnvelopeSource::Peer(&source),
    )
    .unwrap();
    assert!(!replay.inserted);
    assert!(
        workflow::claim(&pair.state, pair.channel, AgentRole::Architect)
            .unwrap()
            .is_none()
    );

    let direct = pair.frame(
        &pair.alice,
        3,
        now,
        now + 120,
        Body::Wake {
            session: target,
            text: "direct request",
        },
    );
    let receipt = node::accept_envelope(
        &pair.state,
        &pair.bob,
        &mut db,
        &direct,
        howl_envelope::inspect_unverified(&direct).unwrap(),
        EnvelopeSource::Peer(&source),
    )
    .unwrap();
    assert!(receipt.inserted);
    let claim = workflow::claim(&pair.state, pair.channel, AgentRole::Architect)
        .unwrap()
        .unwrap();
    assert_eq!(claim.text, "direct request");
}

#[tokio::test]
async fn signed_pull_acks_only_after_local_commit() {
    use ed25519_dalek::Signature;
    use serde_json::{Value, json};
    use tokio::{net::TcpListener, time::timeout};

    let root = tempfile::tempdir().unwrap();
    let pair = Pair::new(root.path());
    let now = node::unix_time().unwrap();
    let good = pair.frame(&pair.alice, 2, now, 0, Body::Chat("durable HTTP pull"));
    let mut bad = pair.frame(&pair.alice, 1, now, 0, Body::Chat("tampered HTTP pull"));
    *bad.last_mut().unwrap() ^= 1;
    let digest = hex::encode(Sha256::digest(&good));
    let message = hex::encode(mailbox_row(&good).message);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let audience = [12; 32];
    let subject = [13; 32];
    let token = [14; 32];
    let public_key = pair.bob.signing_key().verifying_key();
    let credentials = json!({
        "origin": origin,
        "audience": hex::encode(audience),
        "access_expires": now + 60,
        "credentials": {
            "access_token": hex::encode(token),
            "refresh_token": hex::encode([15; 32]),
            "expires_in": 60,
            "session": {
                "id": hex::encode(subject),
                "github_id": 1234,
                "device_id": hex::encode(pair.bob.certificate().device_id()),
                "signing_key": hex::encode(public_key.as_bytes()),
            },
        },
    });
    StateDirectory::open(&pair.state)
        .unwrap()
        .replace("credentials", &serde_json::to_vec(&credentials).unwrap())
        .unwrap();
    let page = json!({ "envelopes": [hosted_row(&bad, 1), hosted_row(&good, 2)], "next": null });
    let local_state = pair.state.clone();
    let local = pair.bob.certificate();
    let channel = pair.channel;
    let server = tokio::spawn(async move {
        for (marker, operation) in [(16, "fetch"), (17, "ack")] {
            let proof_operation = format!("mailbox-{operation}");
            let nonce = [marker; 32];
            let (path, _, challenge, link) = next_http_request(&listener).await;
            assert_eq!(path, "/v1/auth/challenge");
            assert_eq!(
                serde_json::from_slice::<Value>(&challenge).unwrap(),
                json!({ "operation": proof_operation })
            );
            reply_http(
                link,
                "200 OK",
                &json!({ "nonce": hex::encode(nonce) }).to_string(),
            )
            .await;

            let (path, headers, body, link) = next_http_request(&listener).await;
            assert_eq!(path, format!("/v1/mailbox/{operation}"));
            assert_eq!(
                headers["authorization"],
                format!("Bearer {}", hex::encode(token))
            );
            assert_eq!(headers["howl-nonce"], hex::encode(nonce));
            let signature = hex::decode(&headers["howl-signature"])
                .unwrap()
                .try_into()
                .unwrap();
            let signed = crate::control_proof::signing_bytes(
                audience,
                subject,
                &proof_operation,
                nonce,
                Sha256::digest(token).into(),
                &body,
            );
            public_key
                .verify_strict(&signed, &Signature::from_bytes(&signature))
                .unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            if operation == "fetch" {
                assert_eq!(request, json!({ "after": 0, "limit": 16 }));
                reply_http(link, "200 OK", &page.to_string()).await;
            } else {
                let directory = StateDirectory::open(&local_state).unwrap();
                let store = node::open_delivery(&local_state, &directory, &local).unwrap();
                assert_eq!(store.channel_history(channel, 10).unwrap().len(), 1);
                assert_eq!(request, json!({ "message": message, "digest": digest }));
                reply_http(link, "204 No Content", "").await;
            }
        }
    });
    let report = timeout(std::time::Duration::from_secs(10), pull(&pair.state))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    assert_eq!(report.stored, 1);
    assert_eq!(report.acknowledged, 1);
    assert_eq!(report.unacknowledged, 1);
}

fn hosted_row(ciphertext: &[u8], cursor: i64) -> serde_json::Value {
    let envelope = mailbox_row(ciphertext);
    serde_json::json!({
        "cursor": cursor,
        "channel": hex::encode(envelope.channel),
        "epoch": envelope.epoch,
        "sender_account": hex::encode(envelope.sender.account),
        "sender_device": hex::encode(envelope.sender.device),
        "sequence": envelope.sequence,
        "message": hex::encode(envelope.message),
        "sent_at": envelope.sent_at,
        "digest": hex::encode(envelope.digest),
        "ciphertext": hex::encode(ciphertext),
    })
}

type TestHeaders = std::collections::HashMap<String, String>;

async fn next_http_request(
    listener: &tokio::net::TcpListener,
) -> (String, TestHeaders, Vec<u8>, tokio::net::TcpStream) {
    use tokio::io::AsyncReadExt;

    let (mut link, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    let end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        assert!(bytes.len() < 4096);
        assert!(link.read_buf(&mut bytes).await.unwrap() != 0);
    };
    let mut lines = std::str::from_utf8(&bytes[..end]).unwrap().lines();
    let path = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let headers: TestHeaders = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    let length = headers["content-length"].parse::<usize>().unwrap();
    let mut body = bytes.split_off(end + 4);
    assert!(length <= 4096);
    if body.len() < length {
        let have = body.len();
        body.resize(length, 0);
        link.read_exact(&mut body[have..]).await.unwrap();
    }
    (path, headers, body, link)
}

async fn reply_http(mut link: tokio::net::TcpStream, status: &str, body: &str) {
    use tokio::io::AsyncWriteExt;

    let response = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len(),
    );
    link.write_all(response.as_bytes()).await.unwrap();
    link.shutdown().await.unwrap();
}
