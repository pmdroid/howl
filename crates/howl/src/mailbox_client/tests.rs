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
