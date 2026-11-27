use std::path::Path;

use ed25519_dalek::SigningKey;
use serde_json::Value;

use super::*;
use crate::delivery::{Device, Frame, Payload, Stream};

const LOCAL: Device = Device {
    account: [1; 32],
    device: [2; 32],
};
const PEER: Device = Device {
    account: [1; 32],
    device: [3; 32],
};
const CHANNEL: Id = [4; 32];
const OTHER: Id = [5; 32];
const KEY: Id = [6; 32];
const MESSAGE_FILTER: &[WebhookEventKind] = &[WebhookEventKind::MessageReceived];

fn store(path: &Path) -> DeliveryStore {
    let mut store = DeliveryStore::open(path, &KEY, LOCAL).unwrap();
    store.initialize_webhooks().unwrap();
    store.set_epoch(CHANNEL, 1).unwrap();
    store.set_epoch(OTHER, 1).unwrap();
    store
}

fn frame(channel: Id, sequence: u64, now: u64, expires_at: u64) -> Frame {
    Frame {
        stream: Stream {
            channel,
            sender: PEER,
            signing_key: [7; 32],
        },
        message: [sequence.try_into().unwrap(); 32],
        sequence,
        epoch: 1,
        created_at: now,
        expires_at,
    }
}

fn admit(store: &mut DeliveryStore, frame: Frame, payload: Payload<'_>, now: u64) {
    assert!(
        store
            .accept_authenticated(
                frame,
                &frame.sequence.to_be_bytes(),
                payload,
                now,
                &SigningKey::from_bytes(&[8; 32]),
            )
            .unwrap()
            .inserted
    );
}

fn filter(name: &str, content: bool) -> WebhookFilter<'_> {
    WebhookFilter {
        name,
        revision: [9; 32],
        channels: &[CHANNEL],
        events: MESSAGE_FILTER,
        include_content: content,
    }
}

#[test]
fn outbox_recovers_unfinished_lease_and_deduplicates_one_event_per_destination() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("delivery.db");
    let now = crate::node::unix_time().unwrap();
    let filters = [filter("metadata", false), filter("content", true)];
    let mut producer = DeliveryStore::open(&path, &KEY, LOCAL).unwrap();
    let mut delivery = store(&path);
    admit(
        &mut producer,
        frame(CHANNEL, 1, now, 0),
        Payload::Chat("before opt-in"),
        now,
    );
    delivery.synchronize_webhooks(&filters, now).unwrap();
    admit(
        &mut producer,
        frame(OTHER, 2, now, 0),
        Payload::Chat("private other channel"),
        now,
    );
    let message = frame(CHANNEL, 3, now, 0);
    admit(
        &mut producer,
        message,
        Payload::Chat("secret within authorized channel"),
        now,
    );
    delivery.synchronize_webhooks(&filters, now).unwrap();
    let metadata = delivery.claim_webhook(now).unwrap().unwrap();
    let public_body: Value = serde_json::from_str(&metadata.body).unwrap();
    assert_eq!(metadata.destination, "metadata");
    assert_eq!(public_body["source"], hex::encode(message.message));
    assert_eq!(public_body["event"], "message.received");
    assert!(public_body.get("content").is_none());
    drop(delivery);

    let mut delivery = store(&path);
    let content = delivery.claim_webhook(now).unwrap().unwrap();
    assert_eq!(content.destination, "content");
    assert_eq!(content.event, metadata.event);
    let full_body: Value = serde_json::from_str(&content.body).unwrap();
    assert_eq!(full_body["content"], "secret within authorized channel");
    delivery
        .finish_webhook(&content, WebhookOutcome::Delivered, now)
        .unwrap();
    assert!(
        delivery
            .claim_webhook(now + LEASE_SECONDS as u64 - 1)
            .unwrap()
            .is_none()
    );
    let recovered_at = now + LEASE_SECONDS as u64;
    let recovered = delivery.claim_webhook(recovered_at).unwrap().unwrap();
    assert_eq!(recovered.event, metadata.event);
    assert_eq!(recovered.body, metadata.body);
    delivery
        .finish_webhook(&metadata, WebhookOutcome::Delivered, recovered_at)
        .unwrap();
    delivery
        .finish_webhook(&recovered, WebhookOutcome::Rejected, recovered_at)
        .unwrap();
    let failures = serde_json::to_value(delivery.webhook_failures().unwrap()).unwrap();
    assert_eq!(failures[0]["attempts"], 2);
    assert_eq!(failures[0]["state"], "dead");
    assert!(failures[0].get("body").is_none());

    assert!(
        delivery
            .replay_webhook(&filters[0], recovered.event, recovered_at)
            .unwrap()
    );
    let replay = delivery.claim_webhook(recovered_at).unwrap().unwrap();
    assert_eq!(replay.event, recovered.event);
    assert_eq!(replay.body, recovered.body);
    delivery.synchronize_webhooks(&[], recovered_at).unwrap();
    assert!(
        !delivery
            .replay_webhook(&filters[0], replay.event, recovered_at)
            .unwrap()
    );
    assert!(delivery.claim_webhook(recovered_at + 30).unwrap().is_none());
}

#[test]
fn retry_metadata_redacts_content_and_uses_backoff() {
    let temp = tempfile::tempdir().unwrap();
    let mut delivery = store(&temp.path().join("delivery.db"));
    let now = crate::node::unix_time().unwrap();
    let filters = [filter("receiver", true)];
    delivery.synchronize_webhooks(&filters, now).unwrap();
    admit(
        &mut delivery,
        frame(CHANNEL, 1, now, 0),
        Payload::Chat("secret research note"),
        now,
    );
    delivery.synchronize_webhooks(&filters, now).unwrap();
    let attempt = delivery.claim_webhook(now).unwrap().unwrap();
    delivery
        .finish_webhook(&attempt, WebhookOutcome::Retry, now)
        .unwrap();
    assert!(delivery.claim_webhook(now + 1).unwrap().is_none());
    let failures = serde_json::to_string(&delivery.webhook_failures().unwrap()).unwrap();
    assert!(failures.contains("retrying"));
    assert!(!failures.contains("secret"));
    let retry = delivery.claim_webhook(now + 4).unwrap().unwrap();
    assert_eq!(retry.event, attempt.event);
    assert_eq!(retry.body, attempt.body);
}

#[test]
fn scoped_mention_approval_and_failed_run_metadata_are_journaled() {
    let temp = tempfile::tempdir().unwrap();
    let mut delivery = store(&temp.path().join("delivery.db"));
    let now = crate::node::unix_time().unwrap();
    let filters = [WebhookFilter {
        events: &[
            WebhookEventKind::Mention,
            WebhookEventKind::ApprovalRequested,
            WebhookEventKind::RunFailed,
        ],
        ..filter("receiver", false)
    }];
    delivery.synchronize_webhooks(&filters, now).unwrap();
    let agent = AgentRole::Reviewer.agent_id(&LOCAL.device);
    admit(
        &mut delivery,
        frame(CHANNEL, 1, now, 0),
        Payload::Chat(&format!("Review requested @{}", hex::encode(agent))),
        now,
    );
    admit(
        &mut delivery,
        frame(CHANNEL, 2, now, 0),
        Payload::Chat("user@example.org"),
        now,
    );
    delivery.establish_wake_time(now).unwrap();
    delivery
        .enable_network_wake_target(CHANNEL, PEER, agent, 1)
        .unwrap();
    admit(
        &mut delivery,
        frame(CHANNEL, 3, now, now + 30),
        Payload::Wake {
            target: agent,
            text: "Need a human approval",
        },
        now,
    );
    delivery
        .connection
        .execute(
            "INSERT INTO integration_runs
          (id, owner, request_key, fingerprint, channel, peer, target,
           created_at, updated_at, dispatch_before, finish_before)
         VALUES (?1, 'adapter', 'test', ?1, ?2, ?3, ?4, ?5, ?5, ?5, ?5)",
            params![
                [11u8; 32],
                CHANNEL,
                PEER.device,
                agent,
                timestamp(now).unwrap()
            ],
        )
        .unwrap();
    delivery.synchronize_webhooks(&filters, now).unwrap();
    for expected in ["mention", "approval.requested", "run.failed"] {
        let attempt = delivery.claim_webhook(now).unwrap().unwrap();
        let body: Value = serde_json::from_str(&attempt.body).unwrap();
        assert_eq!(body["event"], expected);
        assert_eq!(body["target"], hex::encode(agent));
        assert!(body.get("content").is_none());
        delivery
            .finish_webhook(&attempt, WebhookOutcome::Delivered, now)
            .unwrap();
    }
    assert!(delivery.claim_webhook(now).unwrap().is_none());
}
