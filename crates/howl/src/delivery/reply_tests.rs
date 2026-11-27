use howl_envelope::{AgentRole, DeviceAddress, RecipientSecret, Routing, inspect_unverified, seal};

use super::*;

const LOCAL: Device = Device {
    account: [1; 32],
    device: [2; 32],
};
const PEER: Device = Device {
    account: [3; 32],
    device: [4; 32],
};
const CHANNEL: Id = [5; 32];

fn frame(sender: Device, message: u8, expires_at: u64) -> Frame {
    Frame {
        stream: Stream {
            channel: CHANNEL,
            sender,
            signing_key: [6; 32],
        },
        message: [message; 32],
        sequence: 1,
        epoch: 1,
        created_at: 10,
        expires_at,
    }
}

#[test]
fn records_outbound_messages_only_after_a_successful_enqueue() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("delivery.db");
    let key = [9; 32];
    let mut store = DeliveryStore::open(&path, &key, LOCAL).unwrap();
    store.set_epoch(CHANNEL, 1).unwrap();
    let outgoing = frame(LOCAL, 20, 0);
    assert!(matches!(
        store.enqueue_routed_message(
            outgoing,
            b"signed outbound chat",
            PEER,
            "127.0.0.1:9",
            10,
            Some(Body::Chat("hello")),
        ),
        Err(Error::Unreserved)
    ));
    assert!(store.channel_events(CHANNEL, 0, 10).unwrap().is_empty());
    store.reserve_sequence(outgoing.stream).unwrap();
    for _ in 0..2 {
        store
            .enqueue_routed_message(
                outgoing,
                b"signed outbound chat",
                PEER,
                "127.0.0.1:9",
                10,
                Some(Body::Chat("hello")),
            )
            .unwrap();
    }
    drop(store);

    let store = DeliveryStore::open(&path, &key, LOCAL).unwrap();
    let events = store.channel_events(CHANNEL, 0, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].recipient, Some(PEER));
    assert_eq!(events[0].message.sender, LOCAL);
    assert_eq!(events[0].message.body, Body::Chat("hello".to_owned()));
    assert!(store.channel_history(CHANNEL, 10).unwrap().is_empty());
    assert!(store.chat_history(CHANNEL, 10).unwrap().is_empty());
    assert_eq!(
        store.direct_events(CHANNEL, LOCAL, PEER, 0, 10).unwrap(),
        events
    );
    let other = Device {
        device: [13; 32],
        ..PEER
    };
    assert!(
        store
            .direct_events(CHANNEL, LOCAL, other, 0, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn direct_event_replay_uses_only_signed_single_recipient_messages() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DeliveryStore::open(&root.path().join("delivery.db"), &[9; 32], LOCAL).unwrap();
    store.set_epoch(CHANNEL, 1).unwrap();
    let local_signer = SigningKey::from_bytes(&[10; 32]);
    let peer_signer = howl_envelope::SigningKey::from_bytes(&[11; 32]);
    let local_address = DeviceAddress {
        account: LOCAL.account,
        device: LOCAL.device,
    };
    let local_recipient = RecipientSecret::from_bytes(local_address, &[12; 32])
        .unwrap()
        .public_recipient();
    let other_recipient = RecipientSecret::from_bytes(
        DeviceAddress {
            device: [13; 32],
            ..local_address
        },
        &[14; 32],
    )
    .unwrap()
    .public_recipient();
    let mut message_ids = Vec::new();
    for sequence in 1..=4 {
        let recipients = if sequence == 1 {
            vec![local_recipient, other_recipient]
        } else {
            vec![local_recipient]
        };
        let sealed = seal(
            Routing {
                channel: CHANNEL,
                sender: DeviceAddress {
                    account: PEER.account,
                    device: PEER.device,
                },
                epoch: 1,
                sequence,
                created_at: 10,
                expires_at: 0,
            },
            Body::Chat("hello"),
            &peer_signer,
            &recipients,
        )
        .unwrap();
        let metadata = inspect_unverified(&sealed).unwrap();
        let message = Frame {
            stream: Stream {
                signing_key: metadata.signing_key_id,
                ..frame(PEER, 1, 0).stream
            },
            message: metadata.message_id,
            sequence,
            ..frame(PEER, 1, 0)
        };
        store
            .accept_authenticated(message, &sealed, Payload::Chat("hello"), 10, &local_signer)
            .unwrap();
        message_ids.push(message.message);
    }
    store
        .connection
        .execute(
            "DELETE FROM channel_event_addresses WHERE cursor IN (1, 2, 4)",
            [],
        )
        .unwrap();
    store
        .connection
        .execute("UPDATE inbox SET frame = NULL WHERE id IN (3, 4)", [])
        .unwrap();

    let first = store.direct_events(CHANNEL, LOCAL, PEER, 0, 1).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].recipient, Some(LOCAL));
    assert_eq!(first[0].message.message, message_ids[1]);
    let rest = store
        .direct_events(CHANNEL, LOCAL, PEER, first[0].cursor, 10)
        .unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].message.message, message_ids[2]);
    assert_eq!(store.channel_events(CHANNEL, 0, 10).unwrap().len(), 4);
}

#[test]
fn only_the_linked_running_wake_can_publish_and_finish_in_one_transaction() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DeliveryStore::open(&root.path().join("delivery.db"), &[9; 32], LOCAL).unwrap();
    let actor = AgentRole::Architect;
    let agent = actor.agent_id(&LOCAL.device);
    let signer = SigningKey::from_bytes(&[10; 32]);
    let human = SigningKey::from_bytes(&[11; 32]);
    store.set_epoch(CHANNEL, 1).unwrap();
    store.establish_wake_time(10).unwrap();
    store
        .enable_network_wake_target(CHANNEL, PEER, agent, 1)
        .unwrap();
    let wake = frame(PEER, 12, 30);
    let payload = Payload::Wake {
        target: agent,
        text: "draft a plan",
    };
    let other = Device {
        account: PEER.account,
        device: [13; 32],
    };
    assert!(matches!(
        store.accept_network_wake(
            frame(other, 12, 30),
            b"wrong sender",
            payload,
            || Ok(10),
            &signer
        ),
        Err(Error::WakeGrant)
    ));
    assert!(
        store
            .accept_network_wake(wake, b"signed wake", payload, || Ok(10), &signer)
            .unwrap()
            .inserted
    );
    assert!(
        !store
            .accept_network_wake(wake, b"signed wake", payload, || Ok(10), &signer)
            .unwrap()
            .inserted
    );
    let claim = store.claim_wake(CHANNEL, agent, 10).unwrap().unwrap();
    assert!(store.claim_wake(CHANNEL, agent, 10).unwrap().is_none());
    let approval = WakeApproval {
        nonce: [14; 32],
        expires_at: 29,
        claim: &claim,
        agent,
        cause: None,
    };
    let signature = human.sign(&approval.signing_bytes(LOCAL)).to_bytes();
    let limits = BudgetLimits {
        turns: 2,
        concurrent: 1,
        depth: 1,
        fan_out: 1,
        cooldown_seconds: 0,
        rate_turns: 2,
        rate_window_seconds: 30,
        lifetime_seconds: 10,
    };
    let turn = store
        .conversation_budget(limits, human.verifying_key())
        .unwrap()
        .start_approved_wake(approval, &signature, || Ok(10), |_, _| true)
        .unwrap()
        .turn;
    let outgoing = frame(LOCAL, 15, 0);
    store.reserve_sequence(outgoing.stream).unwrap();
    let publication = ApprovedAgentReply {
        execution: claim.execution,
        reply: AgentReply {
            agent,
            role: actor,
            in_reply_to: wake.message,
            context_digest: [16; 32],
            text: "draft",
        },
    };
    assert!(matches!(
        store.enqueue_agent_reply(
            outgoing,
            b"signed agent reply",
            other,
            "127.0.0.1:9",
            || Ok(11),
            publication,
        ),
        Err(Error::WakeGrant)
    ));
    assert!(
        store
            .delivery_status(outgoing.stream, outgoing.message)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.wake_state(claim.execution).unwrap(),
        Some(WakeState::Running)
    );
    store
        .enqueue_agent_reply(
            outgoing,
            b"signed agent reply",
            PEER,
            "127.0.0.1:9",
            || Ok(11),
            publication,
        )
        .unwrap();
    assert_eq!(
        store.wake_state(claim.execution).unwrap(),
        Some(WakeState::Finished)
    );
    assert!(
        !store
            .conversation_budget(limits, human.verifying_key())
            .unwrap()
            .finish_turn(turn.id)
            .unwrap()
    );
    assert!(matches!(
        store.enqueue_agent_reply(
            outgoing,
            b"signed agent reply",
            PEER,
            "127.0.0.1:9",
            || Ok(11),
            publication,
        ),
        Err(Error::WakeGrant)
    ));
    assert_eq!(
        store
            .delivery_status(outgoing.stream, outgoing.message)
            .unwrap()
            .len(),
        1
    );
    let events = store.channel_events(CHANNEL, 0, 10).unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0].message.body, Body::Wake { .. }));
    assert_eq!(events[1].recipient, Some(PEER));
    assert_eq!(events[1].message.message, outgoing.message);
    assert!(matches!(&events[1].message.body, Body::AgentReply(reply) if reply.text == "draft"));

    let next = Frame {
        sequence: 2,
        ..frame(PEER, 17, 40)
    };
    store
        .accept_network_wake(next, b"next signed wake", payload, || Ok(11), &signer)
        .unwrap();
    let claim = store.claim_wake(CHANNEL, agent, 11).unwrap().unwrap();
    let approval = WakeApproval {
        claim: &claim,
        nonce: [18; 32],
        ..approval
    };
    let signature = human.sign(&approval.signing_bytes(LOCAL)).to_bytes();
    store
        .conversation_budget(limits, human.verifying_key())
        .unwrap()
        .start_approved_wake(approval, &signature, || Ok(11), |_, _| true)
        .unwrap();
    let outgoing = Frame {
        sequence: 2,
        ..frame(LOCAL, 19, 0)
    };
    store.reserve_sequence(outgoing.stream).unwrap();
    let publication = ApprovedAgentReply {
        execution: claim.execution,
        reply: AgentReply {
            in_reply_to: next.message,
            ..publication.reply
        },
    };
    assert!(matches!(
        store.enqueue_agent_reply(
            outgoing,
            b"late reply",
            PEER,
            "127.0.0.1:9",
            || Ok(21),
            publication
        ),
        Err(Error::WakeGrant)
    ));
    assert!(matches!(
        store.enqueue_agent_reply(
            outgoing,
            b"rolled back clock",
            PEER,
            "127.0.0.1:9",
            || Ok(12),
            publication
        ),
        Err(Error::WakeClock)
    ));
    assert!(
        store
            .delivery_status(outgoing.stream, outgoing.message)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn network_wakes_recheck_expiry_under_the_inbox_write_lock_before_acknowledging() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("delivery.db");
    let key = [9; 32];
    let mut receiver = DeliveryStore::open(&path, &key, LOCAL).unwrap();
    let probe = DeliveryStore::open(&path, &key, LOCAL).unwrap();
    probe.connection.busy_timeout(Duration::ZERO).unwrap();
    let signer = SigningKey::from_bytes(&[10; 32]);
    let target = AgentRole::Reviewer.agent_id(&LOCAL.device);
    let payload = Payload::Wake {
        target,
        text: "review",
    };
    receiver.set_epoch(CHANNEL, 1).unwrap();
    receiver.establish_wake_time(10).unwrap();
    receiver
        .enable_network_wake_target(CHANNEL, PEER, target, 1)
        .unwrap();
    let existing = frame(PEER, 21, 30);
    assert!(
        receiver
            .accept_network_wake(existing, b"existing wake", payload, || Ok(10), &signer)
            .unwrap()
            .inserted
    );

    let first_attempt = Frame {
        sequence: 2,
        ..frame(PEER, 22, 20)
    };
    let fresh = || {
        let result = probe.connection.execute_batch("BEGIN IMMEDIATE");
        assert_eq!(
            result.unwrap_err().sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        Ok(20)
    };
    assert!(matches!(
        receiver.accept_network_wake(first_attempt, b"first attempt", payload, fresh, &signer),
        Err(Error::Expired)
    ));
    assert!(matches!(
        receiver.accept_network_wake(first_attempt, b"first attempt", payload, || Ok(19), &signer),
        Err(Error::WakeClock)
    ));
    assert!(matches!(
        receiver.accept_network_wake(existing, b"existing wake", payload, || Ok(30), &signer),
        Err(Error::Expired)
    ));
    assert_eq!(
        receiver
            .connection
            .query_row("SELECT count(*) FROM wake_queue", [], |row| row
                .get::<_, u32>(0))
            .unwrap(),
        1
    );
}
