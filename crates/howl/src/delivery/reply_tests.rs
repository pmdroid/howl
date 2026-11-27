use howl_envelope::AgentRole;

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
        store.accept_network_wake(frame(other, 12, 30), b"wrong sender", payload, 10, &signer),
        Err(Error::WakeGrant)
    ));
    assert!(
        store
            .accept_network_wake(wake, b"signed wake", payload, 10, &signer)
            .unwrap()
            .inserted
    );
    assert!(
        !store
            .accept_network_wake(wake, b"signed wake", payload, 10, &signer)
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
            11,
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
            11,
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
            11,
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
}
