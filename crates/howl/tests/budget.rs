use ed25519_dalek::{Signer, SigningKey};
use howl::delivery::{
    BudgetError, BudgetLimit, BudgetLimits, ConversationBudget, DeliveryStore, Device, Frame,
    HumanAction, HumanCommand, Id, Payload, Stream, Turn, WakeApproval, WakeClaim, WakeOutcome,
    WakeState, WakeTurnError,
};

const LOCAL: Device = Device {
    account: [1; 32],
    device: [2; 32],
};
const OTHER: Device = Device {
    account: [1; 32],
    device: [3; 32],
};
const A: Id = [11; 32];
const B: Id = [12; 32];
const C: Id = [13; 32];
const D: Id = [14; 32];
const STORE_KEY: Id = [15; 32];

fn limits() -> BudgetLimits {
    BudgetLimits {
        turns: 12,
        concurrent: 4,
        depth: 4,
        fan_out: 4,
        cooldown_seconds: 0,
        rate_turns: 20,
        rate_window_seconds: 10,
        lifetime_seconds: 60,
    }
}

fn human() -> SigningKey {
    SigningKey::from_bytes(&[27; 32])
}

fn command(nonce: u8, action: HumanAction, expires_at: u64) -> HumanCommand {
    HumanCommand {
        nonce: [nonce; 32],
        expires_at,
        action,
    }
}

fn begin(budget: &mut ConversationBudget<'_>, nonce: u8, agent: Id, now: u64) -> Turn {
    let command = command(nonce, HumanAction::Begin { agent }, now + 1);
    let signature = human().sign(&command.signing_bytes(LOCAL)).to_bytes();
    budget
        .apply_human(command, &signature, now)
        .unwrap()
        .unwrap()
}

#[test]
fn fan_out_and_cyclic_mentions_stop_at_the_daemon_derived_limits() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DeliveryStore::open(&root.path().join("budget"), &STORE_KEY, LOCAL).unwrap();
    let mut budget = store
        .conversation_budget(
            BudgetLimits {
                fan_out: 2,
                depth: 2,
                ..limits()
            },
            human().verifying_key(),
        )
        .unwrap();

    let first = begin(&mut budget, 1, A, 10);
    assert_eq!((first.cause, first.hop), (None, 0));
    let second = budget.begin_child(first.id, A, B, 10).unwrap();
    let sibling = budget.begin_child(first.id, A, C, 10).unwrap();
    assert_eq!(
        (second.root, second.cause, second.hop),
        (first.root, Some(first.id), 1)
    );
    assert_eq!(
        (sibling.root, sibling.cause, sibling.hop),
        (first.root, Some(first.id), 1)
    );
    assert!(matches!(
        budget.begin_child(first.id, A, D, 10),
        Err(BudgetError::Limit(BudgetLimit::FanOut))
    ));

    let cycle = budget.begin_child(second.id, B, A, 10).unwrap();
    assert_eq!(
        (cycle.root, cycle.cause, cycle.agent, cycle.hop),
        (first.root, Some(second.id), A, 2)
    );
    assert!(matches!(
        budget.begin_child(cycle.id, A, B, 10),
        Err(BudgetError::Limit(BudgetLimit::Depth))
    ));
    assert!(matches!(
        budget.begin_child(second.id, D, A, 10),
        Err(BudgetError::Cause)
    ));
    assert!(matches!(
        budget.begin_child([99; 32], A, B, 10),
        Err(BudgetError::Unknown)
    ));
}

#[test]
fn model_cannot_reset_counts_and_human_continuation_keeps_the_same_root() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DeliveryStore::open(&root.path().join("budget"), &STORE_KEY, LOCAL).unwrap();
    let mut budget = store
        .conversation_budget(
            BudgetLimits {
                turns: 2,
                ..limits()
            },
            human().verifying_key(),
        )
        .unwrap();
    let first_command = command(1, HumanAction::Begin { agent: A }, 70);
    let signed = human().sign(&first_command.signing_bytes(LOCAL)).to_bytes();
    let bad_signature = SigningKey::from_bytes(&[17; 32])
        .sign(&first_command.signing_bytes(LOCAL))
        .to_bytes();
    assert!(matches!(
        budget.apply_human(first_command, &bad_signature, 10),
        Err(BudgetError::Human)
    ));
    let wrong_node = human().sign(&first_command.signing_bytes(OTHER)).to_bytes();
    assert!(matches!(
        budget.apply_human(first_command, &wrong_node, 10),
        Err(BudgetError::Human)
    ));
    let first = budget
        .apply_human(first_command, &signed, 10)
        .unwrap()
        .unwrap();
    assert!(matches!(
        budget.apply_human(first_command, &signed, 10),
        Err(BudgetError::Replay)
    ));

    let second = budget.begin_child(first.id, A, B, 11).unwrap();
    assert!(matches!(
        budget.begin_child(second.id, B, A, 12),
        Err(BudgetError::Limit(BudgetLimit::Turns))
    ));
    assert!(budget.finish_turn(first.id).unwrap());
    assert!(budget.finish_turn(second.id).unwrap());
    let extend = command(
        2,
        HumanAction::Continue {
            cause: second.id,
            agent: A,
        },
        70,
    );
    let forged = HumanCommand {
        action: HumanAction::Continue {
            cause: first.id,
            agent: D,
        },
        ..extend
    };
    let signature = human().sign(&extend.signing_bytes(LOCAL)).to_bytes();
    assert!(matches!(
        budget.apply_human(forged, &signature, 12),
        Err(BudgetError::Human)
    ));
    let continued = budget.apply_human(extend, &signature, 12).unwrap().unwrap();
    assert_eq!(
        (
            continued.root,
            continued.cause,
            continued.hop,
            continued.expires_at
        ),
        (first.root, Some(second.id), 2, first.expires_at)
    );
    assert!(matches!(
        budget.apply_human(extend, &signature, 12),
        Err(BudgetError::Replay)
    ));

    let fourth = budget.begin_child(continued.id, A, B, 12).unwrap();
    assert!(matches!(
        budget.begin_child(fourth.id, B, C, 12),
        Err(BudgetError::Limit(BudgetLimit::Turns))
    ));
}

#[test]
fn limits_concurrency_cooldown_rate_and_lifetime_across_roots() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("budget");
    let policy = BudgetLimits {
        concurrent: 1,
        cooldown_seconds: 3,
        rate_turns: 2,
        rate_window_seconds: 10,
        lifetime_seconds: 20,
        ..limits()
    };
    let mut store = DeliveryStore::open(&path, &STORE_KEY, LOCAL).unwrap();
    let mut budget = store
        .conversation_budget(policy, human().verifying_key())
        .unwrap();
    let first = begin(&mut budget, 1, A, 10);
    let other_root = command(2, HumanAction::Begin { agent: B }, 40);
    let other_signed = human().sign(&other_root.signing_bytes(LOCAL)).to_bytes();
    assert!(matches!(
        budget.apply_human(other_root, &other_signed, 10),
        Err(BudgetError::Limit(BudgetLimit::Concurrent))
    ));
    assert!(budget.finish_turn(first.id).unwrap());
    assert!(matches!(
        budget.begin_child(first.id, A, A, 12),
        Err(BudgetError::Limit(BudgetLimit::Cooldown))
    ));
    let other = budget
        .apply_human(other_root, &other_signed, 12)
        .unwrap()
        .unwrap();
    assert_ne!(other.root, first.root);
    assert!(budget.finish_turn(other.id).unwrap());
    assert!(matches!(
        budget.begin_child(first.id, A, B, 19),
        Err(BudgetError::Limit(BudgetLimit::Rate))
    ));
    let child = budget.begin_child(first.id, A, C, 20).unwrap();
    assert_eq!(child.expires_at, 30);
    assert!(matches!(
        budget.may_run(child.id, 30),
        Err(BudgetError::Limit(BudgetLimit::Lifetime))
    ));
    drop(store);

    let mut store = DeliveryStore::open(&path, &STORE_KEY, LOCAL).unwrap();
    let mut budget = store
        .conversation_budget(policy, human().verifying_key())
        .unwrap();
    assert!(matches!(
        budget.may_run(child.id, 29),
        Err(BudgetError::Clock)
    ));
    assert_eq!(budget.recover_turns().unwrap(), 1);
    assert!(matches!(
        budget.begin_child(child.id, C, D, 30),
        Err(BudgetError::Cause)
    ));
    assert_eq!(budget.recover_turns().unwrap(), 0);
}

#[test]
fn delayed_signed_pause_is_terminal_after_local_receipt_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("budget");
    let mut store = DeliveryStore::open(&path, &STORE_KEY, LOCAL).unwrap();
    let mut budget = store
        .conversation_budget(limits(), human().verifying_key())
        .unwrap();
    let turn = begin(&mut budget, 1, A, 10);
    let pause = command(2, HumanAction::Pause { root: turn.root }, 0);
    let signature = human().sign(&pause.signing_bytes(LOCAL)).to_bytes();
    assert!(budget.may_run(turn.id, 11).is_ok());
    let wrong_device_signature = human().sign(&pause.signing_bytes(OTHER)).to_bytes();
    assert!(matches!(
        budget.apply_human(pause, &wrong_device_signature, 12),
        Err(BudgetError::Human)
    ));
    assert!(budget.may_run(turn.id, 13).is_ok());

    assert!(budget.apply_human(pause, &signature, 12).unwrap().is_none());
    assert!(matches!(
        budget.may_run(turn.id, 14),
        Err(BudgetError::Limit(BudgetLimit::Paused))
    ));
    drop(store);

    let mut store = DeliveryStore::open(&path, &STORE_KEY, LOCAL).unwrap();
    assert!(matches!(
        store.conversation_budget(
            BudgetLimits {
                turns: 99,
                ..limits()
            },
            human().verifying_key(),
        ),
        Err(BudgetError::Policy)
    ));
    assert!(matches!(
        store.conversation_budget(limits(), SigningKey::from_bytes(&[92; 32]).verifying_key(),),
        Err(BudgetError::Policy)
    ));
    let mut budget = store
        .conversation_budget(limits(), human().verifying_key())
        .unwrap();
    assert!(matches!(
        budget.begin_child(turn.id, A, B, 15),
        Err(BudgetError::Limit(BudgetLimit::Paused))
    ));
    assert!(matches!(
        budget.apply_human(pause, &signature, 15),
        Err(BudgetError::Replay)
    ));
    let continuation = command(
        3,
        HumanAction::Continue {
            cause: turn.id,
            agent: A,
        },
        70,
    );
    let signature = human().sign(&continuation.signing_bytes(LOCAL)).to_bytes();
    assert!(matches!(
        budget.apply_human(continuation, &signature, 15),
        Err(BudgetError::Limit(BudgetLimit::Paused))
    ));
}

const WAKE_STREAM: Stream = Stream {
    channel: [42; 32],
    sender: OTHER,
    signing_key: [43; 32],
};
const WAKE_TARGET: Id = [44; 32];

fn accept_and_claim_wake(store: &mut DeliveryStore, sequence: u64, now: u64) -> WakeClaim {
    let message = [sequence as u8; 32];
    store
        .accept_authenticated(
            Frame {
                stream: WAKE_STREAM,
                message,
                sequence,
                epoch: 1,
                created_at: now,
                expires_at: now + 20,
            },
            &message,
            Payload::Wake {
                target: WAKE_TARGET,
                text: "Analyze the fixture repository",
            },
            now,
            &human(),
        )
        .unwrap();
    store
        .claim_wake(WAKE_STREAM.channel, WAKE_TARGET, now)
        .unwrap()
        .unwrap()
}

fn open_wake_store(path: &std::path::Path) -> DeliveryStore {
    let mut store = DeliveryStore::open(path, &STORE_KEY, LOCAL).unwrap();
    store.set_epoch(WAKE_STREAM.channel, 1).unwrap();
    store.establish_wake_time(10).unwrap();
    store
        .enable_wake_target(WAKE_STREAM.channel, WAKE_TARGET, 1)
        .unwrap();
    store
}

fn approve(claim: &WakeClaim, nonce: u8) -> WakeApproval<'_> {
    WakeApproval {
        nonce: [nonce; 32],
        expires_at: 40,
        claim,
        agent: A,
        cause: None,
    }
}

fn authorized(claim: &WakeClaim, agent: Id) -> bool {
    claim.stream == WAKE_STREAM && claim.target == WAKE_TARGET && agent == A
}

#[test]
fn exact_wake_approval_and_budget_admission_commit_together() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("approved-wakes");
    let mut store = open_wake_store(&path);
    let first = accept_and_claim_wake(&mut store, 1, 10);
    let second = accept_and_claim_wake(&mut store, 2, 11);
    drop(store);
    let before_upgrade = rusqlite::Connection::open(&path).unwrap();
    before_upgrade
        .pragma_update(None, "key", format!("x'{}'", hex::encode(STORE_KEY)))
        .unwrap();
    before_upgrade
        .execute("DROP TABLE budget_wakes", [])
        .unwrap();
    drop(before_upgrade);
    let mut store = DeliveryStore::open(&path, &STORE_KEY, LOCAL).unwrap();
    let preview = store
        .preview_claimed_wake(first.execution)
        .unwrap()
        .unwrap();
    assert_eq!(preview.claim, first);
    assert_eq!(preview.text, "Analyze the fixture repository");

    let policy = BudgetLimits {
        concurrent: 1,
        ..limits()
    };
    let mut budget = store
        .conversation_budget(policy, human().verifying_key())
        .unwrap();

    let approval = approve(&first, 1);
    let signature = human().sign(&approval.signing_bytes(LOCAL)).to_bytes();
    assert!(matches!(
        budget.start_approved_wake(
            WakeApproval {
                agent: B,
                ..approval
            },
            &signature,
            || Ok(11),
            authorized
        ),
        Err(WakeTurnError::Approval),
    ));
    assert!(matches!(
        budget.start_approved_wake(
            WakeApproval {
                claim: &second,
                ..approval
            },
            &signature,
            || Ok(11),
            authorized
        ),
        Err(WakeTurnError::Approval),
    ));
    let started = budget
        .start_approved_wake(approval, &signature, || Ok(11), authorized)
        .unwrap();
    assert_eq!(&started.job.claim, &first);
    assert_eq!(started.job.text, "Analyze the fixture repository");
    assert_eq!(started.turn.agent, A);
    assert_eq!(started.deadline(), first.expires_at);

    let second_approval = approve(&second, 2);
    let second_signature = human()
        .sign(&second_approval.signing_bytes(LOCAL))
        .to_bytes();
    assert!(matches!(
        budget.start_approved_wake(second_approval, &second_signature, || Ok(12), authorized),
        Err(WakeTurnError::Budget(BudgetError::Limit(
            BudgetLimit::Concurrent
        ))),
    ));
    drop(store);

    let mut store = DeliveryStore::open(&path, &STORE_KEY, LOCAL).unwrap();
    assert_eq!(
        store.wake_state(first.execution).unwrap(),
        Some(WakeState::Running)
    );
    assert_eq!(
        store.wake_state(second.execution).unwrap(),
        Some(WakeState::Claimed)
    );
    let mut budget = store
        .conversation_budget(policy, human().verifying_key())
        .unwrap();
    assert!(matches!(
        budget.start_approved_wake(approval, &signature, || Ok(12), authorized),
        Err(WakeTurnError::Unavailable),
    ));
    assert_eq!(
        budget
            .finish_approved_wake(first.execution, WakeOutcome::Finished)
            .unwrap(),
        Some(WakeOutcome::Finished),
    );
    assert_eq!(
        budget
            .finish_approved_wake(first.execution, WakeOutcome::Finished)
            .unwrap(),
        None,
    );

    let next = budget
        .start_approved_wake(second_approval, &second_signature, || Ok(13), authorized)
        .unwrap();
    assert_eq!(&next.job.claim, &second);
    assert_eq!(
        budget
            .finish_approved_wake(second.execution, WakeOutcome::Uncertain)
            .unwrap(),
        Some(WakeOutcome::Uncertain),
    );
    assert!(matches!(
        budget.may_run(next.turn.id, 13),
        Err(BudgetError::Cause)
    ));
    assert_eq!(
        store.wake_state(first.execution).unwrap(),
        Some(WakeState::Finished)
    );
    assert_eq!(
        store.wake_state(second.execution).unwrap(),
        Some(WakeState::Uncertain)
    );
}

#[test]
fn wake_admission_rechecks_fresh_time_grant_and_root_pause() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("approved-wakes");
    let mut store = open_wake_store(&path);
    let expired = accept_and_claim_wake(&mut store, 1, 10);
    let source = accept_and_claim_wake(&mut store, 2, 20);
    let next = accept_and_claim_wake(&mut store, 3, 21);
    let denied = accept_and_claim_wake(&mut store, 4, 22);
    let mut budget = store
        .conversation_budget(limits(), human().verifying_key())
        .unwrap();

    let approval = approve(&expired, 1);
    let signature = human().sign(&approval.signing_bytes(LOCAL)).to_bytes();
    assert!(matches!(
        budget.start_approved_wake(approval, &signature, || Ok(30), authorized),
        Err(WakeTurnError::Unavailable),
    ));
    assert!(matches!(
        budget.start_approved_wake(approval, &signature, || Ok(29), authorized),
        Err(WakeTurnError::Delivery(howl::delivery::Error::WakeClock)),
    ));
    let approval = approve(&source, 2);
    let signature = human().sign(&approval.signing_bytes(LOCAL)).to_bytes();
    let running = budget
        .start_approved_wake(approval, &signature, || Ok(30), authorized)
        .unwrap();

    let pause = command(
        3,
        HumanAction::Pause {
            root: running.turn.root,
        },
        0,
    );
    let signature = human().sign(&pause.signing_bytes(LOCAL)).to_bytes();
    budget.apply_human(pause, &signature, 30).unwrap();
    assert_eq!(
        budget
            .finish_approved_wake(source.execution, WakeOutcome::Finished)
            .unwrap(),
        Some(WakeOutcome::Uncertain),
    );
    let continuation = WakeApproval {
        cause: Some(running.turn.id),
        ..approve(&next, 4)
    };
    let signature = human().sign(&continuation.signing_bytes(LOCAL)).to_bytes();
    assert!(matches!(
        budget.start_approved_wake(continuation, &signature, || Ok(30), authorized),
        Err(WakeTurnError::Budget(BudgetError::Limit(
            BudgetLimit::Paused
        ))),
    ));

    let approval = approve(&denied, 5);
    let signature = human().sign(&approval.signing_bytes(LOCAL)).to_bytes();
    assert!(matches!(
        budget.start_approved_wake(approval, &signature, || Ok(31), |_, _| false),
        Err(WakeTurnError::Unavailable),
    ));
    assert_eq!(
        store.wake_state(expired.execution).unwrap(),
        Some(WakeState::Cancelled)
    );
    assert_eq!(
        store.wake_state(next.execution).unwrap(),
        Some(WakeState::Claimed)
    );
    assert_eq!(
        store.wake_state(denied.execution).unwrap(),
        Some(WakeState::Cancelled)
    );
}
