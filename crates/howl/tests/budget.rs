use ed25519_dalek::{Signer, SigningKey};
use howl::delivery::{
    BudgetError, BudgetLimit, BudgetLimits, ConversationBudget, DeliveryStore, Device, HumanAction,
    HumanCommand, Id, Turn,
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
