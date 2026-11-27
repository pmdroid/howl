use std::{fs, path::Path, process::Command, thread};

use ed25519_dalek::SigningKey;
use howl::delivery::{
    ACK_TAG, Acknowledgment, DeliveryStore, Device, Error, Frame, Id, Payload, Stream,
};

const STORE_KEY: [u8; 32] = [91; 32];
const ALICE: Device = Device {
    account: [1; 32],
    device: [2; 32],
};
const BOB: Device = Device {
    account: [3; 32],
    device: [4; 32],
};
const CAROL: Device = Device {
    account: [5; 32],
    device: [6; 32],
};
const STREAM: Stream = Stream {
    channel: [7; 32],
    sender: ALICE,
    signing_key: [8; 32],
};
const SENT_BYTES: &[u8] = b"test fixture signed frame bytes";
const BODY: &str = "oramiddle confidential conversation";

fn bob_signer() -> SigningKey {
    SigningKey::from_bytes(&[92; 32])
}

fn frame(sequence: u64, message: u8) -> Frame {
    Frame {
        stream: STREAM,
        message: [message; 32],
        sequence,
        epoch: 1,
        created_at: 10,
        expires_at: 0,
    }
}

fn open(path: &Path, device: Device) -> DeliveryStore {
    let mut store = DeliveryStore::open(path, &STORE_KEY, device).unwrap();
    store.set_epoch(STREAM.channel, 1).unwrap();
    store
}

#[test]
#[ignore = "subprocess fixture for a receiver that exits after committing"]
fn receiver_exits_before_sending_ack() {
    let Some(path) = std::env::var_os("HOWL_DELIVERY_CRASH_DB") else {
        return;
    };
    let mut receiver = open(Path::new(&path), BOB);
    let receipt = receiver
        .accept_authenticated(
            frame(1, 22),
            SENT_BYTES,
            Payload::Chat(BODY),
            10,
            &bob_signer(),
        )
        .unwrap();
    assert!(receipt.inserted);
    std::process::exit(78);
}

#[test]
fn retries_after_receiver_exit_and_authenticates_per_recipient_receipts() {
    let root = tempfile::tempdir().unwrap();
    let sender_path = root.path().join("sender");
    let receiver_path = root.path().join("receiver");
    let mut sender = open(&sender_path, ALICE);
    let message = frame(sender.reserve_sequence(STREAM).unwrap(), 22);
    assert!(matches!(
        sender.enqueue(frame(2, 23), b"unreserved", &[BOB], 10),
        Err(Error::Unreserved)
    ));
    sender
        .enqueue(message, SENT_BYTES, &[BOB, CAROL], 10)
        .unwrap();
    sender
        .enqueue(message, SENT_BYTES, &[CAROL, BOB], 10)
        .unwrap();
    assert!(matches!(
        sender.enqueue(message, SENT_BYTES, &[BOB], 10),
        Err(Error::Conflict)
    ));
    let initial = sender.claim_due(Some(STREAM.channel), 10, 10).unwrap();
    assert_eq!(initial.len(), 2);
    assert!(initial.iter().all(|attempt| attempt.frame == SENT_BYTES));
    assert!(sender.claim_due(None, 10, 10).unwrap().is_empty());
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "receiver_exits_before_sending_ack"])
        .env("HOWL_DELIVERY_CRASH_DB", &receiver_path)
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(78),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );

    drop(sender);
    let mut sender = open(&sender_path, ALICE);
    assert_eq!(sender.claim_due(None, 11, 10).unwrap(), initial);
    let mut receiver = open(&receiver_path, BOB);
    let retry = receiver
        .accept_authenticated(message, SENT_BYTES, Payload::Chat(BODY), 11, &bob_signer())
        .unwrap();
    assert!(!retry.inserted);
    assert_eq!(receiver.chat_history(STREAM.channel, 10).unwrap().len(), 1);
    assert_eq!(retry.acknowledgment.as_bytes()[0], ACK_TAG);
    let received = Acknowledgment::from_bytes(*retry.acknowledgment.as_bytes());
    assert_eq!(received.recipient(), BOB);
    let verifying = bob_signer().verifying_key();
    let other_key = SigningKey::from_bytes(&[94; 32]).verifying_key();
    assert!(matches!(
        sender.apply_ack(&received, CAROL, &verifying),
        Err(Error::Ack)
    ));
    assert!(matches!(
        sender.apply_ack(&received, BOB, &other_key),
        Err(Error::Ack)
    ));
    let mut altered = *received.as_bytes();
    altered[225] ^= 1;
    assert!(matches!(
        sender.apply_ack(&Acknowledgment::from_bytes(altered), BOB, &verifying),
        Err(Error::Ack)
    ));
    let mut other_receiver = open(&root.path().join("other"), BOB);
    let different = other_receiver
        .accept_authenticated(
            message,
            b"different signed frame",
            Payload::Chat(BODY),
            11,
            &bob_signer(),
        )
        .unwrap();
    assert!(matches!(
        sender.apply_ack(&different.acknowledgment, BOB, &verifying),
        Err(Error::Ack)
    ));

    sender.apply_ack(&received, BOB, &verifying).unwrap();
    sender.apply_ack(&received, BOB, &verifying).unwrap();
    let pending = sender.claim_due(None, 100, 10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].recipient, CAROL);
    let status = sender.delivery_status(STREAM, message.message).unwrap();
    assert!(status[0].acknowledged);
    assert_eq!(status[0].attempts, 2);
    assert!(!status[1].acknowledged);
    sender.set_epoch(STREAM.channel, 2).unwrap();
    assert!(matches!(
        sender.set_epoch(STREAM.channel, 1),
        Err(Error::Epoch)
    ));
    assert!(sender.claim_due(None, 500, 10).unwrap().is_empty());
}

#[test]
fn detects_message_and_sequence_collisions_and_fills_gaps() {
    let root = tempfile::tempdir().unwrap();
    let mut receiver = open(&root.path().join("receiver"), BOB);
    let signer = bob_signer();
    let fourth = frame(4, 24);
    receiver
        .accept_authenticated(fourth, b"fourth", Payload::Chat(BODY), 10, &signer)
        .unwrap();
    let gaps = receiver.gaps(STREAM, 1, 10).unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0], 1..=3);
    let first = frame(1, 21);
    let original = receiver
        .accept_authenticated(first, b"first", Payload::Chat(BODY), 11, &signer)
        .unwrap();
    let gaps = receiver.gaps(STREAM, 1, 10).unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0], 2..=3);
    assert!(matches!(
        receiver.accept_authenticated(
            frame(1, 25),
            b"sequence collision",
            Payload::Chat(BODY),
            12,
            &signer
        ),
        Err(Error::Conflict)
    ));
    let mut reuse = frame(6, 21);
    reuse.stream.signing_key = [13; 32];
    assert!(matches!(
        receiver.accept_authenticated(
            reuse,
            b"message collision",
            Payload::Chat(BODY),
            12,
            &signer
        ),
        Err(Error::Conflict)
    ));
    receiver.prune(STREAM.channel, 20, 20).unwrap();
    assert!(
        receiver
            .chat_history(STREAM.channel, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        receiver
            .search_chat(STREAM.channel, "oramiddle", 10)
            .unwrap()
            .is_empty()
    );
    let retry = receiver
        .accept_authenticated(first, b"first", Payload::Chat(BODY), 20, &signer)
        .unwrap();
    assert!(!retry.inserted);
    assert_eq!(retry.acknowledgment, original.acknowledgment);
    receiver.set_epoch(STREAM.channel, 2).unwrap();
    assert!(matches!(
        receiver.accept_authenticated(first, b"first", Payload::Chat(BODY), 20, &signer),
        Err(Error::Epoch)
    ));
}

#[test]
fn replays_committed_channel_events_after_a_cursor_across_restart_and_pruning() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("receiver");
    let mut receiver = open(&path, BOB);
    let signer = bob_signer();
    let first = frame(1, 21);
    let mut other = frame(2, 22);
    other.stream.channel = [9; 32];
    receiver.set_epoch(other.stream.channel, 1).unwrap();
    for (message, now) in [(first, 20), (other, 30), (frame(3, 23), 10)] {
        receiver
            .accept_authenticated(message, SENT_BYTES, Payload::Chat(BODY), now, &signer)
            .unwrap();
    }
    let page = receiver.channel_events(STREAM.channel, 0, 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].message.message, first.message);
    let first_cursor = page[0].cursor;
    drop(receiver);

    let mut receiver = open(&path, BOB);
    let page = receiver
        .channel_events(STREAM.channel, first_cursor, 10)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].message.message, [23; 32]);
    let second_cursor = page[0].cursor;
    assert!(
        !receiver
            .accept_authenticated(first, SENT_BYTES, Payload::Chat(BODY), 40, &signer)
            .unwrap()
            .inserted
    );
    assert!(
        receiver
            .channel_events(STREAM.channel, second_cursor, 10)
            .unwrap()
            .is_empty()
    );
    receiver.prune(STREAM.channel, 50, 50).unwrap();
    let next = frame(4, 24);
    receiver
        .accept_authenticated(next, SENT_BYTES, Payload::Chat(BODY), 50, &signer)
        .unwrap();
    let page = receiver
        .channel_events(STREAM.channel, second_cursor, 10)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].message.message, next.message);
    assert!(page[0].cursor > second_cursor);
}

#[test]
fn checks_wake_expiry_and_preserves_clock_watermark_across_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("receiver");
    let mut receiver = open(&path, BOB);
    let mut wake = frame(1, 21);
    wake.created_at = 120;
    wake.expires_at = 200;
    let payload = Payload::Wake {
        target: [27; 32],
        text: "",
    };
    let signer = bob_signer();
    assert!(matches!(
        receiver.accept_authenticated(wake, b"wake", payload, 120, &signer),
        Err(Error::WakeClock)
    ));
    receiver.establish_wake_time(110).unwrap();
    let first = receiver
        .accept_authenticated(wake, b"wake", payload, 120, &signer)
        .unwrap();
    let retry = receiver
        .accept_authenticated(wake, b"wake", payload, 130, &signer)
        .unwrap();
    assert_eq!(first.acknowledgment, retry.acknowledgment);
    assert!(!retry.inserted);
    assert!(matches!(
        receiver.accept_authenticated(wake, b"wake", payload, 200, &signer),
        Err(Error::Expired)
    ));
    drop(receiver);
    let mut receiver = open(&path, BOB);
    assert!(matches!(
        receiver.accept_authenticated(wake, b"wake", payload, 150, &signer),
        Err(Error::WakeClock)
    ));
}

#[test]
fn allocation_is_serialized_across_connections() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("sender");
    let mut first = open(&path, ALICE);
    let second = open(&path, ALICE);
    let mut sequences = thread::scope(|threads| {
        let reserve = |mut store: DeliveryStore| {
            (0..20)
                .map(|_| store.reserve_sequence(STREAM).unwrap())
                .collect::<Vec<_>>()
        };
        let worker = threads.spawn(move || reserve(second));
        let mut main = (0..20)
            .map(|_| first.reserve_sequence(STREAM).unwrap())
            .collect::<Vec<_>>();
        main.extend(worker.join().unwrap());
        main
    });
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=40).collect::<Vec<_>>());
    let mut second = open(&path, ALICE);
    assert_eq!(second.reserve_sequence(STREAM).unwrap(), 41);
}

#[test]
fn database_wal_fts_and_backup_keep_plaintext_encrypted() {
    let root = tempfile::tempdir().unwrap();
    let database = root.path().join("receiver");
    let backup = root.path().join("backup");
    let backup_key = [111; 32];
    let mut receiver = open(&database, BOB);
    receiver
        .accept_authenticated(
            frame(1, 21),
            SENT_BYTES,
            Payload::Chat(BODY),
            10,
            &bob_signer(),
        )
        .unwrap();
    assert_eq!(
        receiver
            .search_chat(STREAM.channel, "oramiddle", 10)
            .unwrap(),
        [BODY]
    );
    let wal = fs::read(root.path().join("receiver-wal")).unwrap();
    assert!(wal.len() > 32);
    receiver.backup(&backup, &backup_key).unwrap();
    assert!(receiver.backup(&backup, &STORE_KEY).is_err());
    for bytes in [
        fs::read(&database).unwrap(),
        wal,
        fs::read(&backup).unwrap(),
    ] {
        assert!(!bytes.starts_with(b"SQLite format 3\0"));
        for marker in ["oramiddle", BODY, "CREATE VIRTUAL TABLE"] {
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            );
        }
    }
    assert!(DeliveryStore::open(&database, &backup_key, BOB).is_err());
    assert!(DeliveryStore::open(&backup, &STORE_KEY, BOB).is_err());
    let restored = DeliveryStore::open(&backup, &backup_key, BOB).unwrap();
    assert_eq!(
        restored
            .search_chat(STREAM.channel, "oramiddle", 10)
            .unwrap(),
        [BODY]
    );
    assert_eq!(
        restored.chat_history(STREAM.channel, 10).unwrap()[0].body,
        BODY
    );
    assert!(matches!(
        DeliveryStore::open(&database, &STORE_KEY, ALICE),
        Err(Error::Device)
    ));
}

#[test]
fn a_claimed_wake_is_not_repeated_after_restart_or_replay() {
    use howl::delivery::WakeState;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wakes");
    let target = [43; 32];
    let wake = Payload::Wake {
        target,
        text: "review the plan",
    };
    let signer = bob_signer();
    let mut receiver = open(&path, BOB);
    receiver.establish_wake_time(10).unwrap();
    receiver
        .accept_authenticated(
            frame(1, 20),
            b"ordinary chat",
            Payload::Chat("review the plan"),
            10,
            &signer,
        )
        .unwrap();
    let preapproval = Frame {
        expires_at: 30,
        ..frame(2, 21)
    };
    assert!(
        receiver
            .accept_authenticated(preapproval, b"before approval", wake, 10, &signer)
            .unwrap()
            .inserted
    );
    receiver
        .enable_wake_target(STREAM.channel, target, 1)
        .unwrap();
    assert!(
        receiver
            .claim_wake(STREAM.channel, target, 11)
            .unwrap()
            .is_none()
    );

    let allowed = Frame {
        expires_at: 30,
        ..frame(3, 22)
    };
    let receipt = receiver
        .accept_authenticated(allowed, b"allowed wake", wake, 11, &signer)
        .unwrap();
    let claimed = receiver
        .claim_wake(STREAM.channel, target, 12)
        .unwrap()
        .unwrap();
    assert_eq!(claimed.message, allowed.message);
    assert_eq!(claimed.target, target);
    assert_eq!(claimed.stream, STREAM);
    assert_eq!(claimed.epoch, allowed.epoch);
    assert_eq!(claimed.grant_generation, 1);
    assert!(claimed.cursor > 0);
    assert_eq!(
        receiver.wake_state(claimed.execution).unwrap(),
        Some(WakeState::Claimed)
    );
    let job = receiver
        .start_wake(claimed.execution, || Ok(12), |_| true)
        .unwrap()
        .unwrap();
    assert_eq!(job.claim, claimed);
    assert_eq!(job.text, "review the plan");
    assert_eq!(
        receiver.wake_state(claimed.execution).unwrap(),
        Some(WakeState::Running)
    );
    let duplicate = receiver
        .accept_authenticated(allowed, b"allowed wake", wake, 13, &signer)
        .unwrap();
    assert!(!duplicate.inserted);
    assert_eq!(duplicate.acknowledgment, receipt.acknowledgment);
    assert!(
        receiver
            .claim_wake(STREAM.channel, target, 13)
            .unwrap()
            .is_none()
    );
    drop(receiver);

    let mut reopened = open(&path, BOB);
    assert_eq!(reopened.recover_wakes().unwrap(), 1);
    assert_eq!(
        reopened.wake_state(claimed.execution).unwrap(),
        Some(WakeState::Uncertain)
    );
    reopened
        .enable_wake_target(STREAM.channel, target, 1)
        .unwrap();
    let repeated = reopened
        .accept_authenticated(allowed, b"allowed wake", wake, 14, &signer)
        .unwrap();
    assert!(!repeated.inserted);
    assert!(
        reopened
            .claim_wake(STREAM.channel, target, 14)
            .unwrap()
            .is_none()
    );
    assert!(!reopened.finish_wake(claimed.execution).unwrap());
}

#[test]
fn expiry_revocation_and_epoch_change_are_checked_at_wake_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wakes");
    let target = [44; 32];
    let wake = Payload::Wake {
        target,
        text: "look at the plan",
    };
    let signer = bob_signer();
    let mut receiver = open(&path, BOB);
    receiver.establish_wake_time(10).unwrap();
    receiver
        .enable_wake_target(STREAM.channel, target, 1)
        .unwrap();
    let expiring = Frame {
        expires_at: 12,
        ..frame(1, 20)
    };
    receiver
        .accept_authenticated(expiring, b"expiring", wake, 10, &signer)
        .unwrap();
    assert!(
        receiver
            .claim_wake(STREAM.channel, target, 12)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        receiver.claim_wake(STREAM.channel, target, 11),
        Err(Error::WakeClock)
    ));

    let revoked = Frame {
        expires_at: 30,
        ..frame(2, 21)
    };
    receiver
        .accept_authenticated(revoked, b"revoked", wake, 12, &signer)
        .unwrap();
    receiver
        .disable_wake_target(STREAM.channel, target, 1)
        .unwrap();
    assert!(matches!(
        receiver.enable_wake_target(STREAM.channel, target, 1),
        Err(Error::WakeGrant)
    ));
    receiver
        .enable_wake_target(STREAM.channel, target, 2)
        .unwrap();
    assert!(
        receiver
            .claim_wake(STREAM.channel, target, 13)
            .unwrap()
            .is_none()
    );

    let old_epoch = Frame {
        expires_at: 30,
        ..frame(3, 22)
    };
    receiver
        .accept_authenticated(old_epoch, b"retired epoch", wake, 13, &signer)
        .unwrap();
    receiver.set_epoch(STREAM.channel, 2).unwrap();
    assert!(
        receiver
            .claim_wake(STREAM.channel, target, 14)
            .unwrap()
            .is_none()
    );

    let current = Frame {
        expires_at: 30,
        epoch: 2,
        ..frame(4, 23)
    };
    receiver
        .accept_authenticated(current, b"active epoch", wake, 14, &signer)
        .unwrap();
    let job = receiver
        .claim_wake(STREAM.channel, target, 14)
        .unwrap()
        .unwrap();
    assert_eq!(job.message, current.message);
    assert_eq!(job.grant_generation, 2);
    assert!(!receiver.finish_wake(job.execution).unwrap());
    assert!(
        receiver
            .start_wake(job.execution, || Ok(14), |_| true)
            .unwrap()
            .is_some()
    );
    assert!(receiver.finish_wake(job.execution).unwrap());
    assert!(!receiver.finish_wake(job.execution).unwrap());
}

#[test]
fn claimed_wakes_require_fresh_time_and_current_sender_authorization() {
    use std::cell::Cell;

    use howl::delivery::WakeState;

    let root = tempfile::tempdir().unwrap();
    let target = [44; 32];
    let mut store = open(&root.path().join("wakes"), BOB);
    store.establish_wake_time(10).unwrap();
    store.enable_wake_target(STREAM.channel, target, 1).unwrap();
    enqueue_wake(&mut store, 1, 20, target, 10, 12);
    let claim = store
        .claim_wake(STREAM.channel, target, 11)
        .unwrap()
        .unwrap();
    let clock = Cell::new(11);
    let expired = store
        .start_wake(
            claim.execution,
            || Ok(clock.get()),
            |_| {
                clock.set(12);
                true
            },
        )
        .unwrap();
    assert!(expired.is_none());
    assert_eq!(
        store.wake_state(claim.execution).unwrap(),
        Some(WakeState::Cancelled)
    );
    assert!(matches!(
        store.claim_wake(STREAM.channel, target, 11),
        Err(Error::WakeClock)
    ));

    enqueue_wake(&mut store, 2, 21, target, 12, 30);
    let claim = store
        .claim_wake(STREAM.channel, target, 12)
        .unwrap()
        .unwrap();
    let revoked_sender = store
        .start_wake(
            claim.execution,
            || Ok(13),
            |candidate| {
                assert_eq!(candidate.stream, STREAM);
                assert_eq!(candidate.epoch, 1);
                assert_eq!(candidate.grant_generation, 1);
                false
            },
        )
        .unwrap();
    assert!(revoked_sender.is_none());
    assert_eq!(
        store.wake_state(claim.execution).unwrap(),
        Some(WakeState::Cancelled)
    );

    enqueue_wake(&mut store, 3, 22, target, 13, 30);
    let claim = store
        .claim_wake(STREAM.channel, target, 13)
        .unwrap()
        .unwrap();
    store.set_epoch(STREAM.channel, 2).unwrap();
    assert!(
        store
            .start_wake(
                claim.execution,
                || Ok(14),
                |_| panic!("retired epoch reached authorization")
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.wake_state(claim.execution).unwrap(),
        Some(WakeState::Cancelled)
    );
}

#[test]
fn restart_and_grant_rotation_do_not_cross_authorization_boundaries() {
    use howl::delivery::WakeState;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wakes");
    let target = [44; 32];
    let mut store = open(&path, BOB);
    store.establish_wake_time(10).unwrap();
    store.enable_wake_target(STREAM.channel, target, 1).unwrap();
    enqueue_wake(&mut store, 1, 20, target, 10, 30);
    enqueue_wake(&mut store, 2, 21, target, 10, 30);
    enqueue_wake(&mut store, 3, 22, target, 10, 30);
    let abandoned = store
        .claim_wake(STREAM.channel, target, 10)
        .unwrap()
        .unwrap();
    drop(store);

    let mut store = open(&path, BOB);
    assert_eq!(store.recover_wakes().unwrap(), 0);
    assert!(
        store
            .claim_wake(STREAM.channel, target, 11)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.wake_state(abandoned.execution).unwrap(),
        Some(WakeState::Cancelled)
    );
    store.enable_wake_target(STREAM.channel, target, 1).unwrap();
    let previous_grant = store
        .claim_wake(STREAM.channel, target, 11)
        .unwrap()
        .unwrap();
    assert_eq!(previous_grant.message, [21; 32]);
    store.enable_wake_target(STREAM.channel, target, 2).unwrap();
    assert!(matches!(
        store.enable_wake_target(STREAM.channel, target, 1),
        Err(Error::WakeGrant)
    ));
    assert!(matches!(
        store.disable_wake_target(STREAM.channel, target, 1),
        Err(Error::WakeGrant)
    ));
    assert!(
        store
            .start_wake(previous_grant.execution, || Ok(11), |_| true)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.wake_state(previous_grant.execution).unwrap(),
        Some(WakeState::Cancelled)
    );
    assert!(
        store
            .claim_wake(STREAM.channel, target, 11)
            .unwrap()
            .is_none()
    );

    enqueue_wake(&mut store, 4, 23, target, 11, 30);
    let claim = store
        .claim_wake(STREAM.channel, target, 11)
        .unwrap()
        .unwrap();
    assert_eq!(claim.grant_generation, 2);
    store
        .disable_wake_target(STREAM.channel, target, 2)
        .unwrap();
    assert!(
        store
            .start_wake(claim.execution, || Ok(12), |_| true)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.wake_state(claim.execution).unwrap(),
        Some(WakeState::Cancelled)
    );
}

#[test]
fn cancellation_and_uncertain_execution_are_terminal_per_wake() {
    use howl::delivery::WakeState;

    let root = tempfile::tempdir().unwrap();
    let target = [44; 32];
    let mut store = open(&root.path().join("wakes"), BOB);
    store.establish_wake_time(10).unwrap();
    store.enable_wake_target(STREAM.channel, target, 1).unwrap();
    for sequence in 1..=3 {
        enqueue_wake(&mut store, sequence, 19 + sequence as u8, target, 10, 30);
    }

    let cancelled = store
        .claim_wake(STREAM.channel, target, 10)
        .unwrap()
        .unwrap();
    assert!(store.cancel_wake(cancelled.execution).unwrap());
    assert!(!store.cancel_wake(cancelled.execution).unwrap());
    assert!(
        store
            .start_wake(cancelled.execution, || Ok(10), |_| true)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.wake_state(cancelled.execution).unwrap(),
        Some(WakeState::Cancelled)
    );

    let disconnected = store
        .claim_wake(STREAM.channel, target, 10)
        .unwrap()
        .unwrap();
    assert!(!store.mark_wake_uncertain(disconnected.execution).unwrap());
    assert!(
        store
            .start_wake(disconnected.execution, || Ok(10), |_| true)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .start_wake(disconnected.execution, || Ok(10), |_| true)
            .unwrap()
            .is_none()
    );
    assert!(store.mark_wake_uncertain(disconnected.execution).unwrap());
    assert!(!store.finish_wake(disconnected.execution).unwrap());
    assert_eq!(
        store.wake_state(disconnected.execution).unwrap(),
        Some(WakeState::Uncertain)
    );

    let interrupted = store
        .claim_wake(STREAM.channel, target, 10)
        .unwrap()
        .unwrap();
    assert!(
        store
            .start_wake(interrupted.execution, || Ok(10), |_| true)
            .unwrap()
            .is_some()
    );
    assert!(store.cancel_wake(interrupted.execution).unwrap());
    assert_eq!(
        store.wake_state(interrupted.execution).unwrap(),
        Some(WakeState::Uncertain)
    );
    assert!(
        store
            .claim_wake(STREAM.channel, target, 10)
            .unwrap()
            .is_none()
    );
}

fn enqueue_wake(
    store: &mut DeliveryStore,
    sequence: u64,
    message: u8,
    target: Id,
    now: u64,
    expires_at: u64,
) {
    let frame = Frame {
        expires_at,
        ..frame(sequence, message)
    };
    store
        .accept_authenticated(
            frame,
            &[message],
            Payload::Wake {
                target,
                text: "review the plan",
            },
            now,
            &bob_signer(),
        )
        .unwrap();
}
