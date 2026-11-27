use std::{env, time::Duration};

use deadpool_postgres::{Manager, Pool};
use howl_control_plane::mailbox::{
    Deposit, EnrolledDevice, EnrolledSubmission, Header, Limits, Mailbox, MailboxError,
    MailingAddress, Stream,
};
use sha2::{Digest, Sha256};
use tokio::time;
use tokio_postgres::{Config, NoTls};

const RETENTION: i64 = 7 * 24 * 60 * 60;
const LIMITS: Limits = Limits {
    messages: 2,
    bytes: 12,
    retained_ids: 4,
};

fn pool(config: Config) -> Pool {
    Pool::builder(Manager::new(config, NoTls))
        .max_size(8)
        .build()
        .unwrap()
}

fn enrolled(address: MailingAddress) -> EnrolledDevice {
    EnrolledDevice::from_verified_enrollment(address).unwrap()
}

fn address(account: u8, device: u8) -> MailingAddress {
    MailingAddress {
        account: [account; 32],
        device: [device; 32],
    }
}

fn submission<'a>(
    sender: &EnrolledDevice,
    recipient: &'a EnrolledDevice,
    stream: Stream,
    sequence: u64,
    sent_at: i64,
    ciphertext: &'a [u8],
) -> EnrolledSubmission<'a> {
    EnrolledSubmission::from_verified_request(
        sender,
        recipient,
        Header {
            stream,
            sequence,
            message: Sha256::digest(sequence.to_be_bytes()).into(),
            sent_at,
        },
        ciphertext,
    )
    .unwrap()
}

async fn database_time(pool: &Pool) -> i64 {
    pool.get()
        .await
        .unwrap()
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database named howl_mailbox_test"]
async fn postgres_mailbox_retains_scopes_and_bounds_opaque_envelopes() {
    let url =
        env::var("HOWL_MAILBOX_TEST_DATABASE_URL").expect("set the disposable PostgreSQL URL");
    let mut config: Config = url.parse().unwrap();
    assert_eq!(config.get_dbname(), Some("howl_mailbox_test"));
    let owner = pool(config.clone());
    owner
        .get()
        .await
        .unwrap()
        .batch_execute("CREATE ROLE howl_control_runtime LOGIN")
        .await
        .unwrap();
    Mailbox::migrate(&owner).await.unwrap();
    Mailbox::migrate(&owner).await.unwrap();

    config.user("howl_control_runtime");
    let runtime = pool(config);
    let mailbox = Mailbox::new(runtime.clone(), LIMITS).unwrap();
    let sender = enrolled(address(1, 2));
    let recipient = enrolled(address(3, 4));
    let other = enrolled(address(3, 5));
    let stream = Stream {
        channel: [6; 32],
        epoch: u64::MAX,
        sender: address(1, 2),
    };
    let now = database_time(&runtime).await;

    let wrong_actor = EnrolledSubmission::from_verified_request(
        &other,
        &recipient,
        Header {
            stream,
            sequence: 2,
            message: [7; 32],
            sent_at: now,
        },
        &[0xae; 5],
    );
    assert!(matches!(wrong_actor, Err(MailboxError::Unauthorized)));
    let frame = [0xa2; 5];
    assert_eq!(
        mailbox
            .deposit(submission(&sender, &recipient, stream, 2, now, &frame))
            .await,
        Ok(Deposit::Stored)
    );
    assert_eq!(
        mailbox
            .deposit(submission(&sender, &recipient, stream, 2, now, &frame))
            .await,
        Ok(Deposit::Duplicate)
    );
    assert_eq!(
        mailbox
            .deposit(submission(&sender, &recipient, stream, 2, now, &[0xac; 5]))
            .await,
        Err(MailboxError::Conflict)
    );
    assert_eq!(
        mailbox
            .deposit(submission(&sender, &recipient, stream, 5, now, &[0xa5; 5]))
            .await,
        Ok(Deposit::Stored)
    );
    assert_eq!(
        mailbox
            .deposit(submission(&sender, &recipient, stream, 6, now, &[0xa6]))
            .await,
        Err(MailboxError::Quota)
    );

    let first = mailbox.fetch(&recipient, 0, 1).await.unwrap();
    assert_eq!(first.envelopes.len(), 1);
    let stored = &first.envelopes[0];
    assert_eq!(stored.ciphertext, frame);
    assert_eq!(stored.digest, <[u8; 32]>::from(Sha256::digest(frame)));
    assert_eq!(stored.header.stream, stream);
    assert_eq!(stored.header.sequence, 2);
    assert_eq!(stored.cursor, 1);
    assert!(
        mailbox
            .fetch(&other, 0, 2)
            .await
            .unwrap()
            .envelopes
            .is_empty()
    );
    let restarted = Mailbox::new(runtime.clone(), LIMITS).unwrap();
    let retried = restarted.fetch(&recipient, 0, 2).await.unwrap();
    assert_eq!(retried.envelopes.len(), 2);
    assert_eq!(retried.envelopes[0].cursor, stored.cursor);
    let second = mailbox
        .fetch(&recipient, first.next.unwrap(), 1)
        .await
        .unwrap();
    assert_eq!(second.envelopes[0].header.sequence, 5);
    assert!(second.next.is_none());

    let range = mailbox
        .fetch_range(&recipient, stream, 1..=6, 1)
        .await
        .unwrap();
    assert_eq!(range.missing.len(), 1);
    assert_eq!(range.missing[0], 1..=1);
    assert_eq!(range.next, Some(3));
    let range = mailbox
        .fetch_range(&recipient, stream, range.next.unwrap()..=6, 1)
        .await
        .unwrap();
    assert_eq!(range.missing, [3..=4, 6..=6]);
    assert!(range.next.is_none());

    assert!(
        !mailbox
            .acknowledge(&other, stored.header.message, stored.digest)
            .await
            .unwrap()
    );
    assert!(
        !mailbox
            .acknowledge(&recipient, stored.header.message, [0xff; 32])
            .await
            .unwrap()
    );
    for _ in 0..2 {
        assert!(
            mailbox
                .acknowledge(&recipient, stored.header.message, stored.digest)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        mailbox
            .deposit(submission(&sender, &recipient, stream, 2, now, &frame))
            .await,
        Ok(Deposit::Duplicate)
    );
    let remaining = mailbox.fetch(&recipient, 0, 2).await.unwrap();
    assert_eq!(remaining.envelopes.len(), 1);
    assert_eq!(remaining.envelopes[0].header.sequence, 5);
    assert_eq!(
        mailbox
            .deposit(submission(&sender, &recipient, stream, 6, now, &[0xa6; 7]))
            .await,
        Ok(Deposit::Stored)
    );

    let (left, right) = tokio::join!(
        mailbox.deposit(submission(&sender, &other, stream, 7, now, &[0xa7; 7])),
        mailbox.deposit(submission(&sender, &other, stream, 8, now, &[0xa8; 7])),
    );
    assert!(matches!(
        (left, right),
        (Ok(Deposit::Stored), Err(MailboxError::Quota))
            | (Err(MailboxError::Quota), Ok(Deposit::Stored))
    ));

    let other_page = mailbox.fetch(&other, 0, 1).await.unwrap();
    assert_eq!(other_page.envelopes[0].cursor, 1);

    let small_mailbox = Mailbox::new(
        runtime.clone(),
        Limits {
            messages: 1,
            bytes: 12,
            retained_ids: 1,
        },
    )
    .unwrap();
    let small_recipient = enrolled(address(8, 10));
    assert_eq!(
        small_mailbox
            .deposit(submission(
                &sender,
                &small_recipient,
                stream,
                10,
                now,
                &[0xaa]
            ))
            .await,
        Ok(Deposit::Stored)
    );
    let small_page = small_mailbox.fetch(&small_recipient, 0, 1).await.unwrap();
    let delivered = &small_page.envelopes[0];
    assert!(
        small_mailbox
            .acknowledge(&small_recipient, delivered.header.message, delivered.digest)
            .await
            .unwrap()
    );
    assert_eq!(
        small_mailbox
            .deposit(submission(
                &sender,
                &small_recipient,
                stream,
                11,
                now,
                &[0xab]
            ))
            .await,
        Err(MailboxError::Quota)
    );

    let expiry = enrolled(address(8, 9));
    let nearing_expiry = database_time(&runtime).await - RETENTION + 3;
    let expired = submission(&sender, &expiry, stream, 9, nearing_expiry, &[0xa9]);
    assert_eq!(mailbox.deposit(expired).await, Ok(Deposit::Stored));
    let expired_page = mailbox.fetch(&expiry, 0, 1).await.unwrap();
    let expired_cursor = expired_page.envelopes[0].cursor;
    time::timeout(Duration::from_secs(8), async {
        while database_time(&runtime).await < nearing_expiry + RETENTION {
            time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        mailbox
            .fetch(&expiry, 0, 1)
            .await
            .unwrap()
            .envelopes
            .is_empty()
    );
    assert_eq!(mailbox.prune_expired(8).await.unwrap(), 1);
    assert_eq!(
        mailbox
            .deposit(submission(
                &sender,
                &expiry,
                stream,
                9,
                nearing_expiry,
                &[0xa9]
            ))
            .await,
        Err(MailboxError::Expired)
    );
    assert_eq!(
        mailbox
            .deposit(submission(
                &sender,
                &expiry,
                stream,
                12,
                database_time(&runtime).await,
                &[0xac]
            ))
            .await,
        Ok(Deposit::Stored)
    );
    let fresh_page = mailbox.fetch(&expiry, expired_cursor, 1).await.unwrap();
    assert_eq!(fresh_page.envelopes[0].cursor, expired_cursor + 1);
}
