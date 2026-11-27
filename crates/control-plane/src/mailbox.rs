use std::ops::RangeInclusive;

use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::Id;

pub(crate) const FRAME_LIMIT: usize = 77_112;
const RETENTION: i64 = 7 * 24 * 60 * 60;
const FUTURE_SKEW: i64 = 30;
const PAGE_LIMIT: usize = 64;
const PRUNE_LIMIT: i64 = 1024;

type Result<T> = std::result::Result<T, MailboxError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxError {
    Invalid,
    Unauthorized,
    Expired,
    Conflict,
    Quota,
    Database,
}

impl From<tokio_postgres::Error> for MailboxError {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::Database
    }
}

impl From<deadpool_postgres::PoolError> for MailboxError {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::Database
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailingAddress {
    pub account: Id,
    pub device: Id,
}

pub struct EnrolledDevice(MailingAddress);

impl EnrolledDevice {
    pub fn from_verified_enrollment(address: MailingAddress) -> Result<Self> {
        if address.account == [0; 32] || address.device == [0; 32] {
            return Err(MailboxError::Invalid);
        }
        Ok(Self(address))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stream {
    pub channel: Id,
    pub epoch: u64,
    pub sender: MailingAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub stream: Stream,
    pub sequence: u64,
    pub message: Id,
    pub sent_at: i64,
}

pub struct EnrolledSubmission<'a> {
    recipient: &'a EnrolledDevice,
    header: Header,
    ciphertext: &'a [u8],
}

impl<'a> EnrolledSubmission<'a> {
    pub fn from_verified_request(
        sender: &EnrolledDevice,
        recipient: &'a EnrolledDevice,
        header: Header,
        ciphertext: &'a [u8],
    ) -> Result<Self> {
        if sender.0 != header.stream.sender {
            return Err(MailboxError::Unauthorized);
        }
        if header.sequence == 0
            || header.stream.epoch == 0
            || header.stream.channel == [0; 32]
            || header.message == [0; 32]
            || header.sent_at <= 0
            || !(1..=FRAME_LIMIT).contains(&ciphertext.len())
        {
            return Err(MailboxError::Invalid);
        }
        Ok(Self {
            recipient,
            header,
            ciphertext,
        })
    }
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub messages: i64,
    pub bytes: i64,
    pub retained_ids: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Deposit {
    Stored,
    Duplicate,
}

pub struct Envelope {
    pub cursor: i64,
    pub header: Header,
    pub digest: Id,
    pub ciphertext: Vec<u8>,
}

pub struct Page {
    pub envelopes: Vec<Envelope>,
    pub next: Option<i64>,
}

pub struct RangePage {
    pub envelopes: Vec<Envelope>,
    pub missing: Vec<RangeInclusive<u64>>,
    pub next: Option<u64>,
}

pub struct Mailbox {
    pool: Pool,
    limits: Limits,
}

impl Mailbox {
    pub fn new(pool: Pool, limits: Limits) -> Result<Self> {
        if limits.messages <= 0 || limits.bytes <= 0 || limits.retained_ids < limits.messages {
            return Err(MailboxError::Invalid);
        }
        Ok(Self { pool, limits })
    }

    pub async fn migrate(pool: &Pool) -> Result<()> {
        let mut db = pool.get().await?;
        let transaction = db.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock(4983033826038031201)", &[])
            .await?;
        migrate_in(&transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn deposit(&self, request: EnrolledSubmission<'_>) -> Result<Deposit> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        let stored = self.deposit_in(&tx, request).await?;
        tx.commit().await?;
        Ok(stored)
    }

    pub(crate) async fn deposit_in(
        &self,
        tx: &Transaction<'_>,
        request: EnrolledSubmission<'_>,
    ) -> Result<Deposit> {
        let recipient = request.recipient.0;
        let header = request.header;
        let sender = header.stream.sender;
        let epoch = header.stream.epoch.to_be_bytes();
        let sequence = header.sequence.to_be_bytes();
        let digest: Id = Sha256::digest(request.ciphertext).into();
        let expires_at = header
            .sent_at
            .checked_add(RETENTION)
            .ok_or(MailboxError::Invalid)?;

        let recipient_key: &[&(dyn ToSql + Sync)] =
            &[&recipient.account.as_slice(), &recipient.device.as_slice()];
        tx.execute(
            "INSERT INTO howl_mailbox.inboxes (recipient_account, recipient_device)
             VALUES ($1, $2) ON CONFLICT DO NOTHING",
            recipient_key,
        )
        .await?;
        tx.query_one(
            "SELECT cursor FROM howl_mailbox.inboxes
             WHERE recipient_account = $1 AND recipient_device = $2 FOR UPDATE",
            recipient_key,
        )
        .await?;
        let now = database_time(tx).await?;
        if header.sent_at > now + FUTURE_SKEW {
            return Err(MailboxError::Invalid);
        }
        if now >= expires_at {
            return Err(MailboxError::Expired);
        }

        tx.execute(
            "DELETE FROM howl_mailbox.envelopes
             WHERE recipient_account = $1 AND recipient_device = $2 AND expires_at <= $3",
            &[
                &recipient.account.as_slice(),
                &recipient.device.as_slice(),
                &now,
            ],
        )
        .await?;
        let present = tx
            .query(
                "SELECT cursor, channel, epoch, sender_account, sender_device, sequence,
                        message, sent_at, digest
                 FROM howl_mailbox.envelopes
                 WHERE recipient_account = $1 AND recipient_device = $2
                   AND (message = $3 OR (channel = $4 AND epoch = $5 AND sender_account = $6
                                         AND sender_device = $7 AND sequence = $8))
                 LIMIT 2",
                &[
                    &recipient.account.as_slice(),
                    &recipient.device.as_slice(),
                    &header.message.as_slice(),
                    &header.stream.channel.as_slice(),
                    &epoch.as_slice(),
                    &sender.account.as_slice(),
                    &sender.device.as_slice(),
                    &sequence.as_slice(),
                ],
            )
            .await?;
        match present.as_slice() {
            [] => {}
            [row] if read_header(row)? == header && get_bytes::<32>(row, 8)? == digest => {
                return Ok(Deposit::Duplicate);
            }
            _ => return Err(MailboxError::Conflict),
        }

        let quota = tx
            .query_one(
                "SELECT COUNT(ciphertext), COALESCE(SUM(octet_length(ciphertext)), 0), COUNT(*)
                 FROM howl_mailbox.envelopes
                 WHERE recipient_account = $1 AND recipient_device = $2",
                &[&recipient.account.as_slice(), &recipient.device.as_slice()],
            )
            .await?;
        let messages: i64 = quota.try_get(0)?;
        let bytes: i64 = quota.try_get(1)?;
        let retained_ids: i64 = quota.try_get(2)?;
        let additional = request.ciphertext.len() as i64;
        if messages >= self.limits.messages
            || additional > self.limits.bytes.saturating_sub(bytes)
            || retained_ids >= self.limits.retained_ids
        {
            return Err(MailboxError::Quota);
        }
        let cursor: i64 = tx
            .query_one(
                "UPDATE howl_mailbox.inboxes SET cursor = cursor + 1
                 WHERE recipient_account = $1 AND recipient_device = $2 RETURNING cursor",
                recipient_key,
            )
            .await?
            .try_get(0)?;
        tx.execute(
            "INSERT INTO howl_mailbox.envelopes
                (cursor, recipient_account, recipient_device, channel, epoch, sender_account,
                 sender_device, sequence, message, digest, sent_at, expires_at, ciphertext)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            &[
                &cursor,
                &recipient.account.as_slice(),
                &recipient.device.as_slice(),
                &header.stream.channel.as_slice(),
                &epoch.as_slice(),
                &sender.account.as_slice(),
                &sender.device.as_slice(),
                &sequence.as_slice(),
                &header.message.as_slice(),
                &digest.as_slice(),
                &header.sent_at,
                &expires_at,
                &request.ciphertext,
            ],
        )
        .await?;
        Ok(Deposit::Stored)
    }

    pub async fn fetch(&self, caller: &EnrolledDevice, after: i64, count: usize) -> Result<Page> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        let page = self.fetch_in(&tx, caller, after, count).await?;
        tx.commit().await?;
        Ok(page)
    }

    pub(crate) async fn fetch_in(
        &self,
        tx: &Transaction<'_>,
        caller: &EnrolledDevice,
        after: i64,
        count: usize,
    ) -> Result<Page> {
        let limit = page_limit(count)?;
        if after < 0 {
            return Err(MailboxError::Invalid);
        }
        let rows = tx.query(
                "SELECT cursor, channel, epoch, sender_account, sender_device, sequence,
                        message, sent_at, digest, ciphertext
                 FROM howl_mailbox.envelopes
                 WHERE recipient_account = $1 AND recipient_device = $2
                   AND cursor > $3 AND expires_at > floor(extract(epoch FROM clock_timestamp()))::bigint
                   AND ciphertext IS NOT NULL
                 ORDER BY cursor LIMIT $4",
                &[&caller.0.account.as_slice(), &caller.0.device.as_slice(), &after, &limit],
            )
            .await?;
        let more = rows.len() > count;
        let envelopes = read_page(rows, count)?;
        let next = if more {
            envelopes.last().map(|item| item.cursor)
        } else {
            None
        };
        Ok(Page { envelopes, next })
    }

    pub async fn fetch_range(
        &self,
        caller: &EnrolledDevice,
        stream: Stream,
        range: RangeInclusive<u64>,
        count: usize,
    ) -> Result<RangePage> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        let page = self
            .fetch_range_in(&tx, caller, stream, range, count)
            .await?;
        tx.commit().await?;
        Ok(page)
    }

    pub(crate) async fn fetch_range_in(
        &self,
        tx: &Transaction<'_>,
        caller: &EnrolledDevice,
        stream: Stream,
        range: RangeInclusive<u64>,
        count: usize,
    ) -> Result<RangePage> {
        let limit = page_limit(count)?;
        if range.is_empty() || *range.start() == 0 || stream.epoch == 0 {
            return Err(MailboxError::Invalid);
        }
        let rows = tx
            .query(
                "SELECT cursor, channel, epoch, sender_account, sender_device, sequence,
                        message, sent_at, digest, ciphertext
                 FROM howl_mailbox.envelopes
                 WHERE recipient_account = $1 AND recipient_device = $2
                   AND channel = $3 AND epoch = $4 AND sender_account = $5 AND sender_device = $6
                   AND sequence BETWEEN $7 AND $8
                   AND expires_at > floor(extract(epoch FROM clock_timestamp()))::bigint
                   AND ciphertext IS NOT NULL
                 ORDER BY sequence LIMIT $9",
                &[
                    &caller.0.account.as_slice(),
                    &caller.0.device.as_slice(),
                    &stream.channel.as_slice(),
                    &stream.epoch.to_be_bytes().as_slice(),
                    &stream.sender.account.as_slice(),
                    &stream.sender.device.as_slice(),
                    &range.start().to_be_bytes().as_slice(),
                    &range.end().to_be_bytes().as_slice(),
                    &limit,
                ],
            )
            .await?;
        let more = rows.len() > count;
        let envelopes = read_page(rows, count)?;
        let next = if more {
            envelopes
                .last()
                .and_then(|item| item.header.sequence.checked_add(1))
        } else {
            None
        };
        let through = next.map_or(*range.end(), |start| start - 1);
        let missing = missing(*range.start(), through, &envelopes);
        Ok(RangePage {
            envelopes,
            missing,
            next,
        })
    }

    pub async fn acknowledge(
        &self,
        caller: &EnrolledDevice,
        message: Id,
        digest: Id,
    ) -> Result<bool> {
        let mut db = self.pool.get().await?;
        let tx = db.transaction().await?;
        let confirmed = self.acknowledge_in(&tx, caller, message, digest).await?;
        tx.commit().await?;
        Ok(confirmed)
    }

    pub(crate) async fn acknowledge_in(
        &self,
        tx: &Transaction<'_>,
        caller: &EnrolledDevice,
        message: Id,
        digest: Id,
    ) -> Result<bool> {
        let row = tx.query_one(
                "WITH eligible AS (
                     SELECT cursor FROM howl_mailbox.envelopes
                     WHERE recipient_account = $1 AND recipient_device = $2 AND message = $3
                       AND digest = $4 AND expires_at > floor(extract(epoch FROM clock_timestamp()))::bigint
                 ), acknowledged AS (
                     UPDATE howl_mailbox.envelopes SET ciphertext = NULL
                     WHERE recipient_account = $1 AND recipient_device = $2
                       AND cursor IN (SELECT cursor FROM eligible) AND ciphertext IS NOT NULL
                 )
                 SELECT EXISTS (SELECT 1 FROM eligible)",
                &[&caller.0.account.as_slice(), &caller.0.device.as_slice(), &message.as_slice(), &digest.as_slice()],
            )
            .await?;
        Ok(row.try_get(0)?)
    }

    pub async fn prune_expired(&self, limit: i64) -> Result<u64> {
        if !(1..=PRUNE_LIMIT).contains(&limit) {
            return Err(MailboxError::Invalid);
        }
        let deleted = self
            .pool
            .get()
            .await?
            .execute(
                "DELETE FROM howl_mailbox.envelopes AS envelope USING (
                     SELECT recipient_account, recipient_device, cursor FROM howl_mailbox.envelopes
                     WHERE expires_at <= floor(extract(epoch FROM clock_timestamp()))::bigint
                     ORDER BY expires_at, cursor LIMIT $1 FOR UPDATE SKIP LOCKED
                 ) AS expired
                 WHERE (envelope.recipient_account, envelope.recipient_device, envelope.cursor)
                     = (expired.recipient_account, expired.recipient_device, expired.cursor)",
                &[&limit],
            )
            .await?;
        Ok(deleted)
    }
}

pub(crate) async fn migrate_in(tx: &Transaction<'_>) -> Result<()> {
    tx.batch_execute(include_str!("../migrations/003_mailbox.sql"))
        .await?;
    Ok(())
}

async fn database_time(db: &Transaction<'_>) -> Result<i64> {
    let row = db
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await?;
    Ok(row.try_get(0)?)
}

fn page_limit(count: usize) -> Result<i64> {
    if !(1..=PAGE_LIMIT).contains(&count) {
        return Err(MailboxError::Invalid);
    }
    Ok((count + 1) as i64)
}

fn get_bytes<const N: usize>(row: &Row, index: usize) -> Result<[u8; N]> {
    row.try_get::<_, &[u8]>(index)?
        .try_into()
        .map_err(|_| MailboxError::Database)
}

fn read_header(row: &Row) -> Result<Header> {
    Ok(Header {
        stream: Stream {
            channel: get_bytes(row, 1)?,
            epoch: u64::from_be_bytes(get_bytes(row, 2)?),
            sender: MailingAddress {
                account: get_bytes(row, 3)?,
                device: get_bytes(row, 4)?,
            },
        },
        sequence: u64::from_be_bytes(get_bytes(row, 5)?),
        message: get_bytes(row, 6)?,
        sent_at: row.try_get(7)?,
    })
}

fn read_page(rows: Vec<Row>, count: usize) -> Result<Vec<Envelope>> {
    rows.into_iter()
        .take(count)
        .map(|row| {
            Ok(Envelope {
                cursor: row.try_get(0)?,
                header: read_header(&row)?,
                digest: get_bytes(&row, 8)?,
                ciphertext: row.try_get(9)?,
            })
        })
        .collect()
}

fn missing(first: u64, last: u64, envelopes: &[Envelope]) -> Vec<RangeInclusive<u64>> {
    let mut missing = Vec::new();
    let mut first = Some(first);
    for item in envelopes {
        let sequence = item.header.sequence;
        if let Some(start) = first
            && start < sequence
        {
            missing.push(start..=sequence - 1);
        }
        first = sequence.checked_add(1);
    }
    if let Some(start) = first
        && start <= last
    {
        missing.push(start..=last);
    }
    missing
}
