mod budget;
mod wake;
pub use budget::{
    ApprovedWake, BudgetError, BudgetLimit, BudgetLimits, ConversationBudget, HumanAction,
    HumanCommand, Turn, WakeApproval, WakeOutcome, WakeTurnError,
};
pub use wake::{WakeClaim, WakeJob, WakeState};

use std::{fs::File, io, ops::RangeInclusive, path::Path, time::Duration};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub type Id = [u8; 32];

const MAX_FRAME: usize = 77_112;
const ZERO_TIME: [u8; 8] = [0; 8];
const ACK_DOMAIN: &[u8] = b"howl/delivery-ack/v1\0";
pub const ACK_TAG: u8 = 2;
const ACK_BODY: usize = 257;
pub const ACK_LENGTH: usize = ACK_BODY + 64;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Device {
    pub account: Id,
    pub device: Id,
}

impl Device {
    pub(crate) fn encode(self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.account);
        bytes[32..].copy_from_slice(&self.device);
        bytes
    }

    fn decode(bytes: [u8; 64]) -> Self {
        Self {
            account: field(&bytes, 0),
            device: field(&bytes, 32),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stream {
    pub channel: Id,
    pub sender: Device,
    pub signing_key: Id,
}

impl Stream {
    fn encode(self) -> [u8; 128] {
        let mut bytes = [0; 128];
        bytes[..32].copy_from_slice(&self.channel);
        bytes[32..96].copy_from_slice(&self.sender.encode());
        bytes[96..].copy_from_slice(&self.signing_key);
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub stream: Stream,
    pub message: Id,
    pub sequence: u64,
    pub epoch: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Frame {
    fn validate(self, bytes: &[u8]) -> Result<()> {
        if self.epoch == 0 || self.sequence == 0 || bytes.is_empty() || bytes.len() > MAX_FRAME {
            return Err(Error::InvalidFrame);
        }
        if self.expires_at != 0
            && (!matches!(self.expires_at.checked_sub(self.created_at), Some(1..=300)))
        {
            return Err(Error::InvalidFrame);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Payload<'a> {
    Chat(&'a str),
    Wake { target: Id, text: &'a str },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("delivery database failed")]
    Database(#[from] rusqlite::Error),
    #[error("delivery storage failed")]
    Io(#[from] io::Error),
    #[error("invalid delivery frame")]
    InvalidFrame,
    #[error("frame conflicts with a previously accepted message or sequence")]
    Conflict,
    #[error("unexpected or retired channel epoch")]
    Epoch,
    #[error("device does not match delivery storage")]
    Device,
    #[error("sender sequence was not reserved")]
    Unreserved,
    #[error("sender sequence is exhausted")]
    SequenceExhausted,
    #[error("wake frame is outside its allowed time window")]
    Expired,
    #[error("wake time has not been established or moved backward")]
    WakeClock,
    #[error("invalid or revoked wake grant generation")]
    WakeGrant,
    #[error("delivery acknowledgment is invalid")]
    Ack,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Acknowledgment([u8; ACK_LENGTH]);

impl Acknowledgment {
    pub fn from_bytes(bytes: [u8; ACK_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ACK_LENGTH] {
        &self.0
    }

    pub fn recipient(&self) -> Device {
        Device::decode(field(&self.0, 129))
    }

    fn sign(frame: Frame, recipient: Device, digest: Id, key: &SigningKey) -> Self {
        let mut bytes = [0; ACK_LENGTH];
        bytes[0] = ACK_TAG;
        bytes[1..129].copy_from_slice(&frame.stream.encode());
        bytes[129..193].copy_from_slice(&recipient.encode());
        bytes[193..225].copy_from_slice(&frame.message);
        bytes[225..257].copy_from_slice(&digest);
        let signature = key.sign(&[ACK_DOMAIN, &bytes[..ACK_BODY]].concat());
        bytes[ACK_BODY..].copy_from_slice(&signature.to_bytes());
        Self(bytes)
    }
}

#[derive(Debug)]
pub struct Receipt {
    pub acknowledgment: Acknowledgment,
    pub inserted: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Attempt {
    pub recipient: Device,
    pub frame: Vec<u8>,
    pub route: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Chat {
    pub sender: Device,
    pub message: Id,
    pub received_at: u64,
    pub body: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DeliveryStatus {
    pub recipient: Device,
    pub attempts: u32,
    pub acknowledged: bool,
}

pub struct DeliveryStore {
    connection: Connection,
    local: Device,
}

impl DeliveryStore {
    pub fn open(path: &Path, key: &Id, local: Device) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        let encoded_key = sqlcipher_key(key);
        connection.pragma_update(None, "key", as_text(&encoded_key))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let cipher: String =
            connection.pragma_query_value(None, "cipher_version", |row| row.get(0))?;
        if cipher.is_empty() {
            return Err(Error::Io(io::Error::other("SQLCipher is required")));
        }
        connection.execute_batch(
            "PRAGMA cipher_memory_security = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA secure_delete = ON;",
        )?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if journal != "wal" {
            return Err(Error::Io(io::Error::other("WAL mode is required")));
        }

        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(include_str!("delivery.sql"))?;
        tx.execute_batch(include_str!("presence.sql"))?;
        tx.execute_batch(include_str!("delivery/budget.sql"))?;
        tx.execute(
            "INSERT OR IGNORE INTO store(singleton, device) VALUES (1, ?1)",
            [local.encode()],
        )?;
        let stored: [u8; 64] =
            tx.query_row("SELECT device FROM store WHERE singleton = 1", [], |row| {
                row.get(0)
            })?;
        if stored != local.encode() {
            return Err(Error::Device);
        }
        tx.commit()?;

        Ok(Self { connection, local })
    }

    pub fn presence(&mut self) -> crate::presence::Presence<'_> {
        crate::presence::Presence::new(&mut self.connection)
    }

    pub fn set_epoch(&mut self, channel: Id, epoch: u64) -> Result<()> {
        if epoch == 0 {
            return Err(Error::Epoch);
        }
        let changed = self.connection.execute(
            "INSERT INTO channels VALUES (?1, ?2)
             ON CONFLICT (channel) DO UPDATE SET epoch = excluded.epoch WHERE epoch <= excluded.epoch",
            params![channel, epoch.to_be_bytes()],
        )?;
        if changed == 0 {
            return Err(Error::Epoch);
        }
        Ok(())
    }

    pub fn reserve_sequence(&mut self, stream: Stream) -> Result<u64> {
        if stream.sender != self.local {
            return Err(Error::Device);
        }
        let stream = stream.encode();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last: Option<[u8; 8]> = tx
            .query_row(
                "SELECT last FROM sequences WHERE stream = ?1",
                [stream],
                |row| row.get(0),
            )
            .optional()?;
        let sequence = u64::from_be_bytes(last.unwrap_or(ZERO_TIME))
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        tx.execute(
            "INSERT INTO sequences VALUES (?1, ?2)
             ON CONFLICT (stream) DO UPDATE SET last = excluded.last",
            params![stream, sequence.to_be_bytes()],
        )?;
        tx.commit()?;
        Ok(sequence)
    }

    pub fn enqueue(
        &mut self,
        frame: Frame,
        bytes: &[u8],
        recipients: &[Device],
        now: u64,
    ) -> Result<()> {
        self.enqueue_frames(frame, bytes, recipients, now, None)
    }

    pub fn enqueue_routed(
        &mut self,
        frame: Frame,
        bytes: &[u8],
        recipient: Device,
        route: &str,
        now: u64,
    ) -> Result<()> {
        if route.is_empty() || route.len() > 64 {
            return Err(Error::InvalidFrame);
        }
        self.enqueue_frames(frame, bytes, &[recipient], now, Some(route))
    }

    fn enqueue_frames(
        &mut self,
        frame: Frame,
        bytes: &[u8],
        recipients: &[Device],
        now: u64,
        route: Option<&str>,
    ) -> Result<()> {
        frame.validate(bytes)?;
        if frame.stream.sender != self.local {
            return Err(Error::Device);
        }
        if frame.expires_at != 0 && now >= frame.expires_at {
            return Err(Error::Expired);
        }
        if recipients.is_empty() || recipients.len() > 64 {
            return Err(Error::InvalidFrame);
        }
        let mut recipients = recipients.to_vec();
        recipients.sort_unstable();
        if recipients.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::InvalidFrame);
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_epoch(&tx, frame)?;
        let stream = frame.stream.encode();
        let sequence = frame.sequence.to_be_bytes();
        let reserved = tx
            .query_row(
                "SELECT last >= ?2 FROM sequences WHERE stream = ?1",
                params![stream, sequence],
                |row| row.get::<_, bool>(0),
            )
            .optional()?;
        if reserved != Some(true) {
            return Err(Error::Unreserved);
        }
        let digest: Id = Sha256::digest(bytes).into();
        let changed = tx.execute(
            "INSERT INTO outbox (stream, message, sequence, epoch, expires, digest, frame)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT DO NOTHING",
            params![
                stream,
                frame.message,
                sequence,
                frame.epoch.to_be_bytes(),
                frame.expires_at.to_be_bytes(),
                digest,
                bytes,
            ],
        )?;
        if changed == 0 {
            let existing = tx.query_row(
                "SELECT id, digest FROM outbox
                 WHERE stream = ?1 AND message = ?2 AND sequence = ?3 AND epoch = ?4 AND expires = ?5",
                params![stream, frame.message, sequence, frame.epoch.to_be_bytes(), frame.expires_at.to_be_bytes()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Id>(1)?)),
            ).optional()?;
            let Some((id, saved_digest)) = existing else {
                return Err(Error::Conflict);
            };
            let mut statement =
                tx.prepare("SELECT device FROM recipients WHERE envelope = ?1 ORDER BY device")?;
            let saved = statement
                .query_map([id], |row| row.get::<_, [u8; 64]>(0))?
                .map(|device| device.map(Device::decode))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if digest != saved_digest || recipients != saved {
                return Err(Error::Conflict);
            }
        } else {
            let row = tx.last_insert_rowid();
            for recipient in &recipients {
                tx.execute(
                    "INSERT INTO recipients (envelope, device, due) VALUES (?1, ?2, ?3)",
                    params![row, recipient.encode(), now.to_be_bytes()],
                )?;
            }
        }
        if let Some(route) = route {
            tx.execute(
                "INSERT INTO peer_routes (device, address) VALUES (?1, ?2)
                 ON CONFLICT(device) DO UPDATE SET address = excluded.address",
                params![recipients[0].encode(), route],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn claim_due(
        &mut self,
        channel: Option<Id>,
        now: u64,
        limit: usize,
    ) -> Result<Vec<Attempt>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let due = {
            let mut statement = tx.prepare(
                "SELECT o.id, r.device, o.frame, r.attempt, p.address FROM recipients r
                 JOIN outbox o ON o.id = r.envelope
                 JOIN channels c ON c.channel = substr(o.stream, 1, 32) AND c.epoch = o.epoch
                 LEFT JOIN peer_routes p ON p.device = r.device
                 WHERE (?1 IS NULL OR c.channel = ?1) AND r.acknowledged = 0 AND r.due <= ?2
                 AND o.frame IS NOT NULL AND (o.expires = ?3 OR o.expires > ?2)
                 ORDER BY r.due, o.id, r.device LIMIT ?4",
            )?;
            statement
                .query_map(
                    params![channel, now.to_be_bytes(), ZERO_TIME, limit.min(256) as u32],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, [u8; 64]>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, u32>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut messages = Vec::with_capacity(due.len());
        for (id, device, bytes, attempt, route) in due {
            let interval = 1_u64 << attempt.min(8);
            let jitter = getrandom::u64().map_err(io::Error::other)? % interval;
            let due = now.checked_add(interval + jitter).map(u64::to_be_bytes);
            tx.execute(
                "UPDATE recipients SET due = ?1, attempt = ?2 WHERE envelope = ?3 AND device = ?4",
                params![due, attempt.saturating_add(1), id, device],
            )?;
            messages.push(Attempt {
                recipient: Device::decode(device),
                frame: bytes,
                route,
            });
        }
        tx.commit()?;
        Ok(messages)
    }

    pub fn apply_ack(
        &mut self,
        ack: &Acknowledgment,
        authenticated_recipient: Device,
        key: &VerifyingKey,
    ) -> Result<()> {
        if ack.0[0] != ACK_TAG || ack.recipient() != authenticated_recipient {
            return Err(Error::Ack);
        }
        key.verify_strict(
            &[ACK_DOMAIN, &ack.0[..ACK_BODY]].concat(),
            &Signature::from_bytes(&field(&ack.0, ACK_BODY)),
        )
        .map_err(|_| Error::Ack)?;
        let stream: [u8; 128] = field(&ack.0, 1);
        let message: Id = field(&ack.0, 193);
        let digest: Id = field(&ack.0, 225);
        let changed = self.connection.execute(
            "UPDATE recipients SET acknowledged = 1, due = NULL
             WHERE device = ?1 AND envelope =
                 (SELECT id FROM outbox WHERE stream = ?2 AND message = ?3 AND digest = ?4)",
            params![authenticated_recipient.encode(), stream, message, digest],
        )?;
        if changed == 0 {
            return Err(Error::Ack);
        }
        Ok(())
    }

    pub fn delivery_status(&self, stream: Stream, message: Id) -> Result<Vec<DeliveryStatus>> {
        let mut statement = self.connection.prepare(
            "SELECT r.device, r.attempt, r.acknowledged FROM recipients r JOIN outbox o ON o.id = r.envelope
             WHERE o.stream = ?1 AND o.message = ?2 ORDER BY r.device",
        )?;
        Ok(statement
            .query_map(params![stream.encode(), message], |row| {
                Ok(DeliveryStatus {
                    recipient: Device::decode(row.get(0)?),
                    attempts: row.get(1)?,
                    acknowledged: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn chat_history(&self, channel: Id, limit: usize) -> Result<Vec<Chat>> {
        let mut statement = self.connection.prepare(
            "SELECT substr(stream, 33, 64), message, received, body FROM inbox
             WHERE substr(stream, 1, 32) = ?1 AND kind = 1 AND body IS NOT NULL
             ORDER BY received DESC, id DESC LIMIT ?2",
        )?;
        Ok(statement
            .query_map(params![channel, limit.min(256) as u32], |row| {
                Ok(Chat {
                    sender: Device::decode(row.get(0)?),
                    message: row.get(1)?,
                    received_at: u64::from_be_bytes(row.get(2)?),
                    body: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn establish_wake_time(&self, trusted_now: u64) -> Result<()> {
        let changed = self.connection.execute(
            "UPDATE store SET wake_clock = ?1 WHERE wake_clock IS NULL OR wake_clock <= ?1",
            [trusted_now.to_be_bytes()],
        )?;
        if changed == 0 {
            return Err(Error::WakeClock);
        }
        Ok(())
    }

    pub fn observe_wake_time(&self, now: u64) -> Result<()> {
        wake::record_wake_time(&self.connection, now)
    }

    pub fn accept_authenticated(
        &mut self,
        frame: Frame,
        bytes: &[u8],
        payload: Payload<'_>,
        now: u64,
        local_signer: &SigningKey,
    ) -> Result<Receipt> {
        frame.validate(bytes)?;
        let (kind, target, body) = match payload {
            Payload::Chat(body)
                if frame.expires_at == 0 && !body.is_empty() && body.len() <= 65_536 =>
            {
                (1, None, body)
            }
            Payload::Wake { target, text } if frame.expires_at != 0 && text.len() <= 65_504 => {
                self.observe_wake_time(now)?;
                if now < frame.created_at.saturating_sub(30) || now >= frame.expires_at {
                    return Err(Error::Expired);
                }
                (2, Some(target), text)
            }
            _ => return Err(Error::InvalidFrame),
        };

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_epoch(&tx, frame)?;
        if kind == 2 {
            let current: bool = tx.query_row(
                "SELECT wake_clock <= ?1 FROM store WHERE singleton = 1",
                [now.to_be_bytes()],
                |row| row.get(0),
            )?;
            if !current {
                return Err(Error::WakeClock);
            }
        }
        let stream = frame.stream.encode();
        let sequence = frame.sequence.to_be_bytes();
        let digest: Id = Sha256::digest(bytes).into();
        let matches = {
            let mut statement = tx.prepare(
                "SELECT id, digest, stream = ?1 AND message = ?3 AND sequence = ?4
                        AND epoch = ?5 AND expires = ?6
                 FROM inbox WHERE (substr(stream, 1, 96) = ?2 AND message = ?3)
                                OR (stream = ?1 AND sequence = ?4)",
            )?;
            statement
                .query_map(
                    params![
                        stream,
                        &stream[..96],
                        frame.message,
                        sequence,
                        frame.epoch.to_be_bytes(),
                        frame.expires_at.to_be_bytes()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Id>(1)?,
                            row.get::<_, bool>(2)?,
                        ))
                    },
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let inserted = matches.is_empty();
        let mut conflict = false;
        for (id, previous, exact) in matches {
            if !exact || previous != digest {
                tx.execute(
                    "INSERT OR IGNORE INTO conflicts VALUES (?1, ?2, ?3)",
                    params![id, digest, bytes],
                )?;
                conflict = true;
            }
        }
        if inserted {
            tx.execute(
                "INSERT INTO inbox (stream, message, sequence, epoch, received, expires, digest, frame, kind, target, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    stream, frame.message, sequence, frame.epoch.to_be_bytes(), now.to_be_bytes(),
                    frame.expires_at.to_be_bytes(), digest, bytes, kind, target, body,
                ],
            )?;
            if kind == 1 {
                tx.execute(
                    "INSERT INTO chat_search (rowid, body) VALUES (?1, ?2)",
                    params![tx.last_insert_rowid(), body],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO wake_queue (cursor, generation, state)
                     SELECT ?1, generation, 0 FROM wake_targets WHERE channel = ?2 AND target = ?3 AND status = 1",
                    params![tx.last_insert_rowid(), frame.stream.channel, target],
                )?;
            }
        }
        tx.commit()?;

        if conflict {
            return Err(Error::Conflict);
        }
        Ok(Receipt {
            acknowledgment: Acknowledgment::sign(frame, self.local, digest, local_signer),
            inserted,
        })
    }

    pub fn gaps(
        &self,
        stream: Stream,
        first_expected: u64,
        limit: usize,
    ) -> Result<Vec<RangeInclusive<u64>>> {
        let mut wanted = first_expected.max(1);
        let mut ranges = Vec::new();
        let mut statement = self.connection.prepare(
            "SELECT sequence FROM inbox WHERE stream = ?1 AND sequence >= ?2 ORDER BY sequence",
        )?;
        let sequences = statement
            .query_map(params![stream.encode(), wanted.to_be_bytes()], |row| {
                row.get::<_, [u8; 8]>(0).map(u64::from_be_bytes)
            })?;
        for sequence in sequences {
            if ranges.len() == limit.min(256) {
                break;
            }
            let sequence = sequence?;
            if sequence > wanted {
                ranges.push(wanted..=sequence - 1);
            }
            let Some(next) = sequence.checked_add(1) else {
                break;
            };
            wanted = next;
        }
        Ok(ranges)
    }

    pub fn search_chat(&self, channel: Id, query: &str, limit: usize) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT i.body FROM chat_search JOIN inbox i ON i.id = chat_search.rowid
             WHERE chat_search MATCH ?1 AND substr(i.stream, 1, 32) = ?2
             ORDER BY i.received DESC, i.id DESC LIMIT ?3",
        )?;
        Ok(statement
            .query_map(params![query, channel, limit.min(256) as u32], |row| {
                row.get(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn prune(&mut self, channel: Id, chat_before: u64, now: u64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let epoch: [u8; 8] = tx
            .query_row(
                "SELECT epoch FROM channels WHERE channel = ?1",
                [channel],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::Epoch)?;
        let old_chat = chat_before.to_be_bytes();
        let now = now.to_be_bytes();
        tx.execute(
            "DELETE FROM chat_search WHERE rowid IN (
               SELECT id FROM inbox WHERE substr(stream, 1, 32) = ?1 AND kind = 1 AND received < ?2
             )",
            params![channel, old_chat],
        )?;
        tx.execute(
            "UPDATE inbox SET body = NULL WHERE substr(stream, 1, 32) = ?1
             AND ((kind = 1 AND received < ?2) OR (kind = 2 AND (epoch < ?3 OR expires <= ?4)))",
            params![channel, old_chat, epoch, now],
        )?;
        tx.execute(
            "UPDATE inbox SET frame = NULL WHERE substr(stream, 1, 32) = ?1
             AND (epoch < ?2 OR (expires <> ?3 AND expires <= ?4))
             AND NOT EXISTS (SELECT 1 FROM conflicts WHERE inbox_id = inbox.id)",
            params![channel, epoch, ZERO_TIME, now],
        )?;
        tx.execute(
            "UPDATE outbox SET frame = NULL WHERE substr(stream, 1, 32) = ?1
             AND (epoch < ?2 OR (expires <> ?3 AND expires <= ?4)
                  OR NOT EXISTS (SELECT 1 FROM recipients WHERE envelope = outbox.id AND acknowledged = 0))",
            params![channel, epoch, ZERO_TIME, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn backup(&mut self, destination: &Path, key: &Id) -> Result<()> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let staging = tempfile::Builder::new()
            .prefix(".howl-backup-")
            .tempfile_in(parent)?;
        let path = staging
            .path()
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid backup path"))?;
        let encoded_key = sqlcipher_key(key);
        self.connection.execute(
            "ATTACH DATABASE ?1 AS backup_store KEY ?2",
            params![path, as_text(&encoded_key)],
        )?;
        let exported =
            self.connection
                .query_row("SELECT sqlcipher_export('backup_store')", [], |_| Ok(()));
        let detached = self.connection.execute("DETACH DATABASE backup_store", []);
        exported?;
        detached?;
        staging.as_file().sync_all()?;
        staging
            .persist_noclobber(destination)
            .map_err(|error| error.error)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn require_epoch(connection: &Connection, frame: Frame) -> Result<()> {
    let matching = connection
        .query_row(
            "SELECT epoch = ?2 FROM channels WHERE channel = ?1",
            params![frame.stream.channel, frame.epoch.to_be_bytes()],
            |row| row.get::<_, bool>(0),
        )
        .optional()?;
    if matching != Some(true) {
        return Err(Error::Epoch);
    }
    Ok(())
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    *bytes[offset..].first_chunk().expect("fixed record layout")
}

fn sqlcipher_key(key: &Id) -> Zeroizing<[u8; 67]> {
    let mut encoded = Zeroizing::new([0_u8; 67]);
    encoded[..2].copy_from_slice(b"x'");
    hex::encode_to_slice(key, &mut encoded[2..66]).expect("fixed SQLCipher key length");
    encoded[66] = b'\'';
    encoded
}

fn as_text(key: &[u8; 67]) -> &str {
    str::from_utf8(key).expect("ASCII SQLCipher key")
}
