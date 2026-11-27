use std::io;

use howl_envelope::AgentRole;
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{DeliveryStore, Error, Id, Result};

const RETENTION: i64 = 7 * 24 * 60 * 60;
const MAX_QUEUED: i64 = 20_000;
const MAX_ATTEMPTS: u32 = 48;
const LEASE_SECONDS: i64 = 30;
const MAX_CONTENT_BYTES: usize = 16_384;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum WebhookEventKind {
    #[serde(rename = "message.received")]
    MessageReceived = 1,
    #[serde(rename = "agent.reply")]
    AgentReply = 2,
    #[serde(rename = "run.completed")]
    RunCompleted = 3,
    #[serde(rename = "run.failed")]
    RunFailed = 4,
    #[serde(rename = "mention")]
    Mention = 5,
    #[serde(rename = "approval.requested")]
    ApprovalRequested = 6,
}

pub(crate) struct WebhookFilter<'a> {
    pub name: &'a str,
    pub revision: Id,
    pub channels: &'a [Id],
    pub events: &'a [WebhookEventKind],
    pub include_content: bool,
}

pub(crate) struct WebhookAttempt {
    pub destination: String,
    pub revision: Id,
    pub event: Id,
    pub channel: Id,
    pub body: String,
    attempts: u32,
    lease: [u8; 16],
}

#[derive(Clone, Copy)]
pub(crate) enum WebhookOutcome {
    Delivered,
    Retry,
    Rejected,
    Revoked,
    DestinationBlocked,
}

#[derive(Serialize)]
pub(crate) struct WebhookFailure {
    destination: String,
    event: String,
    state: &'static str,
    attempts: u32,
    outcome: String,
}

struct JournalEvent {
    cursor: i64,
    channel: Id,
    kind: WebhookEventKind,
    created: i64,
    source: Id,
    sender: Option<Id>,
    target: Option<Id>,
    integration: bool,
    content: Option<String>,
}

#[derive(Serialize)]
struct WebhookBody<'a> {
    id: String,
    event: WebhookEventKind,
    timestamp: i64,
    channel: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_truncated: Option<bool>,
}

impl DeliveryStore {
    pub(crate) fn webhooks_initialized(&self) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'webhook_outbox')",
            [],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn initialize_webhooks(&self) -> Result<()> {
        let tx = self.connection.unchecked_transaction()?;
        tx.execute_batch(include_str!("webhook_queue.sql"))?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn synchronize_webhooks(
        &mut self,
        filters: &[WebhookFilter<'_>],
        now: u64,
    ) -> Result<()> {
        let now = timestamp(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let destinations = {
            let mut statement = tx.prepare("SELECT name, revision FROM webhook_destinations")?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Id>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (name, revision) in destinations {
            if !filters
                .iter()
                .any(|filter| filter.name == name && filter.revision == revision)
            {
                tx.execute("DELETE FROM webhook_destinations WHERE name = ?1", [&name])?;
                tx.execute(
                    "UPDATE webhook_outbox SET state = 2, body = NULL, lease = NULL, outcome = 'revoked'
                     WHERE endpoint = ?1 AND revision = ?2 AND (state = 0 OR state = 2)",
                    params![name, revision],
                )?;
            }
        }
        tx.execute(
            "UPDATE webhook_outbox SET state = 2, lease = NULL, outcome = 'expired'
             WHERE state = 0 AND available <= ?1 AND expires <= ?1",
            [now],
        )?;
        tx.execute(
            "UPDATE webhook_outbox SET state = 2, lease = NULL, outcome = 'retry_exhausted'
             WHERE state = 0 AND available <= ?1 AND attempts >= ?2",
            params![now, MAX_ATTEMPTS],
        )?;
        tx.execute(
            "DELETE FROM webhook_outbox WHERE state <> 0 AND expires <= ?1",
            [now.saturating_sub(RETENTION)],
        )?;
        tx.execute(
            "DELETE FROM webhook_events WHERE created < ?1
             AND cursor < (SELECT COALESCE(MAX(cursor), 0) FROM webhook_events)",
            [now.saturating_sub(RETENTION)],
        )?;
        super::integration_runs::expire_due(&tx, now)?;
        for filter in filters {
            queue_destination(&tx, filter, self.local.device, now)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn claim_webhook(&mut self, now: u64) -> Result<Option<WebhookAttempt>> {
        let now = timestamp(now)?;
        let mut lease = [0u8; 16];
        getrandom::fill(&mut lease).map_err(io::Error::other)?;
        Ok(self
            .connection
            .query_row(
                "UPDATE webhook_outbox
                 SET lease = ?2, available = ?3, attempts = attempts + 1
                 WHERE rowid = (SELECT rowid FROM webhook_outbox
                    WHERE state = 0 AND available <= ?1 AND expires > ?1
                    ORDER BY available, rowid LIMIT 1)
                 RETURNING endpoint, revision, event_id, channel, body, attempts",
                params![now, lease, now.saturating_add(LEASE_SECONDS)],
                |row| {
                    Ok(WebhookAttempt {
                        destination: row.get(0)?,
                        revision: row.get(1)?,
                        event: row.get(2)?,
                        channel: row.get(3)?,
                        body: row.get(4)?,
                        attempts: row.get(5)?,
                        lease,
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn finish_webhook(
        &self,
        attempt: &WebhookAttempt,
        outcome: WebhookOutcome,
        now: u64,
    ) -> Result<()> {
        let now = timestamp(now)?;
        let (state, detail, available, erase) = match outcome {
            WebhookOutcome::Delivered => (1, "delivered", now, true),
            WebhookOutcome::Retry if attempt.attempts < MAX_ATTEMPTS => {
                let interval = (1_i64 << attempt.attempts.min(12)).min(3_600);
                let random = getrandom::u64().map_err(io::Error::other)? as i64 & i64::MAX;
                let delay = interval + random % (interval / 4 + 1);
                (0, "retrying", now.saturating_add(delay), false)
            }
            WebhookOutcome::Retry => (2, "retry_exhausted", now, false),
            WebhookOutcome::Rejected => (2, "rejected", now, false),
            WebhookOutcome::Revoked => (2, "revoked", now, true),
            WebhookOutcome::DestinationBlocked => (2, "destination_blocked", now, false),
        };
        self.connection.execute(
            "UPDATE webhook_outbox SET
               state = CASE WHEN ?5 = 0 AND ?7 >= expires THEN 2 ELSE ?5 END,
               outcome = CASE WHEN ?5 = 0 AND ?7 >= expires THEN 'expired' ELSE ?6 END,
               available = ?7, lease = NULL,
               body = CASE WHEN ?8 THEN NULL ELSE body END
             WHERE endpoint = ?1 AND revision = ?2 AND event_id = ?3 AND lease = ?4",
            params![
                attempt.destination,
                attempt.revision,
                attempt.event,
                attempt.lease,
                state,
                detail,
                available,
                erase
            ],
        )?;
        Ok(())
    }

    pub(crate) fn webhook_failures(&self) -> Result<Vec<WebhookFailure>> {
        let mut sql = self.connection.prepare(
            "SELECT endpoint, event_id, state, attempts, outcome FROM webhook_outbox
             WHERE state <> 1 AND outcome IS NOT NULL
             ORDER BY available DESC, rowid DESC LIMIT 200",
        )?;
        Ok(sql
            .query_map([], |row| {
                Ok(WebhookFailure {
                    destination: row.get(0)?,
                    event: hex::encode(row.get::<_, Id>(1)?),
                    state: if row.get::<_, u8>(2)? == 0 {
                        "pending"
                    } else {
                        "dead"
                    },
                    attempts: row.get(3)?,
                    outcome: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn replay_webhook(
        &self,
        filter: &WebhookFilter<'_>,
        event: Id,
        now: u64,
    ) -> Result<bool> {
        let now = timestamp(now)?;
        let channel: Option<Id> = self
            .connection
            .query_row(
                "SELECT channel FROM webhook_outbox WHERE endpoint = ?1 AND revision = ?2
                 AND event_id = ?3 AND state = 2 AND body IS NOT NULL",
                params![filter.name, filter.revision, event],
                |row| row.get(0),
            )
            .optional()?;
        if channel.is_none_or(|channel| !filter.channels.contains(&channel)) {
            return Ok(false);
        }
        Ok(self.connection.execute(
            "UPDATE webhook_outbox SET state = 0, attempts = 0, lease = NULL, outcome = NULL,
             expires = ?4, available = ?5
             WHERE endpoint = ?1 AND revision = ?2 AND event_id = ?3 AND state = 2 AND body IS NOT NULL",
            params![filter.name, filter.revision, event, now.saturating_add(RETENTION), now],
        )? == 1)
    }
}

fn queue_destination(
    tx: &Transaction<'_>,
    filter: &WebhookFilter<'_>,
    local: Id,
    now: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO webhook_destinations (name, revision, cursor)
         SELECT ?1, ?2, COALESCE(MAX(cursor), 0) FROM webhook_events WHERE true
         ON CONFLICT(name) DO NOTHING",
        params![filter.name, filter.revision],
    )?;
    let cursor: i64 = tx.query_row(
        "SELECT cursor FROM webhook_destinations WHERE name = ?1",
        [filter.name],
        |row| row.get(0),
    )?;
    let queued: i64 = tx.query_row(
        "SELECT COUNT(*) FROM webhook_outbox WHERE state = 0 AND endpoint = ?1 AND revision = ?2",
        params![filter.name, filter.revision],
        |row| row.get(0),
    )?;
    let mut sql = tx.prepare(
        "SELECT w.cursor, w.channel, w.kind, w.created, COALESCE(i.message, w.run_id),
              substr(i.stream, 65, 32), COALESCE(i.target, r.target), a.cursor IS NOT NULL,
              CASE WHEN ?3 OR w.kind = 5 THEN COALESCE(i.body, r.reply) ELSE NULL END
         FROM webhook_events w LEFT JOIN inbox i ON i.id = w.inbox_cursor
         LEFT JOIN integration_events a ON a.cursor = w.inbox_cursor
         LEFT JOIN integration_runs r ON r.id = w.run_id
         WHERE w.cursor > ?1 ORDER BY w.cursor LIMIT ?2",
    )?;
    let mut through = cursor;
    let scan = (MAX_QUEUED - queued).clamp(0, 128);
    let candidates = sql.query_map(params![cursor, scan, filter.include_content], read_event)?;
    for event in candidates {
        let event = event?;
        through = event.cursor;
        if !filter.channels.contains(&event.channel)
            || !filter.events.contains(&event.kind)
            || event.created.saturating_add(RETENTION) <= now
            || (event.integration
                && matches!(
                    event.kind,
                    WebhookEventKind::MessageReceived | WebhookEventKind::Mention
                ))
        {
            continue;
        }
        let target = if event.kind == WebhookEventKind::Mention {
            let Some(target) = event
                .content
                .as_deref()
                .and_then(|text| mention_target(text, local))
            else {
                continue;
            };
            Some(target)
        } else {
            event.target
        };
        let id = event_id(&event);
        let content = event.content.as_deref().filter(|_| filter.include_content);
        let body = serde_json::to_string(&WebhookBody {
            id: hex::encode(id),
            event: event.kind,
            timestamp: event.created,
            channel: hex::encode(event.channel),
            source: hex::encode(event.source),
            sender: event.sender.map(hex::encode),
            target: target.map(hex::encode),
            content: content
                .map(|text| &text[..text.floor_char_boundary(MAX_CONTENT_BYTES.min(text.len()))]),
            content_truncated: content
                .filter(|text| text.len() > MAX_CONTENT_BYTES)
                .map(|_| true),
        })
        .map_err(io::Error::other)?;
        tx.execute(
            "INSERT OR IGNORE INTO webhook_outbox
              (endpoint, revision, event_id, channel, body, expires, available)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                filter.name,
                filter.revision,
                id,
                event.channel,
                body,
                event.created.saturating_add(RETENTION),
                now
            ],
        )?;
    }
    if through != cursor {
        tx.execute(
            "UPDATE webhook_destinations SET cursor = ?2 WHERE name = ?1",
            params![filter.name, through],
        )?;
    }
    Ok(())
}

fn read_event(row: &Row<'_>) -> rusqlite::Result<JournalEvent> {
    let kind = match row.get::<_, u8>(2)? {
        1 => WebhookEventKind::MessageReceived,
        2 => WebhookEventKind::AgentReply,
        3 => WebhookEventKind::RunCompleted,
        4 => WebhookEventKind::RunFailed,
        5 => WebhookEventKind::Mention,
        6 => WebhookEventKind::ApprovalRequested,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(JournalEvent {
        cursor: row.get(0)?,
        channel: row.get(1)?,
        kind,
        created: row.get(3)?,
        source: row.get(4)?,
        sender: row.get(5)?,
        target: row.get(6)?,
        integration: row.get(7)?,
        content: row.get(8)?,
    })
}

fn mention_target(text: &str, device: Id) -> Option<Id> {
    let targets = [
        device,
        AgentRole::Architect.agent_id(&device),
        AgentRole::Reviewer.agent_id(&device),
    ];
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '@')
        .filter_map(|word| word.strip_prefix('@'))
        .filter(|target| target.len() == 64)
        .find_map(|target| {
            let mut id = [0; 32];
            hex::decode_to_slice(target, &mut id).ok()?;
            targets.contains(&id).then_some(id)
        })
}

fn event_id(event: &JournalEvent) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"howl/webhook-event/v1\0");
    hash.update([event.kind as u8]);
    hash.update(event.channel);
    hash.update(event.source);
    hash.finalize().into()
}

fn timestamp(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::InvalidFrame)
}

#[cfg(test)]
mod tests;
