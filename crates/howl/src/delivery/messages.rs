use howl_envelope::{AgentReply, AgentRole, Body, inspect_single_recipient_unverified};
use rusqlite::{Connection, OptionalExtension, Row, params};

use super::{DeliveryStore, Device, Error, Id, Result};

#[derive(Debug, Eq, PartialEq)]
pub struct ChannelMessage {
    pub sender: Device,
    pub message: Id,
    pub received_at: u64,
    pub body: Body<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ChannelEvent {
    pub cursor: u64,
    pub message: ChannelMessage,
    pub recipient: Option<Device>,
}

const MESSAGE_FIELDS: &str = "
    substr(i.stream, 33, 64), i.message, i.received, i.body,
    i.kind, a.agent, a.role, a.in_reply_to, a.context_digest, i.target";

const MESSAGES: &str = "
    FROM inbox i LEFT JOIN agent_replies a ON a.cursor = i.id
    LEFT JOIN channel_event_addresses e ON e.cursor = i.id
    WHERE substr(i.stream, 1, 32) = ?1 AND i.body IS NOT NULL";

impl DeliveryStore {
    pub fn channel_history(&self, channel: Id, limit: usize) -> Result<Vec<ChannelMessage>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {MESSAGE_FIELDS} {MESSAGES} AND i.kind IN (1, 3, 4) AND e.outbound IS NOT 1
             ORDER BY i.received DESC, i.id DESC LIMIT ?2"
        ))?;
        Ok(statement
            .query_map(params![channel, limit.min(256) as u32], read)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn channel_events(
        &self,
        channel: Id,
        after: u64,
        limit: usize,
    ) -> Result<Vec<ChannelEvent>> {
        let Ok(after) = i64::try_from(after) else {
            return Ok(Vec::new());
        };
        let mut statement = self.connection.prepare(&format!(
            "SELECT {MESSAGE_FIELDS}, i.id, e.recipient {MESSAGES}
             AND i.kind IN (1, 3, 4) AND i.id > ?2 ORDER BY i.id LIMIT ?3"
        ))?;
        Ok(statement
            .query_map(params![channel, after, limit.min(256) as u32], read_event)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn direct_events(
        &self,
        channel: Id,
        local: Device,
        peer: Device,
        after: u64,
        limit: usize,
    ) -> Result<Vec<ChannelEvent>> {
        if local != self.local || local == peer {
            return Err(Error::Device);
        }
        let Ok(after) = i64::try_from(after) else {
            return Ok(Vec::new());
        };
        let mut statement = self.connection.prepare(&format!(
            "SELECT {MESSAGE_FIELDS}, i.id, e.recipient, CASE WHEN e.cursor IS NULL THEN i.frame END
             {MESSAGES} AND i.kind IN (1, 3, 4) AND i.id > ?2
             AND ((e.outbound = 1 AND e.recipient = ?3)
               OR (e.outbound IS NOT 1 AND substr(i.stream, 33, 64) = ?3
                 AND (e.recipient = ?4 OR (e.cursor IS NULL AND i.frame IS NOT NULL))))
             ORDER BY i.id"
        ))?;
        let mut rows = statement.query(params![channel, after, peer.encode(), local.encode()])?;
        let mut events = Vec::new();
        while events.len() < limit.min(256)
            && let Some(row) = rows.next()?
        {
            let mut event = read_event(row)?;
            if event.recipient.is_none() {
                let Some(frame) = row.get::<_, Option<Vec<u8>>>(12)? else {
                    continue;
                };
                event.recipient = sole_recipient(&frame).filter(|recipient| *recipient == local);
            }
            if event.recipient.is_some() {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub fn channel_message(
        &self,
        channel: Id,
        sender: Device,
        message: Id,
    ) -> Result<Option<ChannelMessage>> {
        Ok(self
            .connection
            .query_row(
                &format!(
                    "SELECT {MESSAGE_FIELDS} {MESSAGES} AND i.kind IN (1, 3) AND e.outbound IS NOT 1
                         AND substr(i.stream, 33, 64) = ?2 AND i.message = ?3"
                ),
                params![channel, sender.encode(), message],
                read,
            )
            .optional()?)
    }
}

pub(super) fn record_outbound(
    connection: &Connection,
    envelope: i64,
    recipient: Device,
    now: u64,
    body: Body<&str>,
) -> Result<()> {
    let (kind, target, text) = match &body {
        Body::Chat(text) => (1, None, *text),
        Body::AgentReply(reply) => (3, None, reply.text),
        Body::Wake { session, text } => (4, Some(session), *text),
    };
    connection.execute(
        "INSERT INTO inbox (stream, message, sequence, epoch, received, expires, digest, kind, target, body)
         SELECT stream, message, sequence, epoch, ?2, expires, digest, ?3, ?4, ?5
         FROM outbox WHERE id = ?1",
        params![envelope, now.to_be_bytes(), kind, target, text],
    )?;
    let cursor = connection.last_insert_rowid();
    if let Body::AgentReply(reply) = body {
        record_agent_reply(connection, cursor, reply)?;
    }
    connection.execute(
        "INSERT INTO channel_event_addresses (cursor, outbound, recipient) VALUES (?1, 1, ?2)",
        params![cursor, recipient.encode()],
    )?;
    Ok(())
}

pub(super) fn record_agent_reply(
    connection: &Connection,
    cursor: i64,
    reply: AgentReply<&str>,
) -> Result<()> {
    connection.execute(
        "INSERT INTO agent_replies (cursor, agent, role, in_reply_to, context_digest)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            cursor,
            reply.agent,
            reply.role as u8,
            reply.in_reply_to,
            reply.context_digest
        ],
    )?;
    Ok(())
}

pub(super) fn record_inbound_recipient(
    connection: &Connection,
    cursor: i64,
    bytes: &[u8],
    local: Device,
) -> Result<()> {
    let recipient = sole_recipient(bytes)
        .filter(|recipient| *recipient == local)
        .map(Device::encode);
    connection.execute(
        "INSERT INTO channel_event_addresses (cursor, outbound, recipient) VALUES (?1, 0, ?2)",
        params![cursor, recipient],
    )?;
    Ok(())
}

fn sole_recipient(bytes: &[u8]) -> Option<Device> {
    let address = inspect_single_recipient_unverified(bytes).ok()??;
    Some(Device {
        account: address.account,
        device: address.device,
    })
}

fn read_event(row: &Row<'_>) -> rusqlite::Result<ChannelEvent> {
    Ok(ChannelEvent {
        cursor: u64::try_from(row.get::<_, i64>(10)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        message: read(row)?,
        recipient: row.get::<_, Option<[u8; 64]>>(11)?.map(Device::decode),
    })
}

fn read(row: &Row<'_>) -> rusqlite::Result<ChannelMessage> {
    let text = row.get(3)?;
    let body = match row.get::<_, u8>(4)? {
        1 => Body::Chat(text),
        3 => Body::AgentReply(AgentReply {
            agent: row.get(5)?,
            role: AgentRole::try_from(row.get::<_, u8>(6)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            in_reply_to: row.get(7)?,
            context_digest: row.get(8)?,
            text,
        }),
        4 => Body::Wake {
            session: row.get(9)?,
            text,
        },
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(ChannelMessage {
        sender: Device::decode(row.get(0)?),
        message: row.get(1)?,
        received_at: u64::from_be_bytes(row.get(2)?),
        body,
    })
}
