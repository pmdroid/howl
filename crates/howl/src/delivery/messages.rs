use howl_envelope::{AgentReply, AgentRole, Body};
use rusqlite::{OptionalExtension, Row, params};

use super::{DeliveryStore, Device, Id, Result};

#[derive(Debug, Eq, PartialEq)]
pub struct ChannelMessage {
    pub sender: Device,
    pub message: Id,
    pub received_at: u64,
    pub body: Body<String>,
}

const MESSAGES: &str = "
    SELECT substr(i.stream, 33, 64), i.message, i.received, i.body,
           i.kind, a.agent, a.role, a.in_reply_to, a.context_digest, i.target
    FROM inbox i LEFT JOIN agent_replies a ON a.cursor = i.id
    WHERE substr(i.stream, 1, 32) = ?1 AND i.body IS NOT NULL";

impl DeliveryStore {
    pub fn channel_history(&self, channel: Id, limit: usize) -> Result<Vec<ChannelMessage>> {
        let mut statement = self.connection.prepare(&format!(
            "{MESSAGES} AND i.kind IN (1, 3, 4) ORDER BY i.received DESC, i.id DESC LIMIT ?2"
        ))?;
        Ok(statement
            .query_map(params![channel, limit.min(256) as u32], read)?
            .collect::<std::result::Result<Vec<_>, _>>()?)
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
                &format!("{MESSAGES} AND i.kind IN (1, 3) AND substr(i.stream, 33, 64) = ?2 AND i.message = ?3"),
                params![channel, sender.encode(), message],
                read,
            )
            .optional()?)
    }
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
