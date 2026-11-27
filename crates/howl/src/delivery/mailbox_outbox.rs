use rusqlite::params;

use super::{DeliveryStore, Device, Result, ZERO_TIME};

pub(crate) const MAILBOX_OUTBOX_BATCH: usize = 32;

pub(crate) struct MailboxOutboxItem {
    pub cursor: i64,
    pub frame: Vec<u8>,
}

impl DeliveryStore {
    pub(crate) fn mailbox_outbox(
        &self,
        recipient: Device,
        after: i64,
        now: u64,
    ) -> Result<Vec<MailboxOutboxItem>> {
        let mut query = self.connection.prepare(
            "SELECT o.id, o.frame
             FROM recipients r JOIN outbox o ON o.id = r.envelope
             JOIN channels c ON c.channel = substr(o.stream, 1, 32) AND c.epoch = o.epoch
             WHERE r.device = ?1 AND r.acknowledged = 0 AND o.id > ?2
               AND o.frame IS NOT NULL AND (o.expires = ?3 OR o.expires > ?4)
             ORDER BY o.id LIMIT ?5",
        )?;
        Ok(query
            .query_map(
                params![
                    recipient.encode(),
                    after,
                    ZERO_TIME,
                    now.to_be_bytes(),
                    (MAILBOX_OUTBOX_BATCH + 1) as i64
                ],
                |row| {
                    Ok(MailboxOutboxItem {
                        cursor: row.get(0)?,
                        frame: row.get(1)?,
                    })
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }
}
