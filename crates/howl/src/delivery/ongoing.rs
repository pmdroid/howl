use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{DeliveryStore, Device, Error, Frame, Id, Result};

#[derive(Clone, Copy)]
pub(crate) struct Thread {
    pub scope: Id,
    pub channel: Id,
    pub peer: Device,
    pub epoch: u64,
    pub origin: Option<Id>,
}

pub(crate) struct Schedule {
    pub id: Id,
    pub seconds: i64,
    pub text: String,
}

pub(crate) struct Input {
    pub id: i64,
    pub scheduled: bool,
    pub text: String,
}

pub(crate) struct Publication {
    pub id: i64,
    pub source: Id,
    pub result: String,
}

#[derive(Serialize)]
pub(crate) struct Exchange {
    input: String,
    reply: String,
}

impl DeliveryStore {
    pub(crate) fn prepare_thread(&self, thread: Thread) -> Result<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO ongoing_threads (scope, channel, peer, epoch, cursor)
             VALUES (?1, ?2, ?3, ?4, (SELECT COALESCE(MAX(id), 0) FROM inbox))",
            params![
                thread.scope,
                thread.channel,
                thread.peer.encode(),
                thread.epoch.to_be_bytes()
            ],
        )?;
        self.connection.execute(
            "UPDATE ongoing_turns SET finished = 1, input = '', result = 'Agent turn interrupted. Send another message to continue.'
             WHERE scope = ?1 AND finished = 0",
            [thread.scope],
        )?;
        Ok(())
    }

    pub(crate) fn next_ongoing(
        &mut self,
        thread: Thread,
        schedules: &[Schedule],
        now: i64,
    ) -> Result<Option<Input>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut due = None;
        for schedule in schedules {
            tx.execute(
                "INSERT OR IGNORE INTO ongoing_schedules VALUES (?1, ?2, ?3)",
                params![
                    thread.scope,
                    schedule.id,
                    now.saturating_add(schedule.seconds)
                ],
            )?;
            let next = tx.query_row(
                "SELECT due FROM ongoing_schedules WHERE scope = ?1 AND schedule = ?2",
                params![thread.scope, schedule.id],
                |row| row.get::<_, i64>(0),
            )?;
            if next <= now && due.is_none_or(|(previous, _)| next < previous) {
                due = Some((next, schedule));
            }
        }
        let selected = if let Some((due, schedule)) = due {
            let source = Sha256::new()
                .chain_update(b"howl/scheduled-turn/v1\0")
                .chain_update(thread.scope)
                .chain_update(schedule.id)
                .chain_update(due.to_be_bytes())
                .finalize();
            tx.execute(
                "UPDATE ongoing_schedules SET due = ?3 WHERE scope = ?1 AND schedule = ?2",
                params![
                    thread.scope,
                    schedule.id,
                    now.saturating_add(schedule.seconds)
                ],
            )?;
            Some((Id::from(source), schedule.text.clone(), true))
        } else {
            let message = tx.query_row(
                "SELECT i.id, i.message, i.body FROM inbox i
                 JOIN channel_event_addresses e ON e.cursor = i.id AND e.outbound = 0 AND e.recipient = ?2
                 LEFT JOIN integration_events g ON g.cursor = i.id
                 WHERE substr(i.stream, 1, 32) = ?3 AND substr(i.stream, 33, 64) = ?4
                   AND i.epoch = ?5 AND g.actor IS ?6 AND i.kind = 1 AND i.body IS NOT NULL
                   AND i.id > (SELECT cursor FROM ongoing_threads WHERE scope = ?1)
                 ORDER BY i.id LIMIT 1",
                params![thread.scope, self.local.encode(), thread.channel, thread.peer.encode(), thread.epoch.to_be_bytes(), thread.origin],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Id>(1)?, row.get::<_, String>(2)?)),
            ).optional()?;
            if let Some((cursor, source, text)) = message {
                tx.execute(
                    "UPDATE ongoing_threads SET cursor = ?2 WHERE scope = ?1",
                    params![thread.scope, cursor],
                )?;
                Some((source, text, false))
            } else {
                None
            }
        };
        let turn = if let Some((source, text, scheduled)) = selected {
            tx.execute(
                "INSERT INTO ongoing_turns (scope, source, scheduled, input) VALUES (?1, ?2, ?3, ?4)",
                params![thread.scope, source, scheduled, text],
            )?;
            Some(Input {
                id: tx.last_insert_rowid(),
                scheduled,
                text,
            })
        } else {
            None
        };
        tx.commit()?;
        Ok(turn)
    }

    pub(crate) fn finish_ongoing(&self, id: i64, result: &str, successful: bool) -> Result<()> {
        let count = self.connection.execute(
            "UPDATE ongoing_turns SET finished = 1, result = ?2, input = CASE WHEN ?3 THEN input ELSE '' END
             WHERE id = ?1 AND finished = 0",
            params![id, result, successful],
        )?;
        if count != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    pub(crate) fn ongoing_history(&self, scope: Id) -> Result<Vec<Exchange>> {
        let mut statement = self.connection.prepare(
            "SELECT input, result FROM ongoing_turns WHERE scope = ?1 AND result IS NOT NULL AND input <> ''
             ORDER BY id DESC LIMIT 8",
        )?;
        let mut history = statement
            .query_map([scope], |row| {
                Ok(Exchange {
                    input: row.get(0)?,
                    reply: row.get(1)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        history.reverse();
        Ok(history)
    }

    pub(crate) fn pending_ongoing(&self, scope: Id) -> Result<Option<Publication>> {
        Ok(self.connection.query_row(
            "SELECT id, source, result FROM ongoing_turns WHERE scope = ?1 AND sent IS NULL AND result IS NOT NULL ORDER BY id LIMIT 1",
            [scope],
            |row| Ok(Publication { id: row.get(0)?, source: row.get(1)?, result: row.get(2)? }),
        ).optional()?)
    }
}

pub(super) fn publication(
    tx: &Connection,
    frame: Frame,
    recipient: Device,
    id: i64,
    reply: howl_envelope::AgentReply<&str>,
) -> Result<Option<Id>> {
    tx.query_row(
        "SELECT t.sent FROM ongoing_turns t JOIN ongoing_threads s ON s.scope = t.scope
         WHERE t.id = ?1 AND t.source = ?2 AND t.result = ?3
           AND s.channel = ?4 AND s.peer = ?5 AND s.epoch = ?6",
        params![
            id,
            reply.in_reply_to,
            reply.text,
            frame.stream.channel,
            recipient.encode(),
            frame.epoch.to_be_bytes()
        ],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(Error::Conflict)
}

pub(super) fn publish(tx: &Connection, id: i64, message: Id) -> Result<()> {
    tx.execute(
        "UPDATE ongoing_turns SET sent = ?2 WHERE id = ?1",
        params![id, message],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_schedules_survive_restart_and_skip_missed_intervals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.db");
        let local = Device {
            account: [1; 32],
            device: [2; 32],
        };
        let thread = Thread {
            scope: [3; 32],
            channel: [4; 32],
            peer: Device {
                account: [1; 32],
                device: [5; 32],
            },
            epoch: 1,
            origin: None,
        };
        let schedules = [Schedule {
            id: [6; 32],
            seconds: 60,
            text: "Check in".into(),
        }];
        let mut store = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        store.prepare_thread(thread).unwrap();
        assert!(
            store
                .next_ongoing(thread, &schedules, 10)
                .unwrap()
                .is_none()
        );
        drop(store);

        let mut store = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        store.prepare_thread(thread).unwrap();
        let turn = store
            .next_ongoing(thread, &schedules, 500)
            .unwrap()
            .unwrap();
        assert!(turn.scheduled);
        assert_eq!(turn.text, "Check in");
        assert!(
            store
                .next_ongoing(thread, &schedules, 500)
                .unwrap()
                .is_none()
        );
        store.finish_ongoing(turn.id, "Checked in", true).unwrap();
        assert_eq!(
            store.pending_ongoing(thread.scope).unwrap().unwrap().result,
            "Checked in"
        );
        assert!(
            store
                .next_ongoing(thread, &schedules, 559)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .next_ongoing(thread, &schedules, 560)
                .unwrap()
                .is_some()
        );
    }
}
