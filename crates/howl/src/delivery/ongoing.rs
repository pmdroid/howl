use std::io;

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
    pub source: Source,
    pub text: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    DirectMessage,
    Schedule,
    WorkResult,
    PeerReply,
}

pub(crate) struct Work {
    pub id: Id,
    pub instruction: String,
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
        work_control_from: &str,
        now: i64,
    ) -> Result<Option<Input>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let completed = tx.query_row(
            "SELECT id, result FROM ongoing_work WHERE scope = ?1 AND result IS NOT NULL AND reported = 0 ORDER BY rowid LIMIT 1",
            [thread.scope], |row| Ok((row.get::<_, Id>(0)?, row.get::<_, String>(1)?)),
        ).optional()?;
        let peer_reply = tx.query_row(
            "SELECT p.message, i.message, i.body FROM ongoing_peer_requests p
             JOIN agent_replies a ON a.in_reply_to = p.message
             JOIN inbox i ON i.id = a.cursor AND i.kind = 3 AND i.body IS NOT NULL
             JOIN channel_event_addresses e ON e.cursor = i.id AND e.outbound = 0 AND e.recipient = ?2
             WHERE p.scope = ?1 AND substr(i.stream, 1, 32) = ?3 AND substr(i.stream, 65, 32) = p.peer
                 AND i.epoch = ?4 AND p.expires > ?5
             ORDER BY i.id LIMIT 1", params![thread.scope, self.local.encode(), thread.channel, thread.epoch.to_be_bytes(), now],
            |row| Ok((row.get::<_, Id>(0)?, row.get::<_, Id>(1)?, row.get::<_, String>(2)?)),
        ).optional()?;
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
        let selected = if let Some((id, result)) = completed {
            tx.execute("UPDATE ongoing_work SET reported = 1 WHERE id = ?1", [id])?;
            Some((id, result, Source::WorkResult))
        } else if let Some((request, reply, text)) = peer_reply {
            tx.execute(
                "DELETE FROM ongoing_peer_requests WHERE scope = ?1 AND message = ?2",
                params![thread.scope, request],
            )?;
            Some((reply, text, Source::PeerReply))
        } else if let Some((due, schedule)) = due {
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
            Some((Id::from(source), schedule.text.clone(), Source::Schedule))
        } else {
            let message = tx.query_row(
                "SELECT i.id, i.message, i.body FROM inbox i
                 JOIN channel_event_addresses e ON e.cursor = i.id AND e.outbound = 0 AND e.recipient = ?2
                 LEFT JOIN integration_events g ON g.cursor = i.id
                 WHERE substr(i.stream, 1, 32) = ?3 AND substr(i.stream, 33, 64) = ?4
                   AND i.epoch = ?5 AND i.kind = 1 AND i.body IS NOT NULL
                   AND (g.actor IS ?6 OR (hex(g.actor) IN (SELECT value FROM json_each(?7))
                       AND (trim(i.body) GLOB '/work *' OR trim(i.body) GLOB '/steer *' OR trim(i.body) GLOB '/cancel *')))
                   AND i.id > (SELECT cursor FROM ongoing_threads WHERE scope = ?1)
                 ORDER BY i.id LIMIT 1",
                params![thread.scope, self.local.encode(), thread.channel, thread.peer.encode(), thread.epoch.to_be_bytes(), thread.origin, work_control_from],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Id>(1)?, row.get::<_, String>(2)?)),
            ).optional()?;
            if let Some((cursor, source, text)) = message {
                tx.execute(
                    "UPDATE ongoing_threads SET cursor = ?2 WHERE scope = ?1",
                    params![thread.scope, cursor],
                )?;
                Some((source, text, Source::DirectMessage))
            } else {
                None
            }
        };
        let turn = if let Some((message, text, source)) = selected {
            tx.execute(
                "INSERT INTO ongoing_turns (scope, source, scheduled, input) VALUES (?1, ?2, ?3, ?4)",
                params![thread.scope, message, source == Source::Schedule, text],
            )?;
            Some(Input {
                id: tx.last_insert_rowid(),
                source,
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

    pub(crate) fn peer_pending(&self, scope: Id, now: i64) -> Result<bool> {
        self.connection.execute(
            "DELETE FROM ongoing_peer_requests WHERE scope = ?1 AND expires <= ?2",
            params![scope, now],
        )?;
        Ok(self.connection.query_row(
            "SELECT COUNT(*) >= 2 FROM ongoing_peer_requests WHERE scope = ?1",
            [scope],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn expect_peer_reply(
        &self,
        scope: Id,
        message: Id,
        peer: Id,
        expires: i64,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO ongoing_peer_requests VALUES (?1, ?2, ?3, ?4)",
            params![scope, message, peer, expires],
        )?;
        Ok(())
    }

    pub(crate) fn queue_work(&mut self, scope: Id, key: &str, instruction: &str) -> Result<Id> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = tx.query_row(
            "SELECT id, instruction = ?3 FROM ongoing_work WHERE scope = ?1 AND request_key = ?2",
            params![scope, key, instruction], |row| Ok((row.get(0)?, row.get::<_, bool>(1)?)),
        ).optional()?;
        if let Some((id, same)) = existing {
            return if same { Ok(id) } else { Err(Error::Conflict) };
        }
        let active: u32 = tx.query_row(
            "SELECT COUNT(*) FROM ongoing_work WHERE scope = ?1 AND state IN ('queued', 'running')",
            [scope],
            |row| row.get(0),
        )?;
        if active >= 2 {
            return Err(Error::Io(io::Error::other(
                "this conversation already has two active work requests",
            )));
        }
        let recent: u32 = tx.query_row(
            "SELECT COUNT(*) FROM ongoing_work WHERE scope = ?1 AND queued_at > unixepoch() - 900",
            [scope],
            |row| row.get(0),
        )?;
        if recent >= 4 {
            return Err(Error::Io(io::Error::other(
                "this conversation has reached its work rate limit",
            )));
        }
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(io::Error::other)?;
        tx.execute("INSERT INTO ongoing_work (id, scope, request_key, instruction, state) VALUES (?1, ?2, ?3, ?4, 'queued')",
            params![id, scope, key, instruction])?;
        tx.commit()?;
        Ok(id)
    }

    pub(crate) fn recover_work(&self, scope: Id) -> Result<()> {
        self.connection.execute(
            "UPDATE ongoing_work SET state = 'failed', result = 'Work ' || lower(hex(id)) || ' was interrupted.'
             WHERE scope = ?1 AND state = 'running'", [scope],
        )?;
        Ok(())
    }

    pub(crate) fn claim_work(&self, scope: Id) -> Result<Option<Work>> {
        self.connection.execute(
            "UPDATE ongoing_work SET state = 'failed', result = 'Work ' || lower(hex(id)) || ' expired in the queue.'
             WHERE scope = ?1 AND state = 'queued' AND queued_at <= unixepoch() - 900",
            [scope],
        )?;
        Ok(self.connection.query_row(
            "UPDATE ongoing_work SET state = 'running' WHERE rowid = (
                SELECT rowid FROM ongoing_work WHERE scope = ?1 AND state = 'queued' ORDER BY rowid LIMIT 1
             ) RETURNING id, instruction", [scope],
            |row| Ok(Work { id: row.get(0)?, instruction: row.get(1)? }),
        ).optional()?)
    }

    pub(crate) fn work_status(&self, scope: Id, id: Id) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT state FROM ongoing_work WHERE scope = ?1 AND id = ?2",
                params![scope, id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(crate) fn ask_work(&self, scope: Id, id: Id, feedback: &str) -> Result<bool> {
        Ok(self.connection.execute(
            "UPDATE ongoing_work SET feedback = ?3 WHERE scope = ?1 AND id = ?2 AND feedback IS NULL
             AND cancelled = 0 AND state IN ('queued', 'running')", params![scope, id, feedback],
        )? == 1)
    }

    pub(crate) fn cancel_work(&self, scope: Id, id: Id) -> Result<bool> {
        Ok(self.connection.execute(
            "UPDATE ongoing_work SET cancelled = 1,
             result = CASE WHEN state = 'queued' THEN 'Work ' || lower(hex(id)) || ' was cancelled.' ELSE NULL END,
             state = CASE WHEN state = 'queued' THEN 'cancelled' ELSE state END
             WHERE scope = ?1 AND id = ?2 AND state IN ('queued', 'running')", params![scope, id],
        )? == 1)
    }

    pub(crate) fn work_control(&mut self, id: Id) -> Result<(bool, Option<String>)> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let response = tx.query_row(
            "SELECT cancelled, feedback FROM ongoing_work WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get::<_, Option<String>>(1)?)),
        )?;
        if response.1.is_some() {
            tx.execute(
                "UPDATE ongoing_work SET feedback = NULL WHERE id = ?1",
                [id],
            )?;
        }
        tx.commit()?;
        Ok(response)
    }

    pub(crate) fn finish_work(&self, id: Id, status: &str, result: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE ongoing_work SET state = CASE WHEN cancelled THEN 'cancelled' ELSE ?2 END,
             result = CASE WHEN cancelled THEN 'Work ' || lower(hex(id)) || ' was cancelled.' ELSE ?3 END
             WHERE id = ?1 AND state = 'running'", params![id, status, result],
        )?;
        Ok(())
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
                .next_ongoing(thread, &schedules, "[]", 10)
                .unwrap()
                .is_none()
        );
        drop(store);

        let mut store = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        store.prepare_thread(thread).unwrap();
        let turn = store
            .next_ongoing(thread, &schedules, "[]", 500)
            .unwrap()
            .unwrap();
        assert!(turn.source == Source::Schedule);
        assert_eq!(turn.text, "Check in");
        assert!(
            store
                .next_ongoing(thread, &schedules, "[]", 500)
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
                .next_ongoing(thread, &schedules, "[]", 559)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .next_ongoing(thread, &schedules, "[]", 560)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn work_is_idempotent_control_is_scoped_and_results_deliver_once() {
        let dir = tempfile::tempdir().unwrap();
        let device = Device {
            account: [2; 32],
            device: [3; 32],
        };
        let mut store =
            DeliveryStore::open(&dir.path().join("delivery.db"), &[9; 32], device).unwrap();
        let thread = Thread {
            scope: [4; 32],
            channel: [5; 32],
            peer: device,
            epoch: 1,
            origin: None,
        };
        store.prepare_thread(thread).unwrap();
        let id = store
            .queue_work(thread.scope, "stable-key", "edit a file")
            .unwrap();
        assert_eq!(
            store
                .queue_work(thread.scope, "stable-key", "edit a file")
                .unwrap(),
            id
        );
        assert!(matches!(
            store.queue_work(thread.scope, "stable-key", "different"),
            Err(Error::Conflict)
        ));
        assert!(!store.ask_work([6; 32], id, "other conversation").unwrap());
        assert!(store.ask_work(thread.scope, id, "keep the API").unwrap());
        assert_eq!(store.claim_work(thread.scope).unwrap().unwrap().id, id);
        assert_eq!(
            store.work_control(id).unwrap(),
            (false, Some("keep the API".into()))
        );
        assert_eq!(store.work_control(id).unwrap(), (false, None));
        assert!(store.cancel_work(thread.scope, id).unwrap());
        store.finish_work(id, "completed", "finished").unwrap();
        let result = store.next_ongoing(thread, &[], "[]", 100).unwrap().unwrap();
        assert!(result.source == Source::WorkResult);
        assert!(result.text.ends_with("was cancelled."));
        assert!(
            store
                .next_ongoing(thread, &[], "[]", 100)
                .unwrap()
                .is_none()
        );
    }
}
