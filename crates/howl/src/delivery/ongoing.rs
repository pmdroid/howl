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
    pub shared: Option<Id>,
    pub sender: Id,
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

#[derive(Clone)]
pub(crate) struct WorkGrant {
    pub policy: Id,
    pub commit: String,
    pub selection: Id,
}

pub(crate) struct Work {
    pub commit: String,
    pub selection: Id,
    pub remaining: u64,
    pub id: Id,
    pub instruction: String,
}

pub(crate) struct Publication {
    pub id: i64,
    pub source: Id,
    pub result: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct Exchange {
    #[serde(skip)]
    pub(crate) id: i64,
    pub(crate) input: String,
    pub(crate) sender: String,
    pub(crate) reply: Option<String>,
}

impl Exchange {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            input: row.get(1)?,
            sender: row.get(2)?,
            reply: row.get(3)?,
        })
    }
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
        forwards_work_commands: bool,
        shared_thread: Option<(&str, Id)>,
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
            "SELECT p.message, i.message, i.body, parent.turn, c.shared, p.peer, original.input FROM ongoing_peer_requests p
             LEFT JOIN ongoing_peer_parents parent USING(scope,message)
             LEFT JOIN ongoing_turns original ON original.id = parent.turn
             LEFT JOIN ongoing_turn_context c ON c.turn = parent.turn
             JOIN agent_replies a ON a.in_reply_to = p.message
             JOIN inbox i ON i.id = a.cursor AND i.kind = 3 AND i.body IS NOT NULL
             JOIN channel_event_addresses e ON e.cursor = i.id AND e.outbound = 0 AND e.recipient = ?2
             WHERE p.scope = ?1 AND substr(i.stream, 1, 32) = ?3 AND substr(i.stream, 65, 32) = p.peer
                 AND i.epoch = ?4 AND p.expires > ?5 AND (c.shared IS NULL OR c.shared = ?6)
             ORDER BY i.id LIMIT 1", params![thread.scope, self.local.encode(), thread.channel, thread.epoch.to_be_bytes(), now,shared_thread.map(|(_,id)|id)],
            |row| Ok((row.get::<_, Id>(0)?, row.get::<_, Id>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<i64>>(3)?, row.get::<_, Option<Id>>(4)?, row.get::<_, Id>(5)?, row.get::<_, Option<String>>(6)?)),
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
        let mut parent = None;
        let mut shared = None;
        let mut sender = thread.origin.unwrap_or(thread.peer.device);
        let selected = if let Some((id, result)) = completed {
            tx.execute("UPDATE ongoing_work SET reported = 1 WHERE id = ?1", [id])?;
            Some((id, result, Source::WorkResult))
        } else if let Some((request, reply, text, original, context, peer, question)) = peer_reply {
            sender = peer;
            parent = original;
            shared = context;
            let text =
                serde_json::json!({"peer":hex::encode(sender), "reply":text, "original_question":question})
                    .to_string();
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
                "SELECT i.id, i.message, i.body, e.recipient IS NULL FROM inbox i
                 JOIN channel_event_addresses e ON e.cursor = i.id AND e.outbound = 0
                 LEFT JOIN integration_events g ON g.cursor = i.id
                 WHERE substr(i.stream, 1, 32) = ?3 AND substr(i.stream, 33, 64) = ?4
                   AND i.epoch = ?5 AND i.kind = 1 AND i.body IS NOT NULL
                   AND (e.recipient = ?2 OR (e.recipient IS NULL AND ?8 IS NOT NULL AND g.actor IS ?6 AND substr(i.body,1,length(?8)) = ?8 AND length(trim(substr(i.body,length(?8)+1))) > 0))
                   AND CASE WHEN e.recipient = ?2 AND (trim(i.body) GLOB '/work *' OR trim(i.body) GLOB '/steer *' OR trim(i.body) GLOB '/cancel *')
                       THEN (g.actor IS ?6 AND NOT ?9) OR hex(g.actor) IN (SELECT value FROM json_each(?7))
                       ELSE g.actor IS ?6 END
                   AND i.id > (SELECT cursor FROM ongoing_threads WHERE scope = ?1)
                 ORDER BY i.id LIMIT 1",
                params![thread.scope, self.local.encode(), thread.channel, thread.peer.encode(), thread.epoch.to_be_bytes(), thread.origin, work_control_from, shared_thread.map(|(name,_)| format!("@{name} ")), forwards_work_commands],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Id>(1)?, row.get::<_, String>(2)?,row.get::<_,bool>(3)?)),
            ).optional()?;
            if let Some((cursor, source, text, channel_post)) = message {
                tx.execute(
                    "UPDATE ongoing_threads SET cursor = ?2 WHERE scope = ?1",
                    params![thread.scope, cursor],
                )?;
                if channel_post {
                    shared = shared_thread.map(|(_, id)| id);
                }
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
            let id = tx.last_insert_rowid();
            if source == Source::DirectMessage
                && let Some((name, context)) = shared_thread
                && text
                    .strip_prefix("/thread ")
                    .and_then(|body| body.split_once(' '))
                    .is_some_and(|(topic, question)| topic == name && !question.trim().is_empty())
            {
                shared = Some(context);
            }
            tx.execute(
                "INSERT INTO ongoing_turn_context (turn, shared, parent, sender) VALUES (?1, ?2, ?3, ?4)",
                params![id, shared, parent, sender],
            )?;
            Some(Input {
                id,
                shared,
                sender,
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

    pub(crate) fn ongoing_history(
        &self,
        scope: Id,
        before: i64,
        shared: Option<Id>,
    ) -> Result<Vec<Exchange>> {
        let mut statement = self.connection.prepare(
            "SELECT id, input, sender, result FROM ongoing_history
             WHERE (scope = ?1 OR ?3 IS NOT NULL) AND shared IS ?3 AND id < ?2
             ORDER BY id DESC LIMIT 8",
        )?;
        let mut history = statement
            .query_map(params![scope, before, shared], Exchange::from_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        history.reverse();
        Ok(history)
    }

    pub(crate) fn ongoing_history_page(
        &self,
        scope: Id,
        shared: Option<Id>,
        after: i64,
        before: i64,
    ) -> Result<Vec<Exchange>> {
        let mut statement = self.connection.prepare(
            "SELECT id, input, sender, result FROM ongoing_history
             WHERE (scope = ?1 OR ?2 IS NOT NULL) AND shared IS ?2 AND id > ?3 AND id < ?4
             ORDER BY id LIMIT 32",
        )?;
        Ok(statement
            .query_map(params![scope, shared, after, before], Exchange::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub(crate) fn ongoing_checkpoint(
        &self,
        scope: Id,
        shared: Option<Id>,
        before: i64,
    ) -> Result<Option<(i64, String)>> {
        Ok(self
            .connection
            .query_row(
                "SELECT through_turn, summary FROM ongoing_checkpoints
             WHERE audience = ?1 AND is_shared = ?2 AND through_turn < ?3
             ORDER BY through_turn DESC LIMIT 1",
                params![shared.unwrap_or(scope), shared.is_some(), before],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub(crate) fn save_ongoing_checkpoint(
        &self,
        scope: Id,
        shared: Option<Id>,
        before: i64,
        expected: i64,
        through: i64,
        summary: &str,
    ) -> Result<bool> {
        if through <= expected || through >= before || summary.trim().is_empty() {
            return Ok(false);
        }
        let saved = self.connection.execute(
            "INSERT INTO ongoing_checkpoints(audience, is_shared, through_turn, summary)
             SELECT ?1, ?2, ?3, ?4
             WHERE ?5 = (SELECT coalesce(max(through_turn), 0) FROM ongoing_checkpoints
                         WHERE audience = ?1 AND is_shared = ?2)
               AND EXISTS (SELECT 1 FROM ongoing_history WHERE id = ?3
                           AND (scope = ?6 OR ?7 IS NOT NULL) AND shared IS ?7)
               AND NOT EXISTS (SELECT 1 FROM ongoing_history WHERE id > ?5 AND id <= ?3
                               AND (scope = ?6 OR ?7 IS NOT NULL) AND shared IS ?7 AND finished = 0)",
            params![shared.unwrap_or(scope), shared.is_some(), through, summary, expected, scope, shared],
        )?;
        Ok(saved == 1)
    }

    pub(crate) fn pending_ongoing(&self, scope: Id) -> Result<Option<Publication>> {
        Ok(self.connection.query_row(
            "SELECT t.id, coalesce(p.source,t.source), t.result FROM ongoing_turns t LEFT JOIN ongoing_turn_context c ON c.turn=t.id LEFT JOIN ongoing_turns p ON p.id=c.parent WHERE t.scope = ?1 AND t.sent IS NULL AND t.result IS NOT NULL ORDER BY t.id LIMIT 1",
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
        &mut self,
        scope: Id,
        message: Id,
        peer: Id,
        expires: i64,
        turn: i64,
    ) -> Result<()> {
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO ongoing_peer_requests VALUES (?1, ?2, ?3, ?4)",
            params![scope, message, peer, expires],
        )?;
        tx.execute(
            "INSERT INTO ongoing_peer_parents VALUES (?1, ?2, ?3)",
            params![scope, message, turn],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn queue_work(
        &mut self,
        scope: Id,
        key: &str,
        instruction: &str,
        grant: &WorkGrant,
    ) -> Result<Id> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = tx.query_row(
            "SELECT id, instruction = ?3 AND (state IN ('completed','failed','cancelled') OR EXISTS (
                 SELECT 1 FROM ongoing_work_grants WHERE run = id AND policy = ?4
             )) FROM ongoing_work WHERE scope = ?1 AND request_key = ?2",
            params![scope, key, instruction, grant.policy], |row| Ok((row.get(0)?, row.get::<_, bool>(1)?)),
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
        tx.execute("INSERT INTO ongoing_work_grants(run, policy, revision, selection) VALUES (?1, ?2, ?3, ?4)",
            params![id, grant.policy, grant.commit, grant.selection])?;
        tx.commit()?;
        Ok(id)
    }

    pub(crate) fn recover_work(&mut self, policies: &[Id]) -> Result<()> {
        let allowed = serde_json::to_string(&policies.iter().map(hex::encode).collect::<Vec<_>>())
            .map_err(io::Error::other)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE ongoing_work SET state = 'cancelled', cancelled = 1,
            result = 'Work ' || lower(hex(id)) || ' authorization was revoked.'
            WHERE state IN ('queued','running') AND NOT EXISTS (
                SELECT 1 FROM ongoing_work_grants WHERE run = id AND lower(hex(policy)) IN (SELECT value FROM json_each(?1))
            )", [allowed])?;
        tx.execute("UPDATE ongoing_work SET state = CASE WHEN cancelled THEN 'cancelled' ELSE 'failed' END,
            result = 'Work ' || lower(hex(id)) || CASE WHEN cancelled THEN ' was cancelled.' ELSE ' was interrupted.' END
            WHERE state = 'running'", [])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn claim_work(&mut self, scope: Id, policy: Id) -> Result<Option<Work>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE ongoing_work SET state = 'failed', result = 'Work ' || lower(hex(id)) || ' expired in the queue.'
             WHERE scope = ?1 AND state = 'queued' AND queued_at <= unixepoch() - 900",
            [scope],
        )?;
        let work = tx
            .query_row(
                "SELECT id, instruction, revision, selection, queued_at + 900 - unixepoch()
             FROM ongoing_work JOIN ongoing_work_grants ON id = run
             WHERE scope = ?1 AND policy = ?2 AND state = 'queued' AND queued_at + 900 > unixepoch()
             ORDER BY ongoing_work.rowid LIMIT 1",
                params![scope, policy],
                |row| {
                    Ok(Work {
                        id: row.get(0)?,
                        instruction: row.get(1)?,
                        commit: row.get(2)?,
                        selection: row.get(3)?,
                        remaining: u64::from(row.get::<_, u32>(4)?),
                    })
                },
            )
            .optional()?;
        if let Some(job) = &work {
            tx.execute(
                "UPDATE ongoing_work SET state = 'running' WHERE id = ?1",
                [job.id],
            )?;
        }
        tx.commit()?;
        Ok(work)
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
            "SELECT cancelled, feedback FROM ongoing_work WHERE id = ?1 AND state = 'running' AND queued_at + 900 > unixepoch()",
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

    pub(crate) fn finish_work(
        &mut self,
        id: Id,
        publish: impl FnOnce() -> io::Result<String>,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active = tx.query_row(
            "SELECT cancelled, queued_at + 900 <= unixepoch() FROM ongoing_work WHERE id = ?1 AND state = 'running'",
            [id], |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
        ).optional()?;
        let run = hex::encode(id);
        let (state, result) = match active {
            None => return Ok(()),
            Some((true, _)) => ("cancelled", format!("Work {run} was cancelled.")),
            Some((false, true)) => ("failed", format!("Work {run} expired.")),
            Some((false, false)) => match publish() {
                Ok(reply) => ("completed", format!("Work {run} completed. {reply}")),
                Err(error) => {
                    eprintln!("Howl microVM work {run} ended. {error}");
                    ("failed", format!("Work {run} ended before completion."))
                }
            },
        };
        tx.execute(
            "UPDATE ongoing_work SET state = ?2, result = ?3 WHERE id = ?1",
            params![id, state, result],
        )?;
        tx.commit()?;
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
        "SELECT t.sent FROM ongoing_turns t JOIN ongoing_threads s ON s.scope = t.scope LEFT JOIN ongoing_turn_context c ON c.turn=t.id LEFT JOIN ongoing_turns p ON p.id=c.parent
         WHERE t.id = ?1 AND coalesce(p.source,t.source) = ?2 AND t.result = ?3
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
    fn checkpoints_advance_over_finished_turns_in_their_own_audience() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.db");
        let local = Device {
            account: [1; 32],
            device: [2; 32],
        };
        let first = Thread {
            scope: [3; 32],
            channel: [4; 32],
            peer: local,
            epoch: 1,
            origin: None,
        };
        let second = Thread {
            scope: [5; 32],
            ..first
        };
        let shared = Some(first.scope);
        let store = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        store.prepare_thread(first).unwrap();
        store.prepare_thread(second).unwrap();
        let mut shared_turns = Vec::new();
        for number in 1..=38u8 {
            let scope = if number % 2 == 0 {
                first.scope
            } else {
                second.scope
            };
            let pending = number == 4;
            store
                .connection
                .execute(
                    "INSERT INTO ongoing_turns(scope, source, scheduled, input, finished, result)
                 VALUES (?1, ?2, 0, ?3, ?4, ?5)",
                    params![
                        scope,
                        [number; 32],
                        number.to_string(),
                        !pending,
                        (!pending).then_some("answered")
                    ],
                )
                .unwrap();
            let id = store.connection.last_insert_rowid();
            if number > 2 {
                store.connection.execute(
                    "INSERT INTO ongoing_turn_context(turn, shared, sender) VALUES (?1, ?2, ?3)",
                    params![id, shared, local.device],
                ).unwrap();
                shared_turns.push(id);
            }
        }
        let page = store
            .ongoing_history_page(first.scope, shared, 0, i64::MAX)
            .unwrap();
        assert_eq!(page.len(), 32);
        assert_eq!(page[0].input, "3");
        assert_eq!(page[1].reply, None);
        assert_eq!(page[31].id, shared_turns[31]);
        let rest = store
            .ongoing_history_page(second.scope, shared, page[31].id, i64::MAX)
            .unwrap();
        assert_eq!(rest.len(), 4);
        assert_eq!(rest[3].input, "38");
        assert_eq!(
            store
                .ongoing_history_page(first.scope, None, 0, i64::MAX)
                .unwrap()[0]
                .input,
            "2"
        );
        let summary = |expected, through, text| {
            store
                .save_ongoing_checkpoint(first.scope, shared, i64::MAX, expected, through, text)
                .unwrap()
        };
        assert!(!summary(
            0,
            shared_turns[2],
            "would swallow a pending question"
        ));
        assert!(!summary(0, 2, "private endpoint"));
        let cut = shared_turns[0];
        assert!(summary(0, cut, "first"));
        assert!(
            store
                .ongoing_checkpoint(first.scope, None, i64::MAX)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .save_ongoing_checkpoint(first.scope, None, i64::MAX, 0, 2, "private")
                .unwrap()
        );
        assert!(
            store
                .ongoing_checkpoint(second.scope, None, i64::MAX)
                .unwrap()
                .is_none()
        );
        store
            .finish_ongoing(shared_turns[1], "later answer", true)
            .unwrap();
        let next = shared_turns[2];
        assert!(summary(cut, next, "second"));
        assert!(!summary(cut, shared_turns[3], "stale writer"));
        assert!(
            !store
                .save_ongoing_checkpoint(
                    first.scope,
                    shared,
                    shared_turns[3],
                    next,
                    shared_turns[3],
                    "future"
                )
                .unwrap()
        );
        drop(store);
        let reopened = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        assert_eq!(
            reopened
                .ongoing_checkpoint(second.scope, shared, next)
                .unwrap(),
            Some((cut, "first".into()))
        );
        assert_eq!(
            reopened
                .ongoing_checkpoint(second.scope, shared, next + 1)
                .unwrap(),
            Some((next, "second".into()))
        );
        assert_eq!(
            reopened
                .ongoing_history_page(first.scope, shared, 0, next)
                .unwrap()
                .len(),
            2
        );
    }

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
                .next_ongoing(thread, &schedules, "[]", false, None, 10)
                .unwrap()
                .is_none()
        );
        drop(store);

        let mut store = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        store.prepare_thread(thread).unwrap();
        let turn = store
            .next_ongoing(thread, &schedules, "[]", false, None, 500)
            .unwrap()
            .unwrap();
        assert!(turn.source == Source::Schedule);
        assert_eq!(turn.text, "Check in");
        assert!(
            store
                .next_ongoing(thread, &schedules, "[]", false, None, 500)
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
                .next_ongoing(thread, &schedules, "[]", false, None, 559)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .next_ongoing(thread, &schedules, "[]", false, None, 560)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn delayed_peer_replies_keep_the_original_question_and_audience() {
        let dir = tempfile::tempdir().unwrap();
        let local = Device {
            account: [1; 32],
            device: [2; 32],
        };
        let thread = Thread {
            scope: [3; 32],
            channel: [4; 32],
            peer: local,
            epoch: 1,
            origin: None,
        };
        let shared = [8; 32];
        let mut store = DeliveryStore::open(&dir.path().join("test.db"), &[1; 32], local).unwrap();
        store.prepare_thread(thread).unwrap();
        for index in 1..=2u8 {
            let message = [index; 32];
            store.connection.execute("INSERT INTO ongoing_turns(scope,source,scheduled,input,finished,result,sent) VALUES (?1,?2,0,?3,1,'queued',?2)",params![thread.scope,message,format!("question {index}")]).unwrap();
            let parent = store.connection.last_insert_rowid();
            store
                .connection
                .execute(
                    "INSERT INTO ongoing_turn_context(turn,shared,sender) VALUES (?1,?2,?3)",
                    params![parent, shared, local.device],
                )
                .unwrap();
            store
                .expect_peer_reply(
                    thread.scope,
                    [index + 10; 32],
                    [index + 20; 32],
                    100,
                    parent,
                )
                .unwrap();
        }
        for index in [2, 1] {
            let peer = [index + 20; 32];
            let stream = super::super::Stream {
                channel: thread.channel,
                sender: Device {
                    account: local.account,
                    device: peer,
                },
                signing_key: [0; 32],
            }
            .encode();
            store.connection.execute("INSERT INTO inbox(stream,message,sequence,epoch,received,expires,digest,kind,body) VALUES (?1,?2,x'01',?3,x'00',x'00',x'00',3,'answer')",params![stream,[index+30;32],thread.epoch.to_be_bytes()]).unwrap();
            let cursor = store.connection.last_insert_rowid();
            store
                .connection
                .execute(
                    "INSERT INTO channel_event_addresses VALUES (?1,0,?2)",
                    params![cursor, local.encode()],
                )
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO agent_replies VALUES (?1,?2,1,?3,?2)",
                    params![cursor, peer, [index + 10; 32]],
                )
                .unwrap();
            assert!(
                store
                    .next_ongoing(thread, &[], "[]", false, Some(("changed", [9; 32])), 50)
                    .unwrap()
                    .is_none()
            );
            let input = store
                .next_ongoing(thread, &[], "[]", false, Some(("review", shared)), 50)
                .unwrap()
                .unwrap();
            assert_eq!(input.sender, peer);
            assert_eq!(input.shared, Some(shared));
            assert!(input.text.contains(&format!("question {index}")));
            store.finish_ongoing(input.id, "answered", true).unwrap();
            let reply = store.pending_ongoing(thread.scope).unwrap().unwrap();
            assert_eq!(reply.source, [index; 32]);
            publish(&store.connection, reply.id, [index + 40; 32]).unwrap();
        }
        assert!(
            store
                .ongoing_history(thread.scope, i64::MAX, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn worker_grants_survive_matching_policy_and_expire_from_issue_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.db");
        let local = Device {
            account: [1; 32],
            device: [2; 32],
        };
        let thread = Thread {
            scope: [3; 32],
            channel: [4; 32],
            peer: local,
            epoch: 1,
            origin: None,
        };
        let grant = WorkGrant {
            policy: [5; 32],
            commit: "a".repeat(40),
            selection: [6; 32],
        };
        let mut store = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        store.prepare_thread(thread).unwrap();
        let id = store
            .queue_work(thread.scope, "first", "build", &grant)
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE ongoing_work SET queued_at = unixepoch() - 850 WHERE id = ?1",
                [id],
            )
            .unwrap();
        drop(store);
        let mut store = DeliveryStore::open(&path, &[9; 32], local).unwrap();
        store.recover_work(&[grant.policy]).unwrap();
        let revised = WorkGrant {
            commit: "b".repeat(40),
            ..grant.clone()
        };
        assert_eq!(
            store
                .queue_work(thread.scope, "first", "build", &revised)
                .unwrap(),
            id
        );
        let work = store
            .claim_work(thread.scope, grant.policy)
            .unwrap()
            .unwrap();
        assert_eq!(work.id, id);
        assert_eq!(work.commit, grant.commit);
        assert_eq!(work.selection, grant.selection);
        assert!((1..=50).contains(&work.remaining));
        store
            .connection
            .execute(
                "UPDATE ongoing_work SET queued_at = unixepoch() - 900 WHERE id = ?1",
                [id],
            )
            .unwrap();
        assert!(store.work_control(id).is_err());
        store
            .finish_work(id, || panic!("expired work published"))
            .unwrap();
        assert_eq!(
            store.work_status(thread.scope, id).unwrap().as_deref(),
            Some("failed")
        );
        let id2 = store
            .queue_work(thread.scope, "second", "build", &grant)
            .unwrap();
        let other = store
            .queue_work(thread.scope, "third", "build", &grant)
            .unwrap();
        assert!(
            store
                .queue_work(thread.scope, "fourth", "build", &grant)
                .is_err()
        );
        assert!(!store.cancel_work([7; 32], other).unwrap());
        assert!(store.cancel_work(thread.scope, other).unwrap());
        let fourth = store
            .queue_work(thread.scope, "fourth", "build", &grant)
            .unwrap();
        assert!(store.cancel_work(thread.scope, fourth).unwrap());
        let fifth = store
            .queue_work(thread.scope, "fifth", "build", &grant)
            .unwrap();
        assert!(store.cancel_work(thread.scope, fifth).unwrap());
        assert!(
            store
                .queue_work(thread.scope, "sixth", "build", &grant)
                .is_err()
        );
        let legacy = [10; 32];
        store
            .connection
            .execute(
                "INSERT INTO ongoing_work(id,scope,request_key,instruction,state)
            VALUES (?1,?2,'legacy','build','queued')",
                params![legacy, thread.scope],
            )
            .unwrap();
        store.recover_work(&[grant.policy]).unwrap();
        assert_eq!(
            store.work_status(thread.scope, legacy).unwrap().as_deref(),
            Some("cancelled")
        );
        store.recover_work(&[[8; 32]]).unwrap();
        assert_eq!(
            store.work_status(thread.scope, id2).unwrap().as_deref(),
            Some("cancelled")
        );
        assert!(
            store
                .claim_work(thread.scope, grant.policy)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn delegated_commands_and_integration_chat_reach_separate_conversations() {
        let dir = tempfile::tempdir().unwrap();
        let local = Device {
            account: [1; 32],
            device: [2; 32],
        };
        let owner = Thread {
            scope: [3; 32],
            channel: [4; 32],
            peer: local,
            epoch: 1,
            origin: None,
        };
        let actor = [5_u8; 32];
        let bot = Thread {
            scope: [6; 32],
            origin: Some(actor),
            ..owner
        };
        let mut store = DeliveryStore::open(&dir.path().join("db"), &[9; 32], local).unwrap();
        store.prepare_thread(owner).unwrap();
        store.prepare_thread(bot).unwrap();
        let stream = super::super::Stream {
            channel: owner.channel,
            sender: local,
            signing_key: [7; 32],
        }
        .encode();
        for (sequence, body, sender) in [
            (1u8, "/steer run change", actor),
            (2, "chat", actor),
            (3, "/cancel run", [8; 32]),
        ] {
            store.connection.execute(
                "INSERT INTO inbox(stream,message,sequence,epoch,received,expires,digest,kind,body)
                 VALUES (?1,?2,?3,?4,x'00',x'00',x'00',1,?5)",
                params![stream,[sequence;32],[sequence],owner.epoch.to_be_bytes(),body],
            ).unwrap();
            let cursor = store.connection.last_insert_rowid();
            store
                .connection
                .execute(
                    "INSERT INTO channel_event_addresses VALUES (?1,0,?2)",
                    params![cursor, local.encode()],
                )
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO integration_events VALUES (?1,?2)",
                    params![cursor, sender],
                )
                .unwrap();
        }
        let delegates = serde_json::to_string(&[hex::encode_upper(actor)]).unwrap();
        for (thread, delegates, forwarded, expected) in [
            (bot, "[]", true, "chat"),
            (owner, delegates.as_str(), false, "/steer run change"),
        ] {
            let read = |store: &mut DeliveryStore| {
                store
                    .next_ongoing(thread, &[], delegates, forwarded, None, 10)
                    .unwrap()
            };
            assert_eq!(read(&mut store).unwrap().text, expected);
            assert!(read(&mut store).is_none());
        }
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
        let grant = WorkGrant {
            policy: [7; 32],
            commit: "a".repeat(40),
            selection: [8; 32],
        };
        let id = store
            .queue_work(thread.scope, "stable-key", "edit a file", &grant)
            .unwrap();
        assert_eq!(
            store
                .queue_work(thread.scope, "stable-key", "edit a file", &grant)
                .unwrap(),
            id
        );
        assert!(matches!(
            store.queue_work(thread.scope, "stable-key", "different", &grant),
            Err(Error::Conflict)
        ));
        assert!(!store.ask_work([6; 32], id, "other conversation").unwrap());
        assert!(store.ask_work(thread.scope, id, "keep the API").unwrap());
        assert_eq!(
            store
                .claim_work(thread.scope, grant.policy)
                .unwrap()
                .unwrap()
                .id,
            id
        );
        assert_eq!(
            store.work_control(id).unwrap(),
            (false, Some("keep the API".into()))
        );
        assert_eq!(store.work_control(id).unwrap(), (false, None));
        assert!(store.cancel_work(thread.scope, id).unwrap());
        store
            .finish_work(id, || panic!("cancelled work published"))
            .unwrap();
        let result = store
            .next_ongoing(thread, &[], "[]", false, None, 100)
            .unwrap()
            .unwrap();
        assert!(result.source == Source::WorkResult);
        assert!(result.text.ends_with("was cancelled."));
        assert!(
            store
                .next_ongoing(thread, &[], "[]", false, None, 100)
                .unwrap()
                .is_none()
        );
    }
}
