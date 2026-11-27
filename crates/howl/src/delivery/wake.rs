use std::io;

use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};

use super::{DeliveryStore, Device, Error, Id, Result, Stream, field};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum WakeState {
    Claimed = 1,
    Running = 2,
    Finished = 3,
    Cancelled = 4,
    Uncertain = 5,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WakeClaim {
    pub execution: Id,
    pub cursor: i64,
    pub message: Id,
    pub frame_digest: Id,
    pub stream: Stream,
    pub epoch: u64,
    pub target: Id,
    pub grant_generation: u64,
    pub expires_at: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WakeJob {
    pub claim: WakeClaim,
    pub text: String,
}

impl DeliveryStore {
    pub fn enable_wake_target(&mut self, channel: Id, target: Id, generation: u64) -> Result<()> {
        if generation == 0 {
            return Err(Error::WakeGrant);
        }
        let generation = generation.to_be_bytes();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        enable_target(&tx, channel, target, generation)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn enable_network_wake_target(
        &mut self,
        channel: Id,
        sender: Device,
        target: Id,
        generation: u64,
    ) -> Result<()> {
        if generation == 0 || sender == self.local {
            return Err(Error::WakeGrant);
        }
        let generation = generation.to_be_bytes();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let conflicts: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM wake_authorizations
             WHERE channel = ?1 AND target = ?2 AND generation = ?3 AND sender <> ?4)",
            params![channel, target, generation, sender.encode()],
            |row| row.get(0),
        )?;
        if conflicts {
            return Err(Error::WakeGrant);
        }
        enable_target(&tx, channel, target, generation)?;
        tx.execute(
            "INSERT INTO wake_authorizations (channel, target, sender, generation)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (channel, target) DO UPDATE
             SET sender = excluded.sender, generation = excluded.generation",
            params![channel, target, sender.encode(), generation],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn wake_sender_authorized(&self, channel: Id, sender: Device) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM wake_authorizations a JOIN wake_targets t
             ON t.channel = a.channel AND t.target = a.target AND t.generation = a.generation
             WHERE a.channel = ?1 AND a.sender = ?2 AND t.status = 1)",
            params![channel, sender.encode()],
            |row| row.get(0),
        )?)
    }

    pub fn wake_grant_generation(
        &self,
        channel: Id,
        sender: Device,
        target: Id,
    ) -> Result<Option<u64>> {
        Ok(grant_generation(&self.connection, channel, sender, target)?)
    }

    pub fn disable_wake_target(&mut self, channel: Id, target: Id, generation: u64) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE wake_targets SET status = 0 WHERE channel = ?1 AND target = ?2 AND generation = ?3",
            params![channel, target, generation.to_be_bytes()],
        )?;
        if changed == 0 {
            return Err(Error::WakeGrant);
        }
        tx.execute(
            "UPDATE wake_queue SET state = CASE state WHEN 2 THEN 5 ELSE 4 END
             WHERE state IN (0, 1, 2) AND generation = ?3 AND cursor IN (
                 SELECT id FROM inbox WHERE kind = 2 AND substr(stream, 1, 32) = ?1 AND target = ?2
             )",
            params![channel, target, generation.to_be_bytes()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn recover_wakes(&mut self) -> Result<usize> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE wake_targets SET status = 2 WHERE status = 1", [])?;
        tx.execute("UPDATE wake_queue SET state = 4 WHERE state = 1", [])?;
        let (linked, _) = recover_linked_wakes(&tx)?;
        let standalone = tx.execute("UPDATE wake_queue SET state = 5 WHERE state = 2", [])?;
        tx.commit()?;
        Ok(linked + standalone)
    }

    pub fn claim_wake(&mut self, channel: Id, target: Id, now: u64) -> Result<Option<WakeClaim>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        record_wake_time(&tx, now)?;
        let now = now.to_be_bytes();
        tx.execute(
            "UPDATE wake_queue SET state = 4 WHERE state = 0 AND cursor IN (
                 SELECT i.id FROM inbox i LEFT JOIN channels c ON c.channel = substr(i.stream, 1, 32)
                 WHERE substr(i.stream, 1, 32) = ?1 AND (c.epoch IS NULL OR i.epoch <> c.epoch OR i.expires <= ?2)
             )",
            params![channel, now],
        )?;
        let mut execution = [0; 32];
        getrandom::fill(&mut execution).map_err(io::Error::other)?;
        let claim = tx
            .query_row(
                "SELECT i.id, i.message, i.target, i.expires, i.stream, i.epoch, w.generation, i.digest
                 FROM wake_queue w JOIN inbox i ON i.id = w.cursor
                 JOIN channels c ON c.channel = substr(i.stream, 1, 32) AND c.epoch = i.epoch
                 JOIN wake_targets t ON t.channel = c.channel AND t.target = i.target
                   AND t.generation = w.generation AND t.status = 1
                 WHERE w.state = 0 AND i.kind = 2 AND t.channel = ?1 AND t.target = ?2
                   AND i.expires > ?3 AND i.body IS NOT NULL
                 ORDER BY i.id LIMIT 1",
                params![channel, target, now],
                |row| read_claim(row, execution),
            )
            .optional()?;
        if let Some(claim) = &claim {
            tx.execute(
                "UPDATE wake_queue SET state = 1, execution = ?1 WHERE cursor = ?2 AND state = 0",
                params![claim.execution, claim.cursor],
            )?;
        }
        tx.commit()?;
        Ok(claim)
    }

    pub fn preview_claimed_wake(&self, execution: Id) -> Result<Option<WakeJob>> {
        Ok(claimed_job(&self.connection, execution)?)
    }

    pub fn start_wake(
        &mut self,
        execution: Id,
        fresh_clock: impl FnOnce() -> io::Result<u64>,
        authorize: impl FnOnce(&WakeClaim) -> bool,
    ) -> Result<Option<WakeJob>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = claimed_job(&tx, execution)?;
        let authorized = job.as_ref().is_some_and(|job| authorize(&job.claim));
        let now = fresh_clock()?;
        record_wake_time(&tx, now)?;
        let job = job.filter(|job| authorized && now < job.claim.expires_at);
        let state = if job.is_some() {
            WakeState::Running
        } else {
            WakeState::Cancelled
        };
        set_claim_state(&tx, execution, state)?;
        tx.commit()?;
        Ok(job)
    }

    pub fn finish_wake(&self, execution: Id) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE wake_queue SET state = 3 WHERE execution = ?1 AND state = 2
             AND NOT EXISTS (SELECT 1 FROM budget_wakes WHERE execution = ?1)",
            [execution],
        )?;
        Ok(changed == 1)
    }

    pub fn cancel_wake(&self, execution: Id) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE wake_queue SET state = CASE state WHEN 2 THEN 5 ELSE 4 END
             WHERE execution = ?1 AND state IN (1, 2)",
            [execution],
        )?;
        Ok(changed == 1)
    }

    pub fn mark_wake_uncertain(&self, execution: Id) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE wake_queue SET state = 5 WHERE execution = ?1 AND state = 2
             AND NOT EXISTS (SELECT 1 FROM budget_wakes WHERE execution = ?1)",
            [execution],
        )?;
        Ok(changed == 1)
    }

    pub fn wake_state(&self, execution: Id) -> Result<Option<WakeState>> {
        let state = self
            .connection
            .query_row(
                "SELECT state FROM wake_queue WHERE execution = ?1",
                [execution],
                |row| match row.get::<_, i64>(0)? {
                    1 => Ok(WakeState::Claimed),
                    2 => Ok(WakeState::Running),
                    3 => Ok(WakeState::Finished),
                    4 => Ok(WakeState::Cancelled),
                    5 => Ok(WakeState::Uncertain),
                    _ => Err(rusqlite::Error::InvalidQuery),
                },
            )
            .optional()?;
        Ok(state)
    }
}

fn enable_target(tx: &Connection, channel: Id, target: Id, generation: [u8; 8]) -> Result<()> {
    let changed = tx.execute(
        "INSERT INTO wake_targets (channel, target, generation, status)
         SELECT ?1, ?2, ?3, 1 WHERE EXISTS (SELECT 1 FROM channels WHERE channel = ?1)
         ON CONFLICT (channel, target) DO UPDATE SET generation = excluded.generation, status = 1
         WHERE wake_targets.generation < excluded.generation
            OR (wake_targets.generation = excluded.generation AND wake_targets.status IN (1, 2))",
        params![channel, target, generation],
    )?;
    if changed == 0 {
        return Err(Error::WakeGrant);
    }
    tx.execute(
        "UPDATE wake_queue SET state = CASE state WHEN 2 THEN 5 ELSE 4 END
         WHERE state IN (0, 1, 2) AND generation < ?3 AND cursor IN (
             SELECT id FROM inbox WHERE kind = 2 AND substr(stream, 1, 32) = ?1 AND target = ?2
         )",
        params![channel, target, generation],
    )?;
    Ok(())
}

pub(super) fn grant_generation(
    connection: &Connection,
    channel: Id,
    sender: Device,
    target: Id,
) -> rusqlite::Result<Option<u64>> {
    connection
        .query_row(
            "SELECT a.generation FROM wake_authorizations a JOIN wake_targets t
             ON t.channel = a.channel AND t.target = a.target AND t.generation = a.generation
             WHERE a.channel = ?1 AND a.target = ?2 AND a.sender = ?3 AND t.status = 1",
            params![channel, target, sender.encode()],
            |row| Ok(u64::from_be_bytes(row.get(0)?)),
        )
        .optional()
}

pub(super) fn recover_linked_wakes(connection: &Connection) -> rusqlite::Result<(usize, usize)> {
    let wakes = connection.execute(
        "UPDATE wake_queue SET state = 5 WHERE state = 2
         AND execution IN (SELECT execution FROM budget_wakes)",
        [],
    )?;
    let turns = connection.execute(
        "UPDATE budget_turns SET state = 2 WHERE state = 1
         AND id IN (SELECT turn FROM budget_wakes)",
        [],
    )?;
    Ok((wakes, turns))
}

pub(super) fn claimed_job(
    connection: &Connection,
    execution: Id,
) -> rusqlite::Result<Option<WakeJob>> {
    connection
        .query_row(
            "SELECT i.id, i.message, i.target, i.expires, i.stream, i.epoch, w.generation, i.digest, i.body
                 FROM wake_queue w JOIN inbox i ON i.id = w.cursor
                 JOIN channels c ON c.channel = substr(i.stream, 1, 32) AND c.epoch = i.epoch
                 JOIN wake_targets t ON t.channel = c.channel AND t.target = i.target
                   AND t.generation = w.generation AND t.status = 1
                 WHERE w.execution = ?1 AND w.state = 1 AND i.kind = 2 AND i.body IS NOT NULL",
            [execution],
            |row| {
                Ok(WakeJob {
                    claim: read_claim(row, execution)?,
                    text: row.get(8)?,
                })
            },
        )
        .optional()
}

pub(super) fn set_claim_state(
    connection: &Connection,
    execution: Id,
    state: WakeState,
) -> rusqlite::Result<usize> {
    connection.execute(
        "UPDATE wake_queue SET state = ?1 WHERE execution = ?2 AND state = 1",
        params![state as i64, execution],
    )
}

pub(super) fn record_wake_time(connection: &Connection, now: u64) -> Result<()> {
    let changed = connection.execute(
        "UPDATE store SET wake_clock = ?1 WHERE wake_clock <= ?1",
        [now.to_be_bytes()],
    )?;
    if changed == 0 {
        return Err(Error::WakeClock);
    }
    Ok(())
}

fn read_claim(row: &Row<'_>, execution: Id) -> rusqlite::Result<WakeClaim> {
    let stream: [u8; 128] = row.get(4)?;
    Ok(WakeClaim {
        execution,
        cursor: row.get(0)?,
        message: row.get(1)?,
        frame_digest: row.get(7)?,
        stream: Stream {
            channel: field(&stream, 0),
            sender: Device::decode(field(&stream, 32)),
            signing_key: field(&stream, 96),
        },
        epoch: u64::from_be_bytes(row.get(5)?),
        target: row.get(2)?,
        grant_generation: u64::from_be_bytes(row.get(6)?),
        expires_at: u64::from_be_bytes(row.get(3)?),
    })
}

#[derive(serde::Serialize)]
pub(crate) struct WorkflowStatus {
    message: String,
    target: String,
    state: &'static str,
    root: Option<String>,
    paused: bool,
}

impl DeliveryStore {
    pub(crate) fn workflow_status(&self, channel: Id, now: u64) -> Result<Vec<WorkflowStatus>> {
        let mut statement = self.connection.prepare(
            "SELECT i.message, i.target, w.state, r.root, coalesce(r.paused, 0), i.expires
             FROM wake_queue w JOIN inbox i ON i.id = w.cursor
             LEFT JOIN budget_wakes a ON a.execution = w.execution
             LEFT JOIN budget_turns t ON t.id = a.turn
             LEFT JOIN budget_roots r ON r.root = t.root
             WHERE substr(i.stream, 1, 32) = ?1 ORDER BY w.cursor DESC LIMIT 100",
        )?;
        Ok(statement
            .query_map([channel], |row| {
                let state = match row.get::<_, i64>(2)? {
                    0..=2 if u64::from_be_bytes(row.get(5)?) <= now => "expired",
                    0 => "pending",
                    1 => "claimed",
                    2 => "running",
                    3 => "finished",
                    4 => "cancelled",
                    5 => "uncertain",
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok(WorkflowStatus {
                    message: hex::encode(row.get::<_, Id>(0)?),
                    target: hex::encode(row.get::<_, Id>(1)?),
                    state,
                    root: row.get::<_, Option<Id>>(3)?.map(hex::encode),
                    paused: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub(crate) fn has_workflow_root(&self, channel: Id, root: Id) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM budget_turns t
             JOIN budget_wakes a ON a.turn = t.id
             JOIN wake_queue w ON w.execution = a.execution
             JOIN inbox i ON i.id = w.cursor
             WHERE t.root = ?2 AND substr(i.stream, 1, 32) = ?1)",
            params![channel, root],
            |row| row.get(0),
        )?)
    }
}
