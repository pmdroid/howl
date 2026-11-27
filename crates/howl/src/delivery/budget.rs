mod approved_wake;
pub use approved_wake::{ApprovedWake, WakeApproval, WakeOutcome, WakeTurnError};

use std::io;

use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{DeliveryStore, Device, Id, wake::recover_linked_wakes};

type Result<T> = std::result::Result<T, BudgetError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetLimits {
    pub turns: u32,
    pub concurrent: u32,
    pub depth: u32,
    pub fan_out: u32,
    pub cooldown_seconds: u64,
    pub rate_turns: u32,
    pub rate_window_seconds: u64,
    pub lifetime_seconds: u64,
}

impl BudgetLimits {
    fn encode(self) -> Vec<u8> {
        [
            u64::from(self.turns),
            u64::from(self.concurrent),
            u64::from(self.depth),
            u64::from(self.fan_out),
            self.cooldown_seconds,
            u64::from(self.rate_turns),
            self.rate_window_seconds,
            self.lifetime_seconds,
        ]
        .into_iter()
        .flat_map(u64::to_be_bytes)
        .collect()
    }

    fn valid(self) -> bool {
        self.turns > 0
            && self.concurrent > 0
            && self.rate_turns > 0
            && self.rate_window_seconds > 0
            && self.lifetime_seconds > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetLimit {
    Turns,
    Concurrent,
    Depth,
    FanOut,
    Cooldown,
    Rate,
    Lifetime,
    Paused,
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("invalid or mismatched conversation budget policy")]
    Policy,
    #[error("conversation budget clock moved backward")]
    Clock,
    #[error("invalid or expired human budget command")]
    Human,
    #[error("human budget command was already applied")]
    Replay,
    #[error("conversation root or causal turn was not found")]
    Unknown,
    #[error("agent has no authority for this causal turn")]
    Cause,
    #[error("conversation budget exhausted: {0:?}")]
    Limit(BudgetLimit),
    #[error("conversation budget storage failed")]
    Storage(#[from] rusqlite::Error),
    #[error("conversation budget entropy unavailable")]
    Randomness(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HumanAction {
    Begin { agent: Id },
    Continue { cause: Id, agent: Id },
    Pause { root: Id },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanCommand {
    pub nonce: Id,
    pub expires_at: u64,
    pub action: HumanAction,
}

impl HumanCommand {
    pub fn signing_bytes(&self, node: Device) -> Vec<u8> {
        let mut bytes = b"howl/local-conversation-budget/v1\0".to_vec();
        bytes.extend_from_slice(&node.encode());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        match self.action {
            HumanAction::Begin { agent } => {
                bytes.push(1);
                bytes.extend_from_slice(&agent);
            }
            HumanAction::Continue { cause, agent } => {
                bytes.push(2);
                bytes.extend_from_slice(&cause);
                bytes.extend_from_slice(&agent);
            }
            HumanAction::Pause { root } => {
                bytes.push(3);
                bytes.extend_from_slice(&root);
            }
        }
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Turn {
    pub id: Id,
    pub root: Id,
    pub cause: Option<Id>,
    pub agent: Id,
    pub hop: u32,
    pub expires_at: u64,
}

pub struct ConversationBudget<'a> {
    connection: &'a mut Connection,
    node: Device,
    limits: BudgetLimits,
    human: VerifyingKey,
}

impl DeliveryStore {
    pub fn conversation_budget(
        &mut self,
        limits: BudgetLimits,
        human: VerifyingKey,
    ) -> Result<ConversationBudget<'_>> {
        if !limits.valid() || human.is_weak() {
            return Err(BudgetError::Policy);
        }
        let encoded = limits.encode();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO budget_policy(singleton, human_key, limits) VALUES (1, ?1, ?2)",
            params![human.as_bytes(), encoded],
        )?;
        let matches = tx.query_row(
            "SELECT human_key = ?1 AND limits = ?2 FROM budget_policy WHERE singleton = 1",
            params![human.as_bytes(), encoded],
            |row| row.get::<_, bool>(0),
        )?;
        if !matches {
            return Err(BudgetError::Policy);
        }
        tx.commit()?;
        Ok(ConversationBudget {
            connection: &mut self.connection,
            node: self.local,
            limits,
            human,
        })
    }
}

impl ConversationBudget<'_> {
    pub fn apply_human(
        &mut self,
        command: HumanCommand,
        signature: &[u8; 64],
        now: u64,
    ) -> Result<Option<Turn>> {
        self.human
            .verify_strict(
                &command.signing_bytes(self.node),
                &Signature::from_bytes(signature),
            )
            .map_err(|_| BudgetError::Human)?;
        let limits = self.limits;
        if command.nonce == [0; 32] {
            return Err(BudgetError::Human);
        }
        let tx = match command.action {
            HumanAction::Pause { .. } if command.expires_at == 0 => self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?,
            HumanAction::Begin { .. } | HumanAction::Continue { .. }
                if command.expires_at > now =>
            {
                self.decision(now)?
            }
            _ => return Err(BudgetError::Human),
        };
        record_control(&tx, command.nonce)?;

        let admitted = match command.action {
            HumanAction::Begin { agent } => Some(begin_human(&tx, limits, now, agent)?),
            HumanAction::Continue { cause, agent } => {
                Some(continue_human(&tx, limits, now, cause, agent)?)
            }
            HumanAction::Pause { root } => {
                if tx.execute("UPDATE budget_roots SET paused = 1 WHERE root = ?1", [root])? == 0 {
                    return Err(BudgetError::Unknown);
                }
                None
            }
        };
        tx.commit()?;
        Ok(admitted)
    }

    pub fn begin_child(&mut self, cause: Id, actor: Id, agent: Id, now: u64) -> Result<Turn> {
        let limits = self.limits;
        let tx = self.decision(now)?;
        let base = read_turn(&tx, cause)?;
        if base.agent != actor || base.state == 2 {
            return Err(BudgetError::Cause);
        }
        let turn = admit_turn(&tx, limits, now, base.root, Some(base), agent)?;
        tx.commit()?;
        Ok(turn)
    }

    pub fn may_run(&mut self, turn: Id, now: u64) -> Result<()> {
        let tx = self.decision(now)?;
        let turn = read_turn(&tx, turn)?;
        if turn.state != 1 {
            return Err(BudgetError::Cause);
        }
        read_root(&tx, turn.root, now)?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish_turn(&self, turn: Id) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE budget_turns SET state = 0 WHERE id = ?1 AND state = 1
             AND NOT EXISTS (SELECT 1 FROM budget_wakes WHERE turn = ?1)",
            [turn],
        )?;
        Ok(changed == 1)
    }

    pub fn recover_turns(&self) -> Result<usize> {
        let tx = Transaction::new_unchecked(self.connection, TransactionBehavior::Immediate)?;
        let (_, linked) = recover_linked_wakes(&tx)?;
        let standalone = tx.execute("UPDATE budget_turns SET state = 2 WHERE state = 1", [])?;
        tx.commit()?;
        Ok(linked + standalone)
    }

    fn decision(&mut self, now: u64) -> Result<Transaction<'_>> {
        record_budget_time(self.connection, now)?;
        let now = now.to_be_bytes();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = tx.query_row(
            "SELECT clock <= ?1 FROM budget_policy WHERE singleton = 1",
            [now],
            |row| row.get::<_, bool>(0),
        )?;
        if !current {
            return Err(BudgetError::Clock);
        }
        Ok(tx)
    }
}

fn record_budget_time(connection: &Connection, now: u64) -> Result<()> {
    let advanced = connection.execute(
        "UPDATE budget_policy SET clock = ?1 WHERE singleton = 1 AND (clock IS NULL OR clock <= ?1)",
        [now.to_be_bytes()],
    )?;
    if advanced == 0 {
        return Err(BudgetError::Clock);
    }
    Ok(())
}

fn record_control(connection: &Connection, nonce: Id) -> Result<()> {
    let saved = connection.execute(
        "INSERT OR IGNORE INTO budget_controls(nonce) VALUES (?1)",
        [nonce],
    )?;
    if saved == 0 {
        return Err(BudgetError::Replay);
    }
    Ok(())
}

fn begin_human(tx: &Connection, limits: BudgetLimits, now: u64, agent: Id) -> Result<Turn> {
    let root = random_id()?;
    let expires_at = now
        .checked_add(limits.lifetime_seconds)
        .ok_or(BudgetError::Limit(BudgetLimit::Lifetime))?;
    tx.execute(
        "INSERT INTO budget_roots(root, expires, ceiling) VALUES (?1, ?2, ?3)",
        params![root, expires_at.to_be_bytes(), limits.turns],
    )?;
    admit_turn(tx, limits, now, root, None, agent)
}

fn continue_human(
    tx: &Connection,
    limits: BudgetLimits,
    now: u64,
    cause: Id,
    agent: Id,
) -> Result<Turn> {
    let base = read_turn(tx, cause)?;
    let root = read_root(tx, base.root, now)?;
    let ceiling = root
        .ceiling
        .checked_add(limits.turns)
        .ok_or(BudgetError::Limit(BudgetLimit::Turns))?;
    tx.execute(
        "UPDATE budget_roots SET ceiling = ?2 WHERE root = ?1",
        params![base.root, ceiling],
    )?;
    admit_turn(tx, limits, now, base.root, Some(base), agent)
}

struct Root {
    ceiling: u32,
    expires_at: u64,
}

fn read_root(tx: &Connection, root: Id, now: u64) -> Result<Root> {
    let (ceiling, expires, paused): (u32, [u8; 8], bool) = tx
        .query_row(
            "SELECT ceiling, expires, paused FROM budget_roots WHERE root = ?1",
            [root],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(BudgetError::Unknown)?;
    let expires_at = u64::from_be_bytes(expires);
    if paused {
        return Err(BudgetError::Limit(BudgetLimit::Paused));
    }
    if now >= expires_at {
        return Err(BudgetError::Limit(BudgetLimit::Lifetime));
    }
    Ok(Root {
        ceiling,
        expires_at,
    })
}

struct Cause {
    id: Id,
    root: Id,
    agent: Id,
    hop: u32,
    state: u8,
}

fn read_turn(tx: &Connection, id: Id) -> Result<Cause> {
    tx.query_row(
        "SELECT root, agent, hop, state FROM budget_turns WHERE id = ?1",
        [id],
        |row| {
            Ok(Cause {
                id,
                root: row.get(0)?,
                agent: row.get(1)?,
                hop: row.get(2)?,
                state: row.get(3)?,
            })
        },
    )
    .optional()?
    .ok_or(BudgetError::Unknown)
}

fn admit_turn(
    tx: &Connection,
    limits: BudgetLimits,
    now: u64,
    root: Id,
    parent: Option<Cause>,
    agent: Id,
) -> Result<Turn> {
    let active_root = read_root(tx, root, now)?;
    let (cause, hop) = if let Some(parent) = parent {
        if parent.hop >= limits.depth {
            return Err(BudgetError::Limit(BudgetLimit::Depth));
        }
        check_count(
            tx,
            "SELECT count(*) FROM budget_turns WHERE cause = ?1",
            [parent.id],
            limits.fan_out,
            BudgetLimit::FanOut,
        )?;
        (Some(parent.id), parent.hop + 1)
    } else {
        (None, 0)
    };

    check_count(
        tx,
        "SELECT count(*) FROM budget_turns WHERE root = ?1",
        [root],
        active_root.ceiling,
        BudgetLimit::Turns,
    )?;
    check_count(
        tx,
        "SELECT count(*) FROM budget_turns WHERE state = 1",
        [],
        limits.concurrent,
        BudgetLimit::Concurrent,
    )?;
    let window_start = now.saturating_sub(limits.rate_window_seconds - 1);
    check_count(
        tx,
        "SELECT count(*) FROM budget_turns WHERE started >= ?1",
        [window_start.to_be_bytes()],
        limits.rate_turns,
        BudgetLimit::Rate,
    )?;
    let last: Option<[u8; 8]> = tx
        .query_row(
            "SELECT started FROM budget_turns WHERE agent = ?1 ORDER BY started DESC LIMIT 1",
            [agent],
            |row| row.get(0),
        )
        .optional()?;
    if last
        .is_some_and(|last| now.saturating_sub(u64::from_be_bytes(last)) < limits.cooldown_seconds)
    {
        return Err(BudgetError::Limit(BudgetLimit::Cooldown));
    }

    let id = random_id()?;
    tx.execute(
        "INSERT INTO budget_turns (id, root, cause, agent, hop, started) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, root, cause, agent, hop, now.to_be_bytes()],
    )?;
    Ok(Turn {
        id,
        root,
        cause,
        agent,
        hop,
        expires_at: active_root.expires_at,
    })
}

fn check_count(
    tx: &Connection,
    query: &str,
    values: impl rusqlite::Params,
    maximum: u32,
    reason: BudgetLimit,
) -> Result<()> {
    let count = tx.query_row(query, values, |row| row.get::<_, i64>(0))?;
    if count >= i64::from(maximum) {
        return Err(BudgetError::Limit(reason));
    }
    Ok(())
}

fn random_id() -> Result<Id> {
    let mut id = [0; 32];
    getrandom::fill(&mut id).map_err(io::Error::other)?;
    Ok(id)
}
