use std::io;

use ed25519_dalek::Signature;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::delivery::{
    Device, Id, WakeClaim, WakeJob, WakeState,
    wake::{claimed_job, record_wake_time, set_claim_state},
};

use super::{
    BudgetError, ConversationBudget, Turn, begin_human, continue_human, record_budget_time,
    record_control,
};

type Result<T> = std::result::Result<T, WakeTurnError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakeApproval<'a> {
    pub nonce: Id,
    pub expires_at: u64,
    pub claim: &'a WakeClaim,
    pub agent: Id,
    pub cause: Option<Id>,
}

impl WakeApproval<'_> {
    pub fn signing_bytes(&self, node: Device) -> Vec<u8> {
        let mut bytes = b"howl/local-wake-approval/v1\0".to_vec();
        bytes.extend_from_slice(&node.encode());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.claim.execution);
        bytes.extend_from_slice(&self.claim.cursor.to_be_bytes());
        bytes.extend_from_slice(&self.claim.message);
        bytes.extend_from_slice(&self.claim.frame_digest);
        bytes.extend_from_slice(&self.claim.stream.encode());
        bytes.extend_from_slice(&self.claim.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.claim.target);
        bytes.extend_from_slice(&self.claim.grant_generation.to_be_bytes());
        bytes.extend_from_slice(&self.claim.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.agent);
        bytes.push(u8::from(self.cause.is_some()));
        if let Some(cause) = self.cause {
            bytes.extend_from_slice(&cause);
        }
        bytes
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ApprovedWake {
    pub job: WakeJob,
    pub turn: Turn,
}

impl ApprovedWake {
    pub fn deadline(&self) -> u64 {
        self.job.claim.expires_at.min(self.turn.expires_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeOutcome {
    Finished,
    Uncertain,
}

#[derive(Debug, thiserror::Error)]
pub enum WakeTurnError {
    #[error("wake approval is invalid or expired")]
    Approval,
    #[error("approved wake is unavailable or no longer authorized")]
    Unavailable,
    #[error(transparent)]
    Budget(#[from] BudgetError),
    #[error(transparent)]
    Delivery(#[from] crate::delivery::Error),
    #[error("wake admission storage failed")]
    Storage(#[from] rusqlite::Error),
    #[error("wake admission clock unavailable")]
    Clock(#[from] io::Error),
}

impl ConversationBudget<'_> {
    pub fn start_approved_wake(
        &mut self,
        approval: WakeApproval<'_>,
        signature: &[u8; 64],
        fresh_clock: impl FnOnce() -> io::Result<u64>,
        authorize: impl FnOnce(&WakeClaim, Id) -> bool,
    ) -> Result<ApprovedWake> {
        if approval.nonce == [0; 32] {
            return Err(WakeTurnError::Approval);
        }
        self.human
            .verify_strict(
                &approval.signing_bytes(self.node),
                &Signature::from_bytes(signature),
            )
            .map_err(|_| WakeTurnError::Approval)?;

        let execution = approval.claim.execution;
        let limits = self.limits;
        let mut tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let job = claimed_job(&tx, execution)?.filter(|job| &job.claim == approval.claim);
        let allowed = job
            .as_ref()
            .is_some_and(|job| authorize(&job.claim, approval.agent));
        let now = fresh_clock()?;
        record_wake_time(&tx, now)?;
        record_budget_time(&tx, now)?;

        if now >= approval.expires_at {
            tx.commit()?;
            return Err(WakeTurnError::Approval);
        }
        let Some(job) = job else {
            tx.commit()?;
            return Err(WakeTurnError::Unavailable);
        };
        if !allowed || now >= job.claim.expires_at {
            set_claim_state(&tx, execution, WakeState::Cancelled)?;
            tx.commit()?;
            return Err(WakeTurnError::Unavailable);
        }

        let attempt = {
            let attempt = tx.savepoint()?;
            let result = (|| {
                record_control(&attempt, approval.nonce)?;
                let turn = match approval.cause {
                    Some(cause) => continue_human(&attempt, limits, now, cause, approval.agent)?,
                    None => begin_human(&attempt, limits, now, approval.agent)?,
                };
                if set_claim_state(&attempt, execution, WakeState::Running)? != 1 {
                    return Err(WakeTurnError::Unavailable);
                }
                attempt.execute(
                    "INSERT INTO budget_wakes (execution, turn) VALUES (?1, ?2)",
                    params![execution, turn.id],
                )?;
                Ok(turn)
            })();
            match result {
                Ok(turn) => {
                    attempt.commit()?;
                    Ok(turn)
                }
                Err(error) => {
                    attempt.finish()?;
                    Err(error)
                }
            }
        };
        tx.commit()?;
        Ok(ApprovedWake {
            job,
            turn: attempt?,
        })
    }

    pub fn finish_approved_wake(
        &mut self,
        execution: Id,
        outcome: WakeOutcome,
    ) -> Result<Option<WakeOutcome>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let link: Option<(Id, i64, bool)> = tx
            .query_row(
                "SELECT b.turn, q.state, r.paused FROM budget_wakes b
             JOIN budget_turns t ON t.id = b.turn AND t.state = 1
             JOIN budget_roots r ON r.root = t.root
             JOIN wake_queue q ON q.execution = b.execution
             WHERE b.execution = ?1",
                [execution],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((turn, state, paused)) = link else {
            return Ok(None);
        };
        let (wake_state, turn_state, terminal) =
            if !paused && state == WakeState::Running as i64 && outcome == WakeOutcome::Finished {
                (WakeState::Finished, 0, WakeOutcome::Finished)
            } else {
                (WakeState::Uncertain, 2, WakeOutcome::Uncertain)
            };
        tx.execute(
            "UPDATE wake_queue SET state = ?2 WHERE execution = ?1 AND state = 2",
            params![execution, wake_state as i64],
        )?;
        tx.execute(
            "UPDATE budget_turns SET state = ?2 WHERE id = ?1 AND state = 1",
            params![turn, turn_state],
        )?;
        tx.commit()?;
        Ok(Some(terminal))
    }
}
