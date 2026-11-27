use std::io;

use howl_envelope::AgentReply;
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{DeliveryStore, Error, Frame, Id, Result};

const MAX_RUN_TIME: i64 = 900;

#[derive(Clone, Copy)]
pub(crate) struct NewIntegrationRun<'a> {
    pub owner: &'a str,
    pub key: &'a str,
    pub channel: Id,
    pub peer: Id,
    pub target: Id,
    pub lifetime: u16,
    pub text: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct IntegrationRun {
    pub id: Id,
    pub channel: Id,
    pub peer: Id,
    pub target: Id,
    pub message: Option<Id>,
    pub state: IntegrationRunState,
    pub created_at: String,
    pub updated_at: String,
    pub cancellation_requested: bool,
}

impl IntegrationRun {
    pub(crate) fn summary(&self) -> Value {
        let mut value = self.value();
        if let Value::Object(fields) = &mut value {
            fields.remove("reply");
        }
        value
    }

    pub(crate) fn value(&self) -> Value {
        let (status, reply, error) = match &self.state {
            IntegrationRunState::Working => ("working", None, None),
            IntegrationRunState::Cancelled => ("cancelled", None, None),
            IntegrationRunState::Completed { reply, message } => (
                "completed",
                Some(json!({ "text": reply, "message": hex::encode(message) })),
                None,
            ),
            IntegrationRunState::Failed { reason } => ("failed", None, Some(reason)),
        };
        json!({
            "run": hex::encode(self.id),
            "channel": hex::encode(self.channel),
            "peer": hex::encode(self.peer),
            "target": hex::encode(self.target),
            "wake_message": self.message.map(hex::encode),
            "status": status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "cancellation_requested": self.cancellation_requested,
            "reply": reply,
            "error": error,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IntegrationRunState {
    Working,
    Completed { reply: String, message: Id },
    Failed { reason: &'static str },
    Cancelled,
}

#[derive(Clone, Copy)]
pub(crate) struct Dispatch {
    pub id: Id,
    pub fingerprint: Id,
}

#[derive(Clone, Copy)]
pub(crate) struct IntegrationDelivery {
    pub actor: Id,
    pub dispatch: Option<Dispatch>,
}

impl DeliveryStore {
    pub(crate) fn integration_dispatch(
        &self,
        dispatch: Dispatch,
        now: u64,
    ) -> Result<(String, Option<Id>)> {
        dispatch_status(&self.connection, dispatch, now)
    }

    pub(crate) fn prepare_integration_run(
        &mut self,
        request: &NewIntegrationRun<'_>,
        now: u64,
    ) -> Result<IntegrationRun> {
        let now = timestamp(now)?;
        if !valid_integration_owner(request.owner)
            || request.key.is_empty()
            || request.key.len() > 128
            || !request.key.bytes().all(|byte| byte.is_ascii_graphic())
            || !(1..=300).contains(&request.lifetime)
            || request.text.is_empty()
            || request.text.len() > crate::node::INTEGRATION_WAKE_LIMIT
        {
            return Err(Error::InvalidFrame);
        }
        let fingerprint = run_fingerprint(
            request.channel,
            request.peer,
            request.target,
            request.lifetime,
            request.text,
        );
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = tx
            .query_row(
                "SELECT id, fingerprint FROM integration_runs WHERE owner = ?1 AND request_key = ?2",
                params![request.owner, request.key],
                |row| Ok((row.get::<_, Id>(0)?, row.get::<_, Id>(1)?)),
            )
            .optional()?;
        let id = match previous {
            Some((id, saved)) if saved == fingerprint => id,
            Some(_) => return Err(Error::Conflict),
            None => {
                let mut id = [0; 32];
                getrandom::fill(&mut id).map_err(io::Error::other)?;
                tx.execute(
                    "INSERT INTO integration_runs (
                        id, owner, request_key, fingerprint, channel, peer, target,
                        created_at, updated_at, dispatch_before, finish_before
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10)",
                    params![
                        id,
                        request.owner,
                        request.key,
                        fingerprint,
                        request.channel,
                        request.peer,
                        request.target,
                        now,
                        now.checked_add(i64::from(request.lifetime))
                            .ok_or(Error::InvalidFrame)?,
                        now.checked_add(MAX_RUN_TIME).ok_or(Error::InvalidFrame)?,
                    ],
                )?;
                id
            }
        };
        expire(&tx, request.owner, id, now)?;
        let run = load(&tx, request.owner, id)?.ok_or(Error::InvalidFrame)?;
        tx.commit()?;
        Ok(run)
    }

    pub(crate) fn integration_run(
        &mut self,
        owner: &str,
        id: Id,
        now: u64,
    ) -> Result<Option<IntegrationRun>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire(&tx, owner, id, timestamp(now)?)?;
        let run = load(&tx, owner, id)?;
        tx.commit()?;
        Ok(run)
    }

    pub(crate) fn cancel_integration_run(
        &mut self,
        owner: &str,
        id: Id,
        now: u64,
    ) -> Result<Option<IntegrationRun>> {
        let now = timestamp(now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire(&tx, owner, id, now)?;
        let pending = tx
            .query_row(
                "SELECT envelope FROM integration_runs
                 WHERE owner = ?1 AND id = ?2 AND state = 0 AND cancellation_requested = 0",
                params![owner, id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?;
        if let Some(envelope) = pending {
            let sent: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM recipients WHERE envelope = ?1
                                AND (attempt > 0 OR acknowledged = 1))",
                [envelope],
                |row| row.get(0),
            )?;
            tx.execute(
                "UPDATE recipients SET due = NULL WHERE envelope = ?1 AND acknowledged = 0",
                [envelope],
            )?;
            tx.execute(
                "UPDATE integration_runs
                 SET cancellation_requested = 1, updated_at = max(updated_at, ?3),
                     state = CASE WHEN ?4 THEN 0 ELSE 3 END
                 WHERE owner = ?1 AND id = ?2",
                params![owner, id, now, sent],
            )?;
        }
        let run = load(&tx, owner, id)?;
        tx.commit()?;
        Ok(run)
    }
}

pub(crate) fn run_fingerprint(channel: Id, peer: Id, target: Id, lifetime: u16, text: &str) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"howl/integration-run/v1\0");
    hash.update(channel);
    hash.update(peer);
    hash.update(target);
    hash.update(lifetime.to_be_bytes());
    hash.update(text.as_bytes());
    hash.finalize().into()
}

pub(crate) fn valid_integration_owner(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 64
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

pub(super) fn dispatch_status(
    connection: &Connection,
    dispatch: Dispatch,
    now: u64,
) -> Result<(String, Option<Id>)> {
    let now = timestamp(now)?;
    let record = connection
        .query_row(
            "SELECT fingerprint, state, cancellation_requested, dispatch_before, run_message, owner
             FROM integration_runs WHERE id = ?1",
            [dispatch.id],
            |row| {
                Ok((
                    row.get::<_, Id>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<Id>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    match record {
        Some((fingerprint, _, _, _, Some(message), owner))
            if fingerprint == dispatch.fingerprint =>
        {
            Ok((owner, Some(message)))
        }
        Some((fingerprint, 0, false, deadline, None, owner))
            if fingerprint == dispatch.fingerprint && now < deadline =>
        {
            Ok((owner, None))
        }
        Some((fingerprint, _, _, _, _, _)) if fingerprint == dispatch.fingerprint => {
            Err(Error::Expired)
        }
        _ => Err(Error::Conflict),
    }
}

pub(super) fn link_dispatch(
    connection: &Connection,
    dispatch: Dispatch,
    frame: Frame,
    envelope: i64,
    now: u64,
) -> Result<()> {
    let changed = connection.execute(
        "UPDATE integration_runs
         SET envelope = ?2, run_message = ?3, updated_at = max(updated_at, ?4)
         WHERE id = ?1 AND state = 0 AND envelope IS NULL AND channel = ?5",
        params![
            dispatch.id,
            envelope,
            frame.message,
            timestamp(now)?,
            frame.stream.channel
        ],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

pub(super) fn record_reply(
    connection: &Connection,
    frame: Frame,
    reply: AgentReply<&str>,
    now: u64,
) -> Result<()> {
    let now = timestamp(now)?;
    connection.execute(
        "UPDATE integration_runs
         SET state = 1, reply_message = ?1, reply = ?2, updated_at = max(updated_at, ?3)
         WHERE state = 0 AND finish_before > ?3
           AND run_message = ?4 AND channel = ?5 AND peer = ?6 AND target = ?7",
        params![
            frame.message,
            reply.text,
            now,
            reply.in_reply_to,
            frame.stream.channel,
            frame.stream.sender.device,
            reply.agent,
        ],
    )?;
    Ok(())
}

fn expire(connection: &Connection, owner: &str, id: Id, now: i64) -> Result<()> {
    connection.execute(
        "UPDATE integration_runs SET state = 2, updated_at = max(updated_at, ?3)
         WHERE owner = ?1 AND id = ?2 AND state = 0
           AND CASE WHEN run_message IS NULL THEN dispatch_before ELSE finish_before END <= ?3",
        params![owner, id, now],
    )?;
    Ok(())
}

fn load(connection: &Connection, owner: &str, id: Id) -> Result<Option<IntegrationRun>> {
    Ok(connection
        .query_row(
            "SELECT channel, peer, target, run_message, state, cancellation_requested,
                    strftime('%Y-%m-%dT%H:%M:%SZ', created_at, 'unixepoch'),
                    strftime('%Y-%m-%dT%H:%M:%SZ', updated_at, 'unixepoch'),
                    reply_message, reply
             FROM integration_runs WHERE owner = ?1 AND id = ?2",
            params![owner, id],
            |row| read_run(row, id),
        )
        .optional()?)
}

fn read_run(row: &Row<'_>, id: Id) -> rusqlite::Result<IntegrationRun> {
    let message = row.get::<_, Option<Id>>(3)?;
    let cancellation_requested = row.get::<_, bool>(5)?;
    let state = match row.get::<_, i64>(4)? {
        0 => IntegrationRunState::Working,
        1 => IntegrationRunState::Completed {
            message: row.get(8)?,
            reply: row.get(9)?,
        },
        2 => IntegrationRunState::Failed {
            reason: match (message, cancellation_requested) {
                (None, _) => "The wake was not queued before its deadline.",
                (Some(_), true) => "The remote cancellation could not be confirmed.",
                (Some(_), false) => "No signed reply arrived before the run deadline.",
            },
        },
        3 => IntegrationRunState::Cancelled,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(IntegrationRun {
        id,
        channel: row.get(0)?,
        peer: row.get(1)?,
        target: row.get(2)?,
        message,
        state,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        cancellation_requested,
    })
}

fn timestamp(now: u64) -> Result<i64> {
    i64::try_from(now).map_err(|_| Error::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use howl_envelope::{AgentRole, Body};

    use super::*;
    use crate::delivery::{Device, Stream};

    const OWNER: &str = "primary";
    const OTHER: &str = "secondary";
    const CHANNEL: Id = [3; 32];
    const KEY: Id = [4; 32];
    const NOW: u64 = 1_800_000_000;
    const LOCAL: Device = Device {
        account: [5; 32],
        device: [6; 32],
    };
    const PEER: Device = Device {
        account: [5; 32],
        device: [7; 32],
    };

    fn request(key: &str) -> NewIntegrationRun<'_> {
        NewIntegrationRun {
            owner: OWNER,
            key,
            channel: CHANNEL,
            peer: PEER.device,
            target: AgentRole::Reviewer.agent_id(&PEER.device),
            lifetime: 60,
            text: "review selected materials privately",
        }
    }

    fn enqueue(
        store: &mut DeliveryStore,
        run: Id,
        request: NewIntegrationRun<'_>,
        message: Id,
    ) -> Result<Id> {
        let stream = Stream {
            channel: CHANNEL,
            sender: LOCAL,
            signing_key: [8; 32],
        };
        store.set_epoch(CHANNEL, 1)?;
        let sequence = store.reserve_sequence(stream)?;
        store.enqueue_integration(
            Frame {
                stream,
                message,
                sequence,
                epoch: 1,
                created_at: NOW,
                expires_at: NOW + u64::from(request.lifetime),
            },
            &message,
            PEER,
            Body::Wake {
                session: request.target,
                text: request.text,
            },
            NOW,
            IntegrationDelivery {
                actor: [16; 32],
                dispatch: Some(Dispatch {
                    id: run,
                    fingerprint: run_fingerprint(
                        request.channel,
                        request.peer,
                        request.target,
                        request.lifetime,
                        request.text,
                    ),
                }),
            },
        )
    }

    #[test]
    fn retries_share_one_wake_and_the_signed_result_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delivery.db");
        let request = request("one");
        let mut store = DeliveryStore::open(&path, &KEY, LOCAL).unwrap();
        let run = store.prepare_integration_run(&request, NOW).unwrap();
        assert_eq!(
            store.prepare_integration_run(&request, NOW + 1).unwrap().id,
            run.id,
        );
        assert!(matches!(
            store.prepare_integration_run(
                &NewIntegrationRun {
                    text: "different",
                    ..request
                },
                NOW
            ),
            Err(Error::Conflict)
        ));
        assert_ne!(
            store
                .prepare_integration_run(
                    &NewIntegrationRun {
                        owner: OTHER,
                        ..request
                    },
                    NOW
                )
                .unwrap()
                .id,
            run.id
        );
        assert!(store.integration_run(OTHER, run.id, NOW).unwrap().is_none());
        assert!(
            store
                .cancel_integration_run(OTHER, run.id, NOW)
                .unwrap()
                .is_none()
        );

        let message = [9; 32];
        assert_eq!(
            enqueue(&mut store, run.id, request, message).unwrap(),
            message
        );
        drop(store);
        let mut store = DeliveryStore::open(&path, &KEY, LOCAL).unwrap();
        assert_eq!(
            enqueue(&mut store, run.id, request, [10; 32]).unwrap(),
            message
        );
        assert_eq!(store.channel_events(CHANNEL, 0, 10).unwrap().len(), 1);
        let reply = AgentReply {
            agent: request.target,
            role: AgentRole::Reviewer,
            in_reply_to: message,
            context_digest: [11; 32],
            text: "private signed answer",
        };
        let mut frame = Frame {
            stream: Stream {
                channel: [255; 32],
                sender: PEER,
                signing_key: [12; 32],
            },
            message: [13; 32],
            sequence: 1,
            epoch: 1,
            created_at: NOW + 2,
            expires_at: 0,
        };
        record_reply(&store.connection, frame, reply, NOW + 2).unwrap();
        frame.stream.channel = CHANNEL;
        frame.stream.sender = LOCAL;
        record_reply(&store.connection, frame, reply, NOW + 2).unwrap();
        assert_eq!(
            store
                .integration_run(OWNER, run.id, NOW + 2)
                .unwrap()
                .unwrap()
                .state,
            IntegrationRunState::Working
        );
        frame.stream.sender = PEER;
        record_reply(&store.connection, frame, reply, NOW + 2).unwrap();
        drop(store);

        let mut store = DeliveryStore::open(&path, &KEY, LOCAL).unwrap();
        let completed = store
            .integration_run(OWNER, run.id, NOW + 1000)
            .unwrap()
            .unwrap();
        assert_eq!(
            completed.state,
            IntegrationRunState::Completed {
                reply: reply.text.to_owned(),
                message: frame.message,
            },
        );
        assert_eq!(completed.value()["reply"]["text"], reply.text);
        assert_eq!(
            store
                .cancel_integration_run(OWNER, run.id, NOW + 1000)
                .unwrap(),
            Some(completed)
        );
        assert!(
            !std::fs::read(path)
                .unwrap()
                .windows(reply.text.len())
                .any(|window| window == reply.text.as_bytes())
        );
    }

    #[test]
    fn cancellation_distinguishes_locally_queued_and_claimed_wakes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delivery.db");
        let mut store = DeliveryStore::open(&path, &KEY, LOCAL).unwrap();
        let queued = request("queued");
        let run = store.prepare_integration_run(&queued, NOW).unwrap();
        enqueue(&mut store, run.id, queued, [14; 32]).unwrap();
        let cancelled = store
            .cancel_integration_run(OWNER, run.id, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(cancelled.state, IntegrationRunState::Cancelled);
        assert!(store.claim_due(Some(CHANNEL), NOW, 10).unwrap().is_empty());

        let in_flight = request("in-flight");
        let run = store.prepare_integration_run(&in_flight, NOW).unwrap();
        enqueue(&mut store, run.id, in_flight, [15; 32]).unwrap();
        assert_eq!(store.claim_due(Some(CHANNEL), NOW, 10).unwrap().len(), 1);
        let cancelling = store
            .cancel_integration_run(OWNER, run.id, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(cancelling.state, IntegrationRunState::Working);
        assert!(cancelling.cancellation_requested);
        assert!(
            store
                .claim_due(Some(CHANNEL), NOW + 10, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .integration_run(OWNER, run.id, NOW + 905)
                .unwrap()
                .unwrap()
                .state,
            IntegrationRunState::Failed {
                reason: "The remote cancellation could not be confirmed."
            },
        );
    }
}
