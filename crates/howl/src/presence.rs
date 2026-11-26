use std::io;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior::Immediate, params};

use crate::delivery::{Device, Id};

pub const PRESENCE_TTL_SECS: u64 = 60;
const MAX_LABEL_BYTES: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("presence storage failed")]
    Database(#[from] rusqlite::Error),
    #[error("presence token generation failed")]
    Entropy(#[source] io::Error),
    #[error("stale or conflicting presence observation")]
    Stale,
    #[error("invalid presence capability metadata")]
    Capabilities,
    #[error("inactive session cannot report active execution")]
    InactiveSession,
    #[error("invalid persisted presence state")]
    StoredState,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Runtime([u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeLink {
    node: Device,
    runtime: Runtime,
    token: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentId {
    pub node: Device,
    pub id: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub at: u64,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Connectivity {
    Offline,
    Online,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodePresence {
    pub connectivity: Connectivity,
    pub last_observed_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum AgentKind {
    ManagedAcp = 0,
    ExternalMcp = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum Readiness {
    Unavailable = 0,
    Ready = 1,
    Recovering = 2,
    Failed = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub harness: String,
    pub version: Option<String>,
    pub mcp: bool,
    pub prompt: bool,
    pub cancel: bool,
    pub load_session: bool,
    pub resume_session: bool,
    pub close_session: bool,
}

impl Capabilities {
    fn encode(&self, kind: AgentKind) -> Result<i64> {
        if !valid_label(&self.harness)
            || self
                .version
                .as_deref()
                .is_some_and(|value| !valid_label(value))
        {
            return Err(Error::Capabilities);
        }
        let flags = i64::from(self.mcp)
            | (i64::from(self.prompt) << 1)
            | (i64::from(self.cancel) << 2)
            | (i64::from(self.load_session) << 3)
            | (i64::from(self.resume_session) << 4)
            | (i64::from(self.close_session) << 5);
        if kind == AgentKind::ExternalMcp && flags != 1 {
            return Err(Error::Capabilities);
        }
        Ok(flags)
    }

    fn decode(harness: String, version: Option<String>, flags: i64) -> Self {
        Self {
            harness,
            version,
            mcp: flags & 1 != 0,
            prompt: flags & 2 != 0,
            cancel: flags & 4 != 0,
            load_session: flags & 8 != 0,
            resume_session: flags & 16 != 0,
            close_session: flags & 32 != 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPresence {
    pub node: NodePresence,
    pub kind: AgentKind,
    pub readiness: Readiness,
    pub capabilities: Capabilities,
    pub capabilities_observed_at: u64,
    pub capabilities_fresh: bool,
}

impl AgentPresence {
    pub fn status(&self) -> Status {
        if self.node.connectivity == Connectivity::Offline || !self.capabilities_fresh {
            return Status::Offline;
        }
        match self.readiness {
            Readiness::Unavailable => Status::Offline,
            Readiness::Ready => Status::Idle,
            Readiness::Recovering => Status::Recovering,
            Readiness::Failed => Status::Failed,
        }
    }

    pub fn wakeable(&self) -> bool {
        self.kind == AgentKind::ManagedAcp
            && self.capabilities.prompt
            && self.status() == Status::Idle
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum SessionLifecycle {
    Open = 0,
    Recovering = 1,
    Closed = 2,
    Failed = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum Execution {
    Idle = 0,
    Queued = 1,
    Running = 2,
    Approval = 3,
    Recovering = 4,
    Failed = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Offline,
    Idle,
    Queued,
    Running,
    Approval,
    Recovering,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPresence {
    pub agent: AgentPresence,
    pub lifecycle: SessionLifecycle,
    pub execution: Execution,
    pub last_observed_at: u64,
}

impl SessionPresence {
    pub fn status(&self) -> Status {
        match self.agent.status() {
            Status::Idle => {}
            status => return status,
        }
        match self.lifecycle {
            SessionLifecycle::Open => {}
            SessionLifecycle::Recovering => return Status::Recovering,
            SessionLifecycle::Closed => return Status::Offline,
            SessionLifecycle::Failed => return Status::Failed,
        }
        match self.execution {
            Execution::Idle => Status::Idle,
            Execution::Queued => Status::Queued,
            Execution::Running => Status::Running,
            Execution::Approval => Status::Approval,
            Execution::Recovering => Status::Recovering,
            Execution::Failed => Status::Failed,
        }
    }

    pub fn wakeable(&self) -> bool {
        self.agent.wakeable() && self.status() == Status::Idle
    }
}

pub struct Presence<'db> {
    connection: &'db mut Connection,
}

impl<'db> Presence<'db> {
    pub(crate) fn new(connection: &'db mut Connection) -> Self {
        Self { connection }
    }

    pub fn start_runtime(&mut self) -> Result<Runtime> {
        let runtime = Runtime(token()?);
        self.connection.execute(
            "INSERT INTO presence_runtime VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET token = excluded.token",
            [runtime.0],
        )?;
        Ok(runtime)
    }

    pub fn connect(&mut self, runtime: Runtime, node: Device, now: u64) -> Result<NodeLink> {
        let link = NodeLink {
            node,
            runtime,
            token: token()?,
        };
        let changed = self.connection.execute(
            "INSERT INTO presence_nodes
             SELECT ?1, ?2, ?3, ?4, 1 WHERE ?2 = (SELECT token FROM presence_runtime)
             ON CONFLICT(node) DO UPDATE SET runtime = excluded.runtime, link = excluded.link,
               observed = excluded.observed, connected = 1
             WHERE presence_nodes.runtime <> excluded.runtime OR presence_nodes.observed <= excluded.observed",
            params![node.encode(), runtime.0, link.token, now.to_be_bytes()],
        )?;
        changed_once(changed)?;
        Ok(link)
    }

    pub fn heartbeat(&mut self, link: NodeLink, now: u64) -> Result<()> {
        let tx = self.connection.transaction_with_behavior(Immediate)?;
        require_link(&tx, link, now)?;
        tx.execute(
            "UPDATE presence_nodes SET observed = ?2 WHERE node = ?1",
            params![link.node.encode(), now.to_be_bytes()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn disconnect(&mut self, link: NodeLink, now: u64) -> Result<()> {
        changed_once(self.connection.execute(
            "UPDATE presence_nodes SET connected = 0, observed = ?4
             WHERE node = ?1 AND runtime = ?2 AND link = ?3
               AND connected = 1 AND observed <= ?4
               AND runtime = (SELECT token FROM presence_runtime)",
            params![
                link.node.encode(),
                link.runtime.0,
                link.token,
                now.to_be_bytes()
            ],
        )?)
    }

    pub fn observe_agent(
        &mut self,
        link: NodeLink,
        agent: Id,
        observation: Observation,
        kind: AgentKind,
        readiness: Readiness,
        capabilities: &Capabilities,
    ) -> Result<()> {
        let flags = capabilities.encode(kind)?;
        require_revision(observation)?;
        let tx = self.connection.transaction_with_behavior(Immediate)?;
        require_link(&tx, link, observation.at)?;
        changed_once(tx.execute(
            "INSERT INTO presence_agents VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(node, agent) DO UPDATE SET link = excluded.link,
               observed = excluded.observed, revision = excluded.revision, readiness = excluded.readiness,
               harness = excluded.harness, version = excluded.version, capabilities = excluded.capabilities
             WHERE presence_agents.kind = excluded.kind AND
               (presence_agents.link <> excluded.link OR
                (presence_agents.revision < excluded.revision AND presence_agents.observed <= excluded.observed))",
            params![
                link.node.encode(), agent, link.token, observation.at.to_be_bytes(),
                observation.revision.to_be_bytes(), kind as i64, readiness as i64,
                capabilities.harness, capabilities.version, flags,
            ],
        )?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn observe_session(
        &mut self,
        link: NodeLink,
        agent: Id,
        session: Id,
        observation: Observation,
        lifecycle: SessionLifecycle,
        execution: Execution,
    ) -> Result<()> {
        if lifecycle != SessionLifecycle::Open
            && matches!(execution, Execution::Running | Execution::Approval)
        {
            return Err(Error::InactiveSession);
        }
        require_revision(observation)?;
        let tx = self.connection.transaction_with_behavior(Immediate)?;
        require_link(&tx, link, observation.at)?;
        changed_once(tx.execute(
            "INSERT INTO presence_sessions VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(node, agent, session) DO UPDATE SET link = excluded.link,
               observed = excluded.observed, revision = excluded.revision,
               lifecycle = excluded.lifecycle, execution = excluded.execution
             WHERE presence_sessions.lifecycle <> ?9 AND
               (presence_sessions.link <> excluded.link OR
                (presence_sessions.revision < excluded.revision AND presence_sessions.observed <= excluded.observed))",
            params![
                link.node.encode(), agent, session, link.token, observation.at.to_be_bytes(),
                observation.revision.to_be_bytes(), lifecycle as i64, execution as i64,
                SessionLifecycle::Closed as i64,
            ],
        )?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn node(&self, device: Device, now: u64) -> Result<NodePresence> {
        Ok(load_node(self.connection, device)?.map_or(
            NodePresence {
                connectivity: Connectivity::Offline,
                last_observed_at: None,
            },
            |node| node.presence(now),
        ))
    }

    pub fn agent(&self, agent: AgentId, now: u64) -> Result<Option<AgentPresence>> {
        let tx = self.connection.unchecked_transaction()?;
        let presence = match load_node(&tx, agent.node)? {
            Some(node) => load_agent(&tx, &node, agent, now)?,
            None => None,
        };
        tx.commit()?;
        Ok(presence)
    }

    pub fn session(
        &self,
        agent: AgentId,
        session: Id,
        now: u64,
    ) -> Result<Option<SessionPresence>> {
        let tx = self.connection.unchecked_transaction()?;
        let Some(node) = load_node(&tx, agent.node)? else {
            return Ok(None);
        };
        let Some(agent_presence) = load_agent(&tx, &node, agent, now)? else {
            return Ok(None);
        };
        let stored = tx
            .query_row(
                "SELECT link, observed, lifecycle, execution FROM presence_sessions
             WHERE node = ?1 AND agent = ?2 AND session = ?3",
                params![agent.node.encode(), agent.id, session],
                |row| {
                    Ok((
                        row.get::<_, [u8; 16]>(0)?,
                        row.get::<_, [u8; 8]>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        tx.commit()?;
        let Some((link, observed, lifecycle, execution)) = stored else {
            return Ok(None);
        };
        let mut lifecycle = decode_value(
            lifecycle,
            [
                SessionLifecycle::Open,
                SessionLifecycle::Recovering,
                SessionLifecycle::Closed,
                SessionLifecycle::Failed,
            ],
        )?;
        let mut execution = decode_value(
            execution,
            [
                Execution::Idle,
                Execution::Queued,
                Execution::Running,
                Execution::Approval,
                Execution::Recovering,
                Execution::Failed,
            ],
        )?;
        if lifecycle == SessionLifecycle::Open && !node.matches(link, now) {
            lifecycle = SessionLifecycle::Recovering;
            if matches!(execution, Execution::Running | Execution::Approval) {
                execution = Execution::Recovering;
            }
        }
        Ok(Some(SessionPresence {
            agent: agent_presence,
            lifecycle,
            execution,
            last_observed_at: u64::from_be_bytes(observed),
        }))
    }
}

struct StoredNode {
    active_runtime: bool,
    connected: bool,
    runtime: Runtime,
    link: [u8; 16],
    observed_at: u64,
}

impl StoredNode {
    fn online(&self, now: u64) -> bool {
        self.active_runtime && self.connected && fresh(self.observed_at, now)
    }

    fn matches(&self, link: [u8; 16], now: u64) -> bool {
        self.link == link && self.online(now)
    }

    fn presence(&self, now: u64) -> NodePresence {
        NodePresence {
            connectivity: if self.online(now) {
                Connectivity::Online
            } else {
                Connectivity::Offline
            },
            last_observed_at: Some(self.observed_at),
        }
    }
}

fn load_node(connection: &Connection, device: Device) -> Result<Option<StoredNode>> {
    Ok(connection.query_row(
        "SELECT runtime = (SELECT token FROM presence_runtime), connected, runtime, link, observed
         FROM presence_nodes WHERE node = ?1",
        [device.encode()],
        |row| Ok(StoredNode {
            active_runtime: row.get(0)?,
            connected: row.get(1)?,
            runtime: Runtime(row.get(2)?),
            link: row.get(3)?,
            observed_at: u64::from_be_bytes(row.get(4)?),
        }),
    ).optional()?)
}

fn load_agent(
    connection: &Connection,
    node: &StoredNode,
    agent: AgentId,
    now: u64,
) -> Result<Option<AgentPresence>> {
    let stored = connection.query_row(
        "SELECT link, observed, kind, readiness, harness, version, capabilities FROM presence_agents
         WHERE node = ?1 AND agent = ?2",
        params![agent.node.encode(), agent.id],
        |row| Ok((
            row.get::<_, [u8; 16]>(0)?,
            row.get::<_, [u8; 8]>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            Capabilities::decode(row.get(4)?, row.get(5)?, row.get(6)?),
        )),
    ).optional()?;
    let Some((link, observed, kind, readiness, capabilities)) = stored else {
        return Ok(None);
    };
    let observed = u64::from_be_bytes(observed);
    let capabilities_fresh = node.matches(link, now) && fresh(observed, now);
    let kind = decode_value(kind, [AgentKind::ManagedAcp, AgentKind::ExternalMcp])?;
    let readiness = if capabilities_fresh {
        decode_value(
            readiness,
            [
                Readiness::Unavailable,
                Readiness::Ready,
                Readiness::Recovering,
                Readiness::Failed,
            ],
        )?
    } else {
        Readiness::Unavailable
    };
    Ok(Some(AgentPresence {
        node: node.presence(now),
        kind,
        readiness,
        capabilities,
        capabilities_observed_at: observed,
        capabilities_fresh,
    }))
}

fn require_link(connection: &Connection, link: NodeLink, now: u64) -> Result<()> {
    if load_node(connection, link.node)?
        .is_some_and(|node| node.runtime == link.runtime && node.matches(link.token, now))
    {
        Ok(())
    } else {
        Err(Error::Stale)
    }
}

fn require_revision(observation: Observation) -> Result<()> {
    if observation.revision == 0 {
        Err(Error::Stale)
    } else {
        Ok(())
    }
}

fn fresh(observed: u64, now: u64) -> bool {
    now.checked_sub(observed)
        .is_some_and(|age| age < PRESENCE_TTL_SECS)
}

fn valid_label(label: &str) -> bool {
    !label.trim().is_empty()
        && label.len() <= MAX_LABEL_BYTES
        && !label.chars().any(char::is_control)
}

fn decode_value<T: Copy, const N: usize>(value: i64, variants: [T; N]) -> Result<T> {
    variants
        .get(value as usize)
        .copied()
        .ok_or(Error::StoredState)
}

fn changed_once(changed: usize) -> Result<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::Stale)
    }
}

fn token() -> Result<[u8; 16]> {
    let mut token = [0; 16];
    getrandom::fill(&mut token).map_err(|error| Error::Entropy(io::Error::other(error)))?;
    Ok(token)
}
