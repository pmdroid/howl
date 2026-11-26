use howl::{
    delivery::{DeliveryStore, Device},
    presence::{
        AgentId, AgentKind, Capabilities, Connectivity, Error, Execution, NodeLink, Observation,
        PRESENCE_TTL_SECS, Presence, Readiness, SessionLifecycle, Status,
    },
};

const DEVICE: Device = Device {
    account: [1; 32],
    device: [2; 32],
};
const AGENT: AgentId = AgentId {
    node: DEVICE,
    id: [3; 32],
};
const SESSION: [u8; 32] = [4; 32];
const KEY: [u8; 32] = [5; 32];

fn observed(at: u64, revision: u64) -> Observation {
    Observation { at, revision }
}

fn capabilities() -> Capabilities {
    Capabilities {
        harness: "test-acp".into(),
        version: Some("1.2".into()),
        mcp: true,
        prompt: true,
        cancel: true,
        load_session: true,
        resume_session: false,
        close_session: true,
    }
}

fn managed(
    presence: &mut Presence<'_>,
    link: NodeLink,
    at: u64,
    revision: u64,
    readiness: Readiness,
) {
    presence
        .observe_agent(
            link,
            AGENT.id,
            observed(at, revision),
            AgentKind::ManagedAcp,
            readiness,
            &capabilities(),
        )
        .unwrap();
}

#[test]
fn connectivity_readiness_and_execution_are_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = DeliveryStore::open(&dir.path().join("mesh.db"), &KEY, DEVICE).unwrap();
    let mut presence = store.presence();
    let runtime = presence.start_runtime().unwrap();
    let link = presence.connect(runtime, DEVICE, 10).unwrap();
    assert_eq!(
        presence.node(DEVICE, 10).unwrap().connectivity,
        Connectivity::Online
    );
    assert_eq!(presence.agent(AGENT, 10).unwrap(), None);

    managed(&mut presence, link, 10, 1, Readiness::Ready);
    assert_eq!(
        presence.agent(AGENT, 10).unwrap().unwrap().status(),
        Status::Idle
    );
    for (revision, (execution, status)) in [
        (Execution::Idle, Status::Idle),
        (Execution::Queued, Status::Queued),
        (Execution::Running, Status::Running),
        (Execution::Approval, Status::Approval),
        (Execution::Recovering, Status::Recovering),
        (Execution::Failed, Status::Failed),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 11 + revision as u64;
        presence
            .observe_session(
                link,
                AGENT.id,
                SESSION,
                observed(at, 1 + revision as u64),
                SessionLifecycle::Open,
                execution,
            )
            .unwrap();
        let session = presence.session(AGENT, SESSION, at).unwrap().unwrap();
        assert_eq!(session.execution, execution);
        assert_eq!(session.status(), status);
        assert_eq!(session.wakeable(), execution == Execution::Idle);
    }

    assert!(matches!(
        presence.observe_session(
            link,
            AGENT.id,
            SESSION,
            observed(17, 7),
            SessionLifecycle::Closed,
            Execution::Running,
        ),
        Err(Error::InactiveSession)
    ));
    managed(&mut presence, link, 17, 2, Readiness::Unavailable);
    let session = presence.session(AGENT, SESSION, 17).unwrap().unwrap();
    assert_eq!(session.agent.node.connectivity, Connectivity::Online);
    assert_eq!(session.agent.readiness, Readiness::Unavailable);
    assert_eq!(session.execution, Execution::Failed);
    assert_eq!(session.status(), Status::Offline);
    assert!(!session.wakeable());
}

#[test]
fn disconnect_and_restart_require_fresh_agent_and_session_observations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mesh.db");
    let mut store = DeliveryStore::open(&path, &KEY, DEVICE).unwrap();
    let mut presence = store.presence();
    let runtime = presence.start_runtime().unwrap();
    let initial = presence.connect(runtime, DEVICE, 10).unwrap();
    managed(&mut presence, initial, 10, 1, Readiness::Ready);
    presence
        .observe_session(
            initial,
            AGENT.id,
            SESSION,
            observed(11, 1),
            SessionLifecycle::Open,
            Execution::Approval,
        )
        .unwrap();

    let mut reader = DeliveryStore::open(&path, &KEY, DEVICE).unwrap();
    assert_eq!(
        reader
            .presence()
            .session(AGENT, SESSION, 11)
            .unwrap()
            .unwrap()
            .status(),
        Status::Approval
    );
    presence.disconnect(initial, 12).unwrap();
    let disconnected = reader
        .presence()
        .session(AGENT, SESSION, 12)
        .unwrap()
        .unwrap();
    assert_eq!(disconnected.status(), Status::Offline);
    assert_eq!(disconnected.lifecycle, SessionLifecycle::Recovering);
    assert_eq!(disconnected.execution, Execution::Recovering);
    assert!(!disconnected.wakeable());

    let reconnected = presence.connect(runtime, DEVICE, 13).unwrap();
    assert!(matches!(presence.heartbeat(initial, 13), Err(Error::Stale)));
    assert!(matches!(
        presence.disconnect(initial, 13),
        Err(Error::Stale)
    ));
    let status = presence.agent(AGENT, 13).unwrap().unwrap();
    assert_eq!(status.node.connectivity, Connectivity::Online);
    assert_eq!(status.status(), Status::Offline);
    managed(&mut presence, reconnected, 14, 1, Readiness::Ready);
    let recovering = presence.session(AGENT, SESSION, 14).unwrap().unwrap();
    assert_eq!(recovering.status(), Status::Recovering);
    assert!(!recovering.wakeable());

    drop(store);
    let mut restarted = DeliveryStore::open(&path, &KEY, DEVICE).unwrap();
    let mut restarted = restarted.presence();
    let fresh_runtime = restarted.start_runtime().unwrap();
    assert!(matches!(
        restarted.connect(runtime, DEVICE, 15),
        Err(Error::Stale)
    ));
    assert!(matches!(
        restarted.heartbeat(reconnected, 15),
        Err(Error::Stale)
    ));
    let old = restarted.session(AGENT, SESSION, 15).unwrap().unwrap();
    assert_eq!(old.status(), Status::Offline);
    assert_eq!(old.execution, Execution::Recovering);
    assert_eq!(old.last_observed_at, 11);
    assert_eq!(old.agent.capabilities.version.as_deref(), Some("1.2"));
    assert!(!old.agent.capabilities_fresh);

    let active = restarted.connect(fresh_runtime, DEVICE, 16).unwrap();
    managed(&mut restarted, active, 16, 1, Readiness::Ready);
    restarted
        .observe_session(
            active,
            AGENT.id,
            SESSION,
            observed(16, 1),
            SessionLifecycle::Open,
            Execution::Idle,
        )
        .unwrap();
    assert!(
        restarted
            .session(AGENT, SESSION, 16)
            .unwrap()
            .unwrap()
            .wakeable()
    );
    restarted
        .observe_session(
            active,
            AGENT.id,
            SESSION,
            observed(17, 2),
            SessionLifecycle::Closed,
            Execution::Idle,
        )
        .unwrap();
    assert!(matches!(
        restarted.observe_session(
            active,
            AGENT.id,
            SESSION,
            observed(18, 3),
            SessionLifecycle::Open,
            Execution::Idle
        ),
        Err(Error::Stale)
    ));
    let closed = restarted.session(AGENT, SESSION, 18).unwrap().unwrap();
    assert_eq!(closed.lifecycle, SessionLifecycle::Closed);
    assert!(!closed.wakeable());
}

#[test]
fn capability_expiry_and_old_revisions_do_not_reenable_wake() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = DeliveryStore::open(&dir.path().join("mesh.db"), &KEY, DEVICE).unwrap();
    let mut presence = store.presence();
    let runtime = presence.start_runtime().unwrap();
    let link = presence.connect(runtime, DEVICE, 10).unwrap();
    managed(&mut presence, link, 10, 1, Readiness::Ready);
    let expiry = 10 + PRESENCE_TTL_SECS;
    presence.heartbeat(link, expiry - 1).unwrap();
    assert!(
        presence
            .agent(AGENT, expiry - 1)
            .unwrap()
            .unwrap()
            .wakeable()
    );
    let expired = presence.agent(AGENT, expiry).unwrap().unwrap();
    assert_eq!(expired.node.connectivity, Connectivity::Online);
    assert_eq!(expired.status(), Status::Offline);
    assert!(!expired.capabilities_fresh);
    assert_eq!(expired.capabilities_observed_at, 10);
    assert!(!expired.wakeable());
    assert!(matches!(
        presence.observe_agent(
            link,
            AGENT.id,
            observed(expiry, 1),
            AgentKind::ManagedAcp,
            Readiness::Ready,
            &capabilities()
        ),
        Err(Error::Stale)
    ));
    managed(&mut presence, link, expiry, 2, Readiness::Ready);
    assert!(presence.agent(AGENT, expiry).unwrap().unwrap().wakeable());
    assert!(
        !presence
            .agent(AGENT, expiry - 1)
            .unwrap()
            .unwrap()
            .wakeable()
    );
    assert_eq!(
        presence.node(DEVICE, expiry * 2).unwrap().connectivity,
        Connectivity::Offline
    );
    assert!(matches!(
        presence.heartbeat(link, expiry * 2),
        Err(Error::Stale)
    ));
}

#[test]
fn unmanaged_agents_are_visible_and_cannot_gain_managed_wake() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = DeliveryStore::open(&dir.path().join("mesh.db"), &KEY, DEVICE).unwrap();
    let mut presence = store.presence();
    let runtime = presence.start_runtime().unwrap();
    let link = presence.connect(runtime, DEVICE, 10).unwrap();
    let mut external = capabilities();
    assert!(matches!(
        presence.observe_agent(
            link,
            AGENT.id,
            observed(10, 1),
            AgentKind::ExternalMcp,
            Readiness::Ready,
            &external
        ),
        Err(Error::Capabilities)
    ));
    external.prompt = false;
    external.cancel = false;
    external.load_session = false;
    external.close_session = false;
    external.harness = "external\nagent".into();
    assert!(matches!(
        presence.observe_agent(
            link,
            AGENT.id,
            observed(10, 1),
            AgentKind::ExternalMcp,
            Readiness::Ready,
            &external
        ),
        Err(Error::Capabilities)
    ));
    external.harness = "external-mcp".into();
    presence
        .observe_agent(
            link,
            AGENT.id,
            observed(10, 1),
            AgentKind::ExternalMcp,
            Readiness::Ready,
            &external,
        )
        .unwrap();
    let agent = presence.agent(AGENT, 10).unwrap().unwrap();
    assert_eq!(agent.kind, AgentKind::ExternalMcp);
    assert!(agent.capabilities.mcp);
    assert_eq!(agent.status(), Status::Idle);
    assert!(!agent.wakeable());
    assert!(matches!(
        presence.observe_agent(
            link,
            AGENT.id,
            observed(11, 2),
            AgentKind::ManagedAcp,
            Readiness::Ready,
            &capabilities()
        ),
        Err(Error::Stale)
    ));
    assert!(!presence.agent(AGENT, 11).unwrap().unwrap().wakeable());
}
