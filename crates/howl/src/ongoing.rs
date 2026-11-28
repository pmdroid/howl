mod context;
mod github;
mod tokens;
mod work;

pub(crate) use work::WorkTools;

use std::{
    collections::HashSet,
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use agent_client_protocol::v1::schema::StopReason;
use serde::{Deserialize, Deserializer, de};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    sync::{broadcast, watch},
    task::JoinSet,
    time::{interval, timeout},
};

use crate::{
    channel::Channel,
    delivery::{DeliveryStore, Id, OngoingInput, OngoingSchedule, OngoingSource, OngoingThread},
    enrollment::ChannelPermission,
    identity::{LocalIdentity, PeerTrust, StateDirectory},
    managed_acp::{Harness, ManagedSession},
    node,
    observer::{ObserverProvider, Snapshot},
    workflow::ReplyBuffer,
};

const TICK: Duration = Duration::from_secs(1);
const TURN_LIMIT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    model: Option<String>,
    context: Option<context::Policy>,
    conversations: Vec<Conversation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Conversation {
    #[serde(deserialize_with = "decode_id")]
    channel: Id,
    #[serde(deserialize_with = "decode_id")]
    peer: Id,
    integration: Option<String>,
    shared_thread: Option<String>,
    route: Option<String>,
    repository: PathBuf,
    revision: String,
    #[serde(default)]
    work: bool,
    #[serde(skip)]
    work_policy: Option<Id>,
    #[serde(default)]
    work_control_from: Vec<String>,
    #[serde(skip)]
    forwards_work_commands: bool,
    #[serde(default)]
    peers: Vec<AgentPeer>,
    #[serde(default)]
    schedules: Vec<Schedule>,
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AgentPeer {
    #[serde(deserialize_with = "decode_id")]
    id: Id,
    route: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    github_pull_requests: Option<String>,
    name: String,
    seconds: i64,
    instruction: String,
}

fn valid_thread_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

impl Conversation {
    fn validate(&mut self) -> io::Result<Option<Id>> {
        let origin = self.integration.as_deref().map(parse_id).transpose()?;
        if self
            .shared_thread
            .as_deref()
            .is_some_and(|name| !valid_thread_name(name))
        {
            return Err(invalid("invalid shared thread name"));
        }
        if self.work_control_from.len() > 4
            || (!self.work_control_from.is_empty() && (!self.work || origin.is_some()))
        {
            return Err(invalid(
                "work control delegates require a human conversation with work enabled",
            ));
        }
        for delegate in &mut self.work_control_from {
            *delegate = hex::encode_upper(parse_id(delegate)?);
        }
        node::parse_route(self.route().as_bytes())?;
        let mut peers = HashSet::new();
        if self.peers.len() > 8
            || self.peers.iter().any(|peer| {
                peer.id == self.peer
                    || !peers.insert(peer.id)
                    || peer.name.as_ref().is_some_and(|name| name.len() > 64)
            })
        {
            return Err(invalid("invalid conversation peers"));
        }
        for peer in &self.peers {
            node::parse_route(peer.route.as_deref().unwrap_or("-").as_bytes())?;
        }
        let mut names = HashSet::new();
        if !self.repository.is_absolute()
            || self.revision.trim().is_empty()
            || self.schedules.len() > 8
            || self.schedules.iter().any(|schedule| {
                schedule
                    .github_pull_requests
                    .as_deref()
                    .is_some_and(|name| !github::valid_repository(name))
                    || schedule.name.is_empty()
                    || !names.insert(&schedule.name)
                    || !(60..=31_536_000).contains(&schedule.seconds)
                    || schedule.instruction.trim().is_empty()
                    || schedule.instruction.len() > 4096
            })
        {
            return Err(invalid("invalid agent conversation or schedule"));
        }
        self.repository = self.repository.canonicalize()?;
        self.revision = self.revision.trim().to_owned();
        Ok(origin)
    }

    fn route(&self) -> &str {
        self.route.as_deref().unwrap_or("-")
    }

    fn schedules(&self) -> Vec<OngoingSchedule> {
        self.schedules
            .iter()
            .map(|schedule| {
                let mut hash = Sha256::new()
                    .chain_update(schedule.seconds.to_be_bytes())
                    .chain_update(schedule.name.as_bytes())
                    .chain_update([0])
                    .chain_update(schedule.instruction.as_bytes());
                if let Some(repo) = &schedule.github_pull_requests {
                    hash = Sha256::new()
                        .chain_update(b"howl/github-pr-schedule/v1")
                        .chain_update(hash.finalize())
                        .chain_update(repo.as_bytes());
                }
                OngoingSchedule {
                    id: hash.finalize().into(),
                    seconds: schedule.seconds,
                    text: schedule.instruction.clone(),
                    github_pull_requests: schedule.github_pull_requests.clone(),
                }
            })
            .collect()
    }
}

struct AgentContext<F> {
    context_policy: Option<context::Policy>,
    state: PathBuf,
    observer: ObserverProvider,
    identity: LocalIdentity,
    profile: Id,
    microvm: Option<crate::microvm::Profile>,
    sending_peer: Arc<tokio::sync::Mutex<()>>,
    harness: F,
}

pub async fn serve<F>(state: &Path, observer: ObserverProvider, harness: F) -> io::Result<()>
where
    F: Fn() -> io::Result<Harness> + Send + Sync + 'static,
{
    let directory = StateDirectory::open(state)?;
    let _lock = directory.lock("ongoing-agent.lock")?;
    let bytes = directory.read_bounded("conversations.json", 65_536)?;
    let mut config: Configuration = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if config.conversations.is_empty() || config.conversations.len() > 8 {
        return Err(invalid("configure one to eight conversations"));
    }
    let mut keys = HashSet::new();
    let mut conversations = Vec::new();
    for mut conversation in config.conversations.drain(..) {
        let origin = conversation.validate()?;
        if !keys.insert((conversation.channel, conversation.peer, origin)) {
            return Err(invalid("duplicate agent conversation"));
        }
        conversations.push((conversation, origin));
    }
    let mut delegates = HashSet::new();
    for (owner, _) in &conversations {
        for delegate in &owner.work_control_from {
            delegates.insert((owner.channel, owner.peer, parse_id(delegate)?));
        }
    }
    for (conversation, origin) in &mut conversations {
        conversation.forwards_work_commands = origin
            .is_some_and(|id| delegates.contains(&(conversation.channel, conversation.peer, id)));
        if conversation.forwards_work_commands && conversation.work {
            return Err(invalid("a work control delegate cannot also own workers"));
        }
    }
    if let Some(policy) = &config.context {
        policy.budget()?;
    }
    let profile = harness()?.fingerprint();
    let model = config.model;
    let harness = move || {
        let agent = harness()?;
        match &model {
            Some(model) => agent.with_model(model),
            None => Ok(agent),
        }
    };
    harness()?;
    let microvm = conversations
        .iter()
        .any(|(conversation, _)| conversation.work)
        .then(|| crate::microvm::Profile::load(state))
        .transpose()?;
    let identity = LocalIdentity::load_or_create(state)?;
    let mut work_policies = Vec::new();
    for (conversation, origin) in &mut conversations {
        if let Some(guest) = microvm.as_ref().filter(|_| conversation.work) {
            let binding = serde_json::to_vec(&(
                "howl/work-policy/v1",
                identity.certificate().device_id(),
                profile,
                conversation.channel,
                conversation.peer,
                origin,
                &conversation.repository,
                &conversation.revision,
                &conversation.work_control_from,
                guest,
            ))
            .map_err(io::Error::other)?;
            let policy = Id::from(Sha256::digest(binding));
            conversation.work_policy = Some(policy);
            work_policies.push(policy);
        }
    }
    node::open_delivery(state, &directory, &identity.certificate())?
        .recover_work(&work_policies)
        .map_err(io::Error::other)?;
    ManagedSession::reap_observers(&state.join("ongoing-acp"), &observer)
        .map_err(io::Error::other)?;
    let context = Arc::new(AgentContext {
        context_policy: config.context,
        state: state.to_owned(),
        observer,
        identity,
        profile,
        microvm,
        sending_peer: Default::default(),
        harness,
    });
    let (stop, stopping) = watch::channel(false);
    let mut threads = JoinSet::new();
    let shared_groups: Vec<_> = conversations
        .iter()
        .map(|(conversation, _)| {
            let name = conversation.shared_thread.as_ref()?;
            let mut members: Vec<_> = conversations
                .iter()
                .filter(|(other, _)| {
                    other.channel == conversation.channel
                        && other.shared_thread == conversation.shared_thread
                        && other.repository == conversation.repository
                        && other.revision == conversation.revision
                })
                .map(|(other, origin)| (other.peer, *origin))
                .collect();
            members.sort();
            let bytes = serde_json::to_vec(&(
                name,
                members,
                &conversation.repository,
                &conversation.revision,
            ))
            .ok()?;
            Some(Id::from(Sha256::digest(bytes)))
        })
        .collect();
    for ((conversation, origin), group) in conversations.into_iter().zip(shared_groups) {
        let conversation = Arc::new(conversation);
        if conversation.work {
            threads.spawn(work::serve(
                context.clone(),
                conversation.clone(),
                origin,
                stopping.clone(),
            ));
        }
        threads.spawn(run(
            context.clone(),
            conversation,
            origin,
            group,
            stopping.clone(),
        ));
    }
    let outcome = tokio::select! {
        signal = tokio::signal::ctrl_c() => signal,
        thread = threads.join_next() => thread.ok_or_else(|| io::Error::other("agent runner stopped"))?
            .map_err(io::Error::other)?,
    };
    stop.send_replace(true);
    let _ = timeout(Duration::from_secs(8), async {
        while threads.join_next().await.is_some() {}
    })
    .await;
    outcome
}

async fn run<F>(
    context: Arc<AgentContext<F>>,
    conversation: Arc<Conversation>,
    origin: Option<Id>,
    group: Option<Id>,
    mut stopping: watch::Receiver<bool>,
) -> io::Result<()>
where
    F: Fn() -> io::Result<Harness> + Send + Sync + 'static,
{
    let directory = StateDirectory::open(&context.state)?;
    let mut delivery =
        node::open_delivery(&context.state, &directory, &context.identity.certificate())?;
    let mut turns: JoinSet<FinishedTurn> = JoinSet::new();
    let (cancel_turns, _) = watch::channel(());
    let mut active = None;
    let mut session = None;
    let schedules = conversation.schedules();
    let delegates =
        serde_json::to_string(&conversation.work_control_from).map_err(io::Error::other)?;
    let mut tick = interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stopping.changed() => break,
            Some(done) = turns.join_next() => {
                let done = done.map_err(io::Error::other)?;
                delivery.finish_ongoing(done.id, &done.text, done.success).map_err(io::Error::other)?;
                if done.session.is_some() {
                    session = done.session;
                }
            }
            _ = tick.tick() => {},
        }
        let thread = match authorized(&context, &conversation, origin) {
            Ok(thread) => thread,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                close(&mut session).await;
                stop_turns(&cancel_turns, &mut turns).await?;
                active = None;
                continue;
            }
            Err(error) => return Err(error),
        };
        if active != Some(thread.scope) {
            close(&mut session).await;
            stop_turns(&cancel_turns, &mut turns).await?;
            delivery.prepare_thread(thread).map_err(io::Error::other)?;
            active = Some(thread.scope);
        }
        if let Some(publication) = delivery
            .pending_ongoing(thread.scope)
            .map_err(io::Error::other)?
        {
            node::queue_ongoing_reply(
                &context.state,
                &context.identity,
                &mut delivery,
                thread,
                conversation.route(),
                &publication,
            )?;
        }
        if turns.len() >= 2 {
            continue;
        }
        let shared = group.map(|group| {
            Id::from(
                Sha256::new()
                    .chain_update(b"howl/shared-thread/v1")
                    .chain_update(context.profile)
                    .chain_update(thread.channel)
                    .chain_update(thread.epoch.to_be_bytes())
                    .chain_update(group)
                    .finalize(),
            )
        });
        let now = i64::try_from(node::unix_time()?).map_err(io::Error::other)?;
        let Some(input) = delivery
            .next_ongoing(
                thread,
                &schedules,
                &delegates,
                conversation.forwards_work_commands,
                conversation.shared_thread.as_deref().zip(shared),
                now,
            )
            .map_err(io::Error::other)?
        else {
            continue;
        };
        if conversation.work
            && input.source == OngoingSource::DirectMessage
            && let Some(reply) = work::command(&delivery, thread.scope, &input.text)?
        {
            delivery
                .finish_ongoing(input.id, &reply, false)
                .map_err(io::Error::other)?;
            continue;
        }
        if input.source == OngoingSource::DirectMessage
            && input.text.starts_with("/thread ")
            && input.shared.is_none()
        {
            delivery
                .finish_ongoing(
                    input.id,
                    "Use /thread NAME MESSAGE with a configured shared thread.",
                    false,
                )
                .map_err(io::Error::other)?;
            continue;
        }
        let reusable =
            context.context_policy.is_none() && input.shared.is_none() && turns.is_empty();
        let mut current = if reusable { session.take() } else { None };
        let context = context.clone();
        let conversation = conversation.clone();
        let mut stopping = cancel_turns.subscribe();
        turns.spawn(async move {
            let result = turn(
                &context,
                &conversation,
                thread,
                &input,
                &mut current,
                &mut stopping,
            )
            .await;
            if !reusable || result.is_err() {
                close(&mut current).await;
            }
            let (text, success) = match result {
                Ok(text) => (text, true),
                Err(error) => {
                    eprintln!("Howl conversation failed. {error}");
                    let message = if error.kind() == io::ErrorKind::InvalidInput
                        && error.to_string().starts_with("Howl context: ")
                    {
                        error.to_string()
                    } else {
                        "Agent turn ended without a reply. Send another message to continue.".into()
                    };
                    (message, false)
                }
            };
            FinishedTurn {
                id: input.id,
                text,
                success,
                session: current,
            }
        });
    }
    stop_turns(&cancel_turns, &mut turns).await?;
    close(&mut session).await;
    Ok(())
}

struct FinishedTurn {
    id: i64,
    text: String,
    success: bool,
    session: Option<ManagedSession>,
}

async fn stop_turns(
    cancel: &watch::Sender<()>,
    turns: &mut JoinSet<FinishedTurn>,
) -> io::Result<()> {
    cancel.send_replace(());
    while let Some(done) = turns.join_next().await {
        close(&mut done.map_err(io::Error::other)?.session).await;
    }
    Ok(())
}

fn authorized<F>(
    context: &AgentContext<F>,
    conversation: &Conversation,
    origin: Option<Id>,
) -> io::Result<OngoingThread> {
    let local = context.identity.certificate();
    let roster = Channel::load(&context.state, &context.identity, &conversation.channel)?;
    for permission in [ChannelPermission::Receive, ChannelPermission::Send] {
        if !roster.allows(local.device_id(), permission)
            || !roster.allows(&conversation.peer, permission)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "conversation permission revoked",
            ));
        }
    }
    let peer = PeerTrust::open(&context.state)?.pinned(&conversation.peer)?;
    let peer = node::device_for(&context.state, &peer)?;
    let epoch = roster.epoch();
    let scope = Sha256::new()
        .chain_update(b"howl/ongoing-thread/v1\0")
        .chain_update(context.profile)
        .chain_update(conversation.channel)
        .chain_update(peer.device)
        .chain_update(peer.account)
        .chain_update(epoch.to_be_bytes())
        .chain_update([u8::from(origin.is_some())])
        .chain_update(origin.unwrap_or_default())
        .chain_update(conversation.repository.as_os_str().as_encoded_bytes())
        .finalize()
        .into();
    Ok(OngoingThread {
        scope,
        channel: conversation.channel,
        peer,
        epoch,
        origin,
    })
}

async fn turn<F>(
    context: &AgentContext<F>,
    conversation: &Conversation,
    thread: OngoingThread,
    input: &OngoingInput,
    session: &mut Option<ManagedSession>,
    stopping: &mut watch::Receiver<()>,
) -> io::Result<String>
where
    F: Fn() -> io::Result<Harness>,
{
    let run = async {
        let text = context::build(context, conversation, thread, input).await?;
        if session.is_none() {
            let snapshot =
                Snapshot::from_repository(&conversation.repository, &conversation.revision)
                    .map_err(io::Error::other)?;
            let mut harness = (context.harness)()?;
            if conversation.work || !conversation.peers.is_empty() {
                harness = harness.with_work_tools(WorkTools::new(
                    context.state.clone(),
                    thread,
                    conversation,
                    &snapshot,
                    context.sending_peer.clone(),
                ));
            }
            *session = Some(
                ManagedSession::start(
                    &context.state.join("ongoing-acp"),
                    &context.observer,
                    snapshot,
                    harness,
                )
                .await
                .map_err(io::Error::other)?,
            );
        }
        let session = session
            .as_ref()
            .ok_or_else(|| io::Error::other("ACP session unavailable"))?;
        session.conversation_source(input.source, input.id);
        prompt(session, text, TURN_LIMIT).await
    };
    tokio::pin!(run);
    let mut guard = interval(TICK);
    loop {
        tokio::select! {
            _ = stopping.changed() => return Err(io::ErrorKind::Interrupted.into()),
            _ = guard.tick() => {
                if authorized(context, conversation, thread.origin)?.scope != thread.scope {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
            }
            result = &mut run => return result,
        }
    }
}

pub(crate) async fn prompt(
    session: &ManagedSession,
    text: String,
    limit: Duration,
) -> io::Result<String> {
    let mut events = session.subscribe();
    let mut reply = ReplyBuffer::default();
    let run = session.prompt(text, limit);
    tokio::pin!(run);
    loop {
        tokio::select! {
            event = events.recv() => reply.receive(event.map_err(io::Error::other)?)?,
            result = &mut run => {
                if !matches!(result.map_err(io::Error::other)?, StopReason::EndTurn) {
                    return Err(io::Error::other("agent turn did not finish"));
                }
                loop {
                    match events.try_recv() {
                        Ok(event) => reply.receive(event)?,
                        Err(broadcast::error::TryRecvError::Empty) => return reply.finish(),
                        Err(error) => return Err(io::Error::other(error)),
                    }
                }
            }
        }
    }
}

async fn close(session: &mut Option<ManagedSession>) {
    if let Some(session) = session.take() {
        let _ = timeout(Duration::from_secs(2), session.cancel()).await;
        let _ = timeout(Duration::from_secs(5), async {
            let _ = session.close().await;
            let _ = session.wait_for_observer_stop().await;
        })
        .await;
    }
}

fn decode_id<'de, D: Deserializer<'de>>(input: D) -> Result<Id, D::Error> {
    parse_id(&String::deserialize(input)?).map_err(de::Error::custom)
}

fn parse_id(value: &str) -> io::Result<Id> {
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id).map_err(|_| invalid("invalid conversation ID"))?;
    Ok(id)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
