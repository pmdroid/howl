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
    delivery::{DeliveryStore, Id, OngoingInput, OngoingSchedule, OngoingThread},
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
    route: Option<String>,
    repository: PathBuf,
    revision: String,
    #[serde(default)]
    schedules: Vec<Schedule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    name: String,
    seconds: i64,
    instruction: String,
}

impl Conversation {
    fn validate(&mut self) -> io::Result<Option<Id>> {
        let origin = self.integration.as_deref().map(parse_id).transpose()?;
        node::parse_route(self.route().as_bytes())?;
        let mut names = HashSet::new();
        if !self.repository.is_absolute()
            || self.revision.trim().is_empty()
            || self.schedules.len() > 8
            || self.schedules.iter().any(|schedule| {
                schedule.name.is_empty()
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
            .map(|schedule| OngoingSchedule {
                id: Sha256::new()
                    .chain_update(schedule.seconds.to_be_bytes())
                    .chain_update(schedule.name.as_bytes())
                    .chain_update([0])
                    .chain_update(schedule.instruction.as_bytes())
                    .finalize()
                    .into(),
                seconds: schedule.seconds,
                text: schedule.instruction.clone(),
            })
            .collect()
    }
}

struct AgentContext<F> {
    state: PathBuf,
    observer: ObserverProvider,
    identity: LocalIdentity,
    profile: Id,
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
    let profile = harness()?.fingerprint();
    let identity = LocalIdentity::load_or_create(state)?;
    ManagedSession::reap_observers(&state.join("ongoing-acp"), &observer)
        .map_err(io::Error::other)?;
    let context = Arc::new(AgentContext {
        state: state.to_owned(),
        observer,
        identity,
        profile,
        harness,
    });
    let (stop, stopping) = watch::channel(false);
    let mut threads = JoinSet::new();
    for (conversation, origin) in conversations {
        threads.spawn(run(context.clone(), conversation, origin, stopping.clone()));
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
    conversation: Conversation,
    origin: Option<Id>,
    mut stopping: watch::Receiver<bool>,
) -> io::Result<()>
where
    F: Fn() -> io::Result<Harness> + Send + Sync + 'static,
{
    let directory = StateDirectory::open(&context.state)?;
    let mut delivery =
        node::open_delivery(&context.state, &directory, &context.identity.certificate())?;
    let mut active = None;
    let mut session = None;
    let schedules = conversation.schedules();
    let mut tick = interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stopping.changed() => break,
            _ = tick.tick() => {},
        }
        let thread = match authorized(&context, &conversation, origin) {
            Ok(thread) => thread,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                close(&mut session).await;
                active = None;
                continue;
            }
            Err(error) => return Err(error),
        };
        if active != Some(thread.scope) {
            close(&mut session).await;
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
        let now = i64::try_from(node::unix_time()?).map_err(io::Error::other)?;
        let Some(input) = delivery
            .next_ongoing(thread, &schedules, now)
            .map_err(io::Error::other)?
        else {
            continue;
        };
        let result = match turn(
            &context,
            &conversation,
            thread,
            &input,
            &mut delivery,
            &mut session,
            &mut stopping,
        )
        .await
        {
            Ok(text) => (text, true),
            Err(error) => {
                eprintln!("Howl conversation failed. {error}");
                close(&mut session).await;
                (
                    "Agent turn ended without a reply. Send another message to continue."
                        .to_owned(),
                    false,
                )
            }
        };
        delivery
            .finish_ongoing(input.id, &result.0, result.1)
            .map_err(io::Error::other)?;
        if *stopping.borrow() {
            break;
        }
    }
    close(&mut session).await;
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
    delivery: &mut DeliveryStore,
    session: &mut Option<ManagedSession>,
    stopping: &mut watch::Receiver<bool>,
) -> io::Result<String>
where
    F: Fn() -> io::Result<Harness>,
{
    let mut history = if session.is_none() {
        delivery
            .ongoing_history(thread.scope)
            .map_err(io::Error::other)?
    } else {
        Vec::new()
    };
    let directive = "Continue the Howl conversation. Earlier exchanges are context. Respond to the current input. Repository tools use the approved read-only snapshot.";
    let text = loop {
        let data = json!({ "source": if input.scheduled { "schedule" } else { "direct_message" }, "input": input.text, "earlier_exchanges": history });
        let text = format!("{directive}\n{data}");
        if text.len() <= 60 * 1024 {
            break text;
        }
        if history.is_empty() {
            return Err(invalid("conversation input is too large"));
        }
        history.remove(0);
    };
    let run = async {
        if session.is_none() {
            let snapshot =
                Snapshot::from_repository(&conversation.repository, &conversation.revision)
                    .map_err(io::Error::other)?;
            *session = Some(
                ManagedSession::start(
                    &context.state.join("ongoing-acp"),
                    &context.observer,
                    snapshot,
                    (context.harness)()?,
                )
                .await
                .map_err(io::Error::other)?,
            );
        }
        prompt(
            session
                .as_ref()
                .ok_or_else(|| io::Error::other("ACP session unavailable"))?,
            text,
        )
        .await
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

async fn prompt(session: &ManagedSession, text: String) -> io::Result<String> {
    let mut events = session.subscribe();
    let mut reply = ReplyBuffer::default();
    let run = session.prompt(text, TURN_LIMIT);
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
