mod journal;

use std::{
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use agent_client_protocol::{
    Agent, Client, ConnectTo, Lines,
    schema::ProtocolVersion,
    v1::{
        ConnectionTo, SentRequest,
        schema::{
            CancelNotification, CloseSessionRequest, InitializeRequest, LoadSessionRequest,
            NewSessionRequest, PermissionOptionKind, PromptRequest, RequestPermissionOutcome,
            RequestPermissionRequest, RequestPermissionResponse, ResumeSessionRequest,
            SelectedPermissionOutcome, SessionId, SessionNotification, StopReason,
        },
    },
};
use futures_util::{SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    process::{ChildStderr, ChildStdin, ChildStdout},
    sync::{broadcast, mpsc, oneshot, watch},
    time::{Instant, sleep, timeout},
};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

use crate::observer::{ObserverProcess, ObserverProvider, Snapshot, WORKSPACE};
use crate::provider_broker::{self, Broker, Provider};
use journal::Journal;

const REQUEST_LIMIT: Duration = Duration::from_secs(25);
const CANCEL_GRACE: Duration = Duration::from_secs(2);
const MAX_PROMPT: usize = 64 * 1024;
const MAX_ACP_MESSAGE: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("observer launch failed")]
    Observer(#[from] crate::observer::Error),
    #[error(transparent)]
    Provider(#[from] provider_broker::Error),
    #[error("managed session storage or pipes failed")]
    Io(#[from] io::Error),
    #[error("invalid managed session state")]
    State,
    #[error("the session is supervised by another process")]
    InUse,
    #[error("recovery requires the original approved snapshot and harness")]
    ScopeChanged,
    #[error("the managed session is closed")]
    Closed,
    #[error("the session already has an active turn")]
    Busy,
    #[error("the session has no active turn")]
    Idle,
    #[error("ACP process disconnected")]
    Disconnected,
    #[error("ACP request timed out")]
    TimedOut,
    #[error("ACP agent does not support {0}")]
    Unsupported(&'static str),
    #[error("ACP agent rejected the request (code {0})")]
    Remote(i32),
    #[error("invalid ACP prompt or time limit")]
    Prompt,
}

type Result<T> = std::result::Result<T, Error>;

pub struct Harness {
    name: String,
    image: String,
    executable: PathBuf,
    args: Vec<String>,
    provider: Option<(Provider, String)>,
}

impl Harness {
    pub fn codex(image: String) -> Self {
        Self::new("codex", image, "/usr/local/bin/codex-acp", &[])
    }

    pub fn grok(image: String) -> Self {
        Self::new(
            "grok",
            image,
            "/usr/local/bin/grok",
            &[
                "--no-auto-update",
                "agent",
                "stdio",
                "--leader-socket",
                "/scratch/grok.sock",
            ],
        )
    }

    pub fn new(name: &str, image: String, executable: impl Into<PathBuf>, args: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            image,
            executable: executable.into(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            provider: None,
        }
    }

    pub fn with_provider(mut self, provider: Provider, model: &str) -> Self {
        self.provider = Some((provider, model.to_owned()));
        self
    }

    fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"howl/observer-harness/v1\0");
        for value in [
            self.name.as_bytes(),
            self.image.as_bytes(),
            self.executable.as_os_str().as_bytes(),
        ]
        .into_iter()
        .chain(self.args.iter().map(String::as_bytes))
        {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        if let Some((provider, model)) = &self.provider {
            hash.update(b"provider");
            hash.update([provider.tag()]);
            hash.update((model.len() as u64).to_be_bytes());
            hash.update(model.as_bytes());
        }
        hash.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    pub load: bool,
    pub resume: bool,
    pub close: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Starting,
    Ready,
    Active,
    Interrupted,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionState {
    pub id: String,
    pub harness: String,
    pub commit: String,
    pub snapshot: [u8; 32],
    pub profile: [u8; 32],
    pub engine: String,
    pub remote_session: Option<String>,
    pub container: Option<String>,
    pub capabilities: Capabilities,
    pub phase: Phase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Restore {
    Fresh,
    Load,
    Resume,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Close {
    Remote,
    Local,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionDecision {
    RejectOnce,
    Cancelled,
}

#[derive(Clone, Debug)]
pub enum Event {
    Update(Box<SessionNotification>),
    Permission {
        offered: Vec<PermissionOptionKind>,
        decision: PermissionDecision,
    },
}

pub struct ManagedSession {
    commands: mpsc::Sender<Command>,
    status: watch::Receiver<SessionState>,
    events: broadcast::Sender<Event>,
}

impl ManagedSession {
    pub async fn start(
        root: &Path,
        provider: &ObserverProvider,
        snapshot: Snapshot,
        harness: Harness,
    ) -> Result<Self> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let id = hex::encode(random);
        Self::open(root, provider, snapshot, harness, id, None).await
    }

    pub async fn recover(
        root: &Path,
        provider: &ObserverProvider,
        snapshot: Snapshot,
        harness: Harness,
        id: &str,
        restore: Restore,
    ) -> Result<Self> {
        if id.len() != 32
            || !id
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(Error::State);
        }
        Self::open(
            root,
            provider,
            snapshot,
            harness,
            id.to_owned(),
            Some(restore),
        )
        .await
    }

    async fn open(
        root: &Path,
        provider: &ObserverProvider,
        snapshot: Snapshot,
        harness: Harness,
        id: String,
        restore: Option<Restore>,
    ) -> Result<Self> {
        let broker = harness
            .provider
            .as_ref()
            .map(|(provider, model)| Broker::from_environment(*provider, model))
            .transpose()?;
        Self::open_with_broker(root, provider, snapshot, harness, id, restore, broker).await
    }

    async fn open_with_broker(
        root: &Path,
        provider: &ObserverProvider,
        snapshot: Snapshot,
        harness: Harness,
        id: String,
        restore: Option<Restore>,
        broker: Option<Broker>,
    ) -> Result<Self> {
        if harness.name.is_empty()
            || harness.name.len() > 64
            || !harness
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::State);
        }
        let expected = SessionState {
            id: id.clone(),
            harness: harness.name.clone(),
            commit: snapshot.commit().to_owned(),
            snapshot: snapshot.selection(),
            profile: harness.fingerprint(),
            engine: provider.engine_id().to_owned(),
            remote_session: None,
            container: None,
            capabilities: Capabilities::default(),
            phase: Phase::Starting,
        };
        let root = root.to_owned();
        let provider = provider.clone();
        let (journal, process) = tokio::task::spawn_blocking(move || -> Result<_> {
            let journal = if let Some(restore) = restore {
                let journal = Journal::existing(&root, expected)?;
                let state = journal.state();
                if state.phase == Phase::Closed {
                    return Err(Error::Closed);
                }
                check_restore(restore, &state)?;
                provider.reap_managed(&id)?;
                journal.update(|state| {
                    state.phase = Phase::Starting;
                    state.container = None;
                })?;
                journal
            } else {
                Journal::new(&root, expected)?
            };
            let args = harness.args.iter().map(String::as_str).collect::<Vec<_>>();
            match provider.launch_managed(
                &snapshot,
                &harness.image,
                &harness.executable,
                &args,
                &id,
            ) {
                Ok(process) => {
                    journal.update(|state| {
                        state.container = process.container_id().map(str::to_owned)
                    })?;
                    Ok((journal, process))
                }
                Err(error) => {
                    journal.update(|state| state.phase = Phase::Interrupted)?;
                    Err(error.into())
                }
            }
        })
        .await
        .map_err(|_| Error::Disconnected)??;

        let broker = if let Some(broker) = broker {
            match broker.attach(&process).await {
                Ok(task) => Some(task),
                Err(error) => {
                    journal.update(|state| state.phase = Phase::Interrupted)?;
                    return Err(error.into());
                }
            }
        } else {
            None
        };
        let status = journal.subscribe();
        let (commands, requests) = mpsc::channel(32);
        let (events, _) = broadcast::channel(64);
        let (ready, initialized) = oneshot::channel();
        tokio::spawn(supervise(
            process,
            broker,
            journal,
            requests,
            events.clone(),
            restore.unwrap_or(Restore::Fresh),
            ready,
        ));
        initialized.await.map_err(|_| Error::Disconnected)??;
        Ok(Self {
            commands,
            status,
            events,
        })
    }

    pub fn status(&self) -> SessionState {
        self.status.borrow().clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub async fn prompt(&self, text: String, limit: Duration) -> Result<StopReason> {
        if text.is_empty()
            || text.len() > MAX_PROMPT
            || limit.is_zero()
            || limit > Duration::from_secs(3600)
        {
            return Err(Error::Prompt);
        }
        self.request(|reply| Command::Prompt { text, limit, reply })
            .await
    }

    pub async fn cancel(&self) -> Result<()> {
        self.request(Command::Cancel).await
    }

    pub async fn restore(&self, mode: Restore) -> Result<()> {
        if mode == Restore::Fresh {
            return Err(Error::Unsupported("implicit session replacement"));
        }
        self.request(|reply| Command::Restore { mode, reply }).await
    }

    pub async fn close(&self) -> Result<Close> {
        self.request(Command::Close).await
    }

    async fn request<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<T>>) -> Command,
    ) -> Result<T> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(command(reply))
            .await
            .map_err(|_| Error::Disconnected)?;
        response.await.map_err(|_| Error::Disconnected)?
    }
}

enum Command {
    Prompt {
        text: String,
        limit: Duration,
        reply: oneshot::Sender<Result<StopReason>>,
    },
    Cancel(oneshot::Sender<Result<()>>),
    Restore {
        mode: Restore,
        reply: oneshot::Sender<Result<()>>,
    },
    Close(oneshot::Sender<Result<Close>>),
}

fn check_restore(mode: Restore, state: &SessionState) -> Result<()> {
    match mode {
        Restore::Fresh => Ok(()),
        Restore::Load if !state.capabilities.load => Err(Error::Unsupported("session/load")),
        Restore::Resume if !state.capabilities.resume => Err(Error::Unsupported("session/resume")),
        _ if state.remote_session.is_none() => Err(Error::State),
        _ => Ok(()),
    }
}

async fn supervise(
    mut process: ObserverProcess,
    _broker: Option<provider_broker::BrokerTask>,
    journal: Journal,
    requests: mpsc::Receiver<Command>,
    events: broadcast::Sender<Event>,
    restore: Restore,
    ready: oneshot::Sender<Result<()>>,
) {
    let result = (
        process.take_stdin().map(ChildStdin::from_std).transpose(),
        process.take_stdout().map(ChildStdout::from_std).transpose(),
        process.take_stderr().map(ChildStderr::from_std).transpose(),
    );
    let journal = Arc::new(journal);
    if let (Ok(Some(input)), Ok(Some(output)), Ok(Some(mut errors))) = result {
        let discard = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut errors, &mut tokio::io::sink()).await;
        });
        let outgoing = SinkExt::<String>::sink_map_err(
            FramedWrite::new(input, LinesCodec::new()),
            io::Error::other,
        );
        let incoming = FramedRead::new(output, LinesCodec::new_with_max_length(MAX_ACP_MESSAGE))
            .map_err(io::Error::other);
        drive(
            Lines::new(outgoing, incoming),
            journal.clone(),
            requests,
            events,
            restore,
            ready,
        )
        .await;
        discard.abort();
    } else {
        let _ = ready.send(Err(Error::Disconnected));
    }
    if journal.state().phase != Phase::Closed {
        let _ = journal.update(|state| state.phase = Phase::Interrupted);
    }
    if matches!(
        tokio::task::spawn_blocking(move || process.stop()).await,
        Ok(Ok(()))
    ) {
        let _ = journal.update(|state| state.container = None);
    }
}

async fn drive(
    transport: impl ConnectTo<Client> + 'static,
    journal: Arc<Journal>,
    requests: mpsc::Receiver<Command>,
    events: broadcast::Sender<Event>,
    restore: Restore,
    ready: oneshot::Sender<Result<()>>,
) {
    let notifications = journal.subscribe();
    let permission_state = journal.subscribe();
    let updates = events.clone();
    let _ = Client
        .v1()
        .on_receive_notification(
            async move |notification: SessionNotification, _| {
                if notifications.borrow().remote_session.as_deref()
                    == Some(notification.session_id.0.as_ref())
                {
                    let _ = updates.send(Event::Update(Box::new(notification)));
                }
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .on_receive_request(
            async move |request: RequestPermissionRequest, responder, _| {
                let in_turn = {
                    let state = permission_state.borrow();
                    state.phase == Phase::Active
                        && state.remote_session.as_deref() == Some(request.session_id.0.as_ref())
                };
                let reject = in_turn
                    .then(|| {
                        request
                            .options
                            .iter()
                            .find(|option| option.kind == PermissionOptionKind::RejectOnce)
                    })
                    .flatten();
                let (decision, outcome) = if let Some(option) = reject {
                    (
                        PermissionDecision::RejectOnce,
                        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                            option.option_id.clone(),
                        )),
                    )
                } else {
                    (
                        PermissionDecision::Cancelled,
                        RequestPermissionOutcome::Cancelled,
                    )
                };
                let _ = events.send(Event::Permission {
                    offered: request
                        .options
                        .into_iter()
                        .map(|option| option.kind)
                        .collect(),
                    decision,
                });
                responder.respond(RequestPermissionResponse::new(outcome))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .connect_with(transport, async move |connection| {
            let closed = connection.incoming_closed();
            let serve = async {
                let session = match initialize(&connection, &journal, restore).await {
                    Ok(session) => session,
                    Err(error) => {
                        let _ = journal.update(|state| state.phase = Phase::Interrupted);
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(())).is_ok() {
                    serve_session(&connection, &journal, requests, session).await;
                }
            };
            tokio::select! {
                biased;
                _ = closed => {}
                _ = serve => {}
            }
            Ok(())
        })
        .await;
}

async fn initialize(
    connection: &ConnectionTo<Agent>,
    journal: &Journal,
    restore: Restore,
) -> Result<SessionId> {
    let initialized =
        call(connection.send_request(InitializeRequest::new(ProtocolVersion::V1))).await?;
    if initialized.protocol_version != ProtocolVersion::V1 {
        return Err(Error::Unsupported("ACP v1"));
    }
    let reported = initialized.agent_capabilities;
    let capabilities = Capabilities {
        load: reported.load_session,
        resume: reported.session_capabilities.resume.is_some(),
        close: reported.session_capabilities.close.is_some(),
    };
    journal.update(|state| state.capabilities = capabilities)?;
    let session = if restore == Restore::Fresh {
        call(connection.send_request(NewSessionRequest::new(WORKSPACE)))
            .await?
            .session_id
    } else {
        let state = journal.state();
        check_restore(restore, &state)?;
        let session = SessionId::new(state.remote_session.ok_or(Error::State)?);
        load(connection, restore, session.clone()).await?;
        session
    };
    if session.0.is_empty() || session.0.len() > 1024 || session.0.chars().any(char::is_control) {
        return Err(Error::State);
    }
    journal.update(|state| {
        state.remote_session = Some(session.0.to_string());
        state.phase = Phase::Ready;
    })?;
    Ok(session)
}

async fn load(
    connection: &ConnectionTo<Agent>,
    restore: Restore,
    session: SessionId,
) -> Result<()> {
    match restore {
        Restore::Load => {
            call(connection.send_request(LoadSessionRequest::new(session, WORKSPACE))).await?;
        }
        Restore::Resume => {
            call(connection.send_request(ResumeSessionRequest::new(session, WORKSPACE))).await?;
        }
        Restore::Fresh => return Err(Error::Unsupported("implicit session replacement")),
    }
    Ok(())
}

async fn serve_session(
    connection: &ConnectionTo<Agent>,
    journal: &Journal,
    mut requests: mpsc::Receiver<Command>,
    session: SessionId,
) {
    while let Some(request) = requests.recv().await {
        match request {
            Command::Prompt { text, limit, reply } => {
                if let Err(error) = journal.update(|state| state.phase = Phase::Active) {
                    let _ = reply.send(Err(error));
                    return;
                }
                let (result, keep_running) =
                    drive_turn(connection, &mut requests, session.clone(), text, limit).await;
                let phase = if keep_running {
                    Phase::Ready
                } else {
                    Phase::Interrupted
                };
                let stored = journal.update(|state| state.phase = phase);
                let durable = stored.is_ok();
                let _ = reply.send(stored.and(result));
                if !keep_running || !durable {
                    return;
                }
            }
            Command::Cancel(reply) => {
                let _ = reply.send(Err(Error::Idle));
            }
            Command::Restore { mode, reply } => {
                let result = match check_restore(mode, &journal.state()) {
                    Ok(()) => load(connection, mode, session.clone()).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Command::Close(reply) => {
                let result = match journal.update(|state| state.phase = Phase::Closed) {
                    Ok(()) if journal.state().capabilities.close => {
                        call(connection.send_request(CloseSessionRequest::new(session)))
                            .await
                            .map(|_| Close::Remote)
                    }
                    Ok(()) => Ok(Close::Local),
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
                return;
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Interruption {
    None,
    Cancel,
    Timeout,
}

async fn drive_turn(
    connection: &ConnectionTo<Agent>,
    requests: &mut mpsc::Receiver<Command>,
    session: SessionId,
    text: String,
    limit: Duration,
) -> (Result<StopReason>, bool) {
    let turn = connection
        .send_request(PromptRequest::new(session.clone(), vec![text.into()]))
        .block_task();
    let deadline = sleep(limit);
    tokio::pin!(turn, deadline);
    let mut interruption = Interruption::None;
    loop {
        tokio::select! {
            result = &mut turn => {
                if interruption == Interruption::Timeout {
                    return (Err(Error::TimedOut), true);
                }
                return (result.map(|response| response.stop_reason).map_err(remote_error), true);
            }
            _ = &mut deadline => {
                if interruption != Interruption::None {
                    let error = if interruption == Interruption::Cancel { Error::Disconnected } else { Error::TimedOut };
                    return (Err(error), false);
                }
                if connection.send_notification(CancelNotification::new(session.clone())).is_err() {
                    return (Err(Error::TimedOut), false);
                }
                interruption = Interruption::Timeout;
                deadline.as_mut().reset(Instant::now() + CANCEL_GRACE);
            }
            request = requests.recv() => match request {
                Some(Command::Prompt { reply, .. }) => { let _ = reply.send(Err(Error::Busy)); }
                Some(Command::Restore { reply, .. }) => { let _ = reply.send(Err(Error::Busy)); }
                Some(Command::Close(reply)) => { let _ = reply.send(Err(Error::Busy)); }
                Some(Command::Cancel(reply)) => {
                    if interruption == Interruption::None {
                        let sent = connection.send_notification(CancelNotification::new(session.clone()));
                        if sent.is_err() {
                            let _ = reply.send(Err(Error::Disconnected));
                            return (Err(Error::Disconnected), false);
                        }
                        interruption = Interruption::Cancel;
                        deadline.as_mut().reset(Instant::now() + CANCEL_GRACE);
                    }
                    let _ = reply.send(Ok(()));
                }
                None => return (Err(Error::Disconnected), false),
            }
        }
    }
}

async fn call<T: Send + 'static>(request: SentRequest<T>) -> Result<T> {
    timeout(REQUEST_LIMIT, request.block_task())
        .await
        .map_err(|_| Error::TimedOut)?
        .map_err(remote_error)
}

fn remote_error(error: agent_client_protocol::Error) -> Error {
    Error::Remote(error.code.value())
}
