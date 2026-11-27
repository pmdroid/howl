mod chatgpt;
mod host;
mod journal;
mod repository;
mod repository_http;
mod v2;

pub use chatgpt::ChatGptPlanAuth;
use host::HostAgent;
pub use host::{HostClaude, HostCodex, HostGrok, HostOpenCode};
use repository::RepositoryEndpoint;
use repository_http::RepositoryHttp;

use std::{
    future::Future,
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use agent_client_protocol::{
    Agent, Client, ConnectTo, Lines, Protocol,
    schema::ProtocolVersion,
    v1::{
        ConnectionTo,
        schema::{
            CancelNotification, CloseSessionRequest, InitializeRequest, LoadSessionRequest,
            McpServer, McpServerHttp, NewSessionRequest, PermissionOptionKind, PromptRequest,
            RequestPermissionOutcome, RequestPermissionRequest, RequestPermissionResponse,
            ResumeSessionRequest, SelectedPermissionOutcome, SessionId, SessionNotification,
            StopReason,
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
    #[error(
        "ChatGPT plan authorization unavailable. Run the Howl ChatGPT sign-in helper and try again."
    )]
    ChatGptAuth,
    #[error("managed session storage or pipes failed")]
    Io(#[from] io::Error),
    #[error("invalid trusted host agent configuration")]
    HostAgent,
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
    #[error("ACP agent ended the turn without a supported stop reason")]
    UnreportedStop,
    #[error("ACP agent reported a turn failure")]
    TurnFailed,
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
    chatgpt: Option<ChatGptPlanAuth>,
    host: Option<HostAgent>,
    prefer_v2: bool,
    editable: bool,
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
            chatgpt: None,
            host: None,
            prefer_v2: false,
            editable: false,
        }
    }

    pub fn host_claude(repository_image: String, claude: HostClaude) -> Self {
        Self::host_agent("claude-host", repository_image, HostAgent::Claude(claude))
    }

    pub fn host_grok(repository_image: String, grok: HostGrok) -> Self {
        Self::host_agent("grok-host", repository_image, HostAgent::Grok(grok))
    }

    pub fn host_codex(repository_image: String, codex: HostCodex) -> Self {
        Self::host_agent("codex-host", repository_image, HostAgent::Codex(codex))
    }

    pub fn host_opencode(repository_image: String, opencode: HostOpenCode) -> Self {
        Self::host_agent(
            "opencode-host",
            repository_image,
            HostAgent::OpenCode(opencode),
        )
    }

    fn host_agent(name: &str, repository_image: String, host: HostAgent) -> Self {
        let mut harness = Self::new(
            name,
            repository_image,
            "/usr/local/bin/node",
            &[
                "-e",
                r#"process.stdout.write("ready\n"); setInterval(() => {}, 1000)"#,
            ],
        );
        harness.host = Some(host);
        harness
    }

    pub fn with_provider(mut self, provider: Provider, model: &str) -> Self {
        self.provider = Some((provider, model.to_owned()));
        self.chatgpt = None;
        self
    }

    pub fn with_chatgpt_plan(mut self, model: &str, auth: ChatGptPlanAuth) -> Self {
        self.provider = Some((Provider::ChatGptPlan, model.to_owned()));
        self.chatgpt = Some(auth);
        self
    }

    pub fn with_acp_v2(mut self) -> Self {
        self.prefer_v2 = true;
        self
    }

    pub fn with_editable_workspace(mut self) -> Self {
        self.editable = true;
        self
    }

    pub(crate) fn editable(&self) -> bool {
        self.editable
    }

    async fn broker(&self) -> Result<Option<Broker>> {
        let Some((provider, model)) = &self.provider else {
            return Ok(None);
        };
        let broker = if let Some(auth) = &self.chatgpt {
            Broker::from_chatgpt_plan(model, auth.access_token().await?)?
        } else {
            Broker::from_environment(*provider, model)?
        };
        Ok(Some(broker))
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
        if let Some(auth) = &self.chatgpt {
            let store = auth.store().as_os_str().as_bytes();
            hash.update(b"chatgpt-plan-store");
            hash.update((store.len() as u64).to_be_bytes());
            hash.update(store);
        }
        if self.editable {
            hash.update(b"editable-workspace");
        }
        if self.prefer_v2 {
            hash.update(b"acp-v2");
        }
        if let Some(host) = &self.host {
            host.fingerprint(&mut hash);
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
    #[serde(default)]
    pub protocol_version: Option<ProtocolVersion>,
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
    AllowOnce,
    RejectOnce,
    Cancelled,
}

#[derive(Clone, Debug)]
pub enum Event {
    Update(Box<SessionNotification>),
    UpdateV2(Box<agent_client_protocol::v2::schema::UpdateSessionNotification>),
    PermissionV2 {
        offered: Vec<agent_client_protocol::v2::schema::PermissionOptionKind>,
        decision: PermissionDecision,
    },
    Permission {
        offered: Vec<PermissionOptionKind>,
        decision: PermissionDecision,
    },
}

pub struct ManagedSession {
    commands: mpsc::Sender<Command>,
    status: watch::Receiver<SessionState>,
    events: broadcast::Sender<Event>,
    export: Option<std::process::Command>,
}

impl ManagedSession {
    pub(crate) fn reap_observers(root: &Path, provider: &ObserverProvider) -> Result<()> {
        Journal::reap_observers(root, provider)
    }

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
        if harness.editable && harness.host.is_none() {
            return Err(Error::HostAgent);
        }
        if harness.host.is_some()
            && (harness.provider.is_some() || harness.prefer_v2 || restore.is_some())
        {
            return Err(Error::HostAgent);
        }
        let broker = harness.broker().await?;
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
            protocol_version: None,
            phase: Phase::Starting,
        };
        let prefer_v2 = harness.prefer_v2;
        let editable = harness.editable;
        let host = harness.host;
        let harness = Harness {
            host: None,
            ..harness
        };
        let root = root.to_owned();
        let provider = provider.clone();
        let (journal, mut process) = tokio::task::spawn_blocking(move || -> Result<_> {
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
            let args = if editable {
                vec!["-e", include_str!("editable_workspace.cjs")]
            } else {
                harness.args.iter().map(String::as_str).collect()
            };
            match provider.launch_managed(
                &snapshot,
                &harness.image,
                &harness.executable,
                &args,
                &id,
                editable,
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

        let host = if let Some(host) = host {
            match start_host_agent(&mut process, host, editable).await {
                Ok(host) => Some(host),
                Err(error) => {
                    journal.update(|state| state.phase = Phase::Interrupted)?;
                    return Err(error);
                }
            }
        } else {
            None
        };
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
        let client = Driver {
            journal: Arc::new(journal),
            events: events.clone(),
            restore: restore.unwrap_or(Restore::Fresh),
            channels: Arc::new(Mutex::new(Some((requests, ready)))),
            mode: ClientMode::V1,
            workspace: host.as_ref().map(|host| host.workspace.clone()),
        };
        let export = editable
            .then(|| {
                process.broker_command(
                    Path::new("/usr/local/bin/node"),
                    &["-e", include_str!("editable_workspace.cjs"), "export"],
                )
            })
            .transpose()?;
        tokio::spawn(supervise(process, broker, client, prefer_v2, host));
        initialized.await.map_err(|_| Error::Disconnected)??;
        Ok(Self {
            commands,
            status,
            events,
            export,
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

    pub async fn export_changes(&mut self) -> Result<serde_json::Value> {
        if self.status().phase != Phase::Ready {
            return Err(Error::State);
        }
        let command = self.export.take().ok_or(Error::State)?;
        let output = tokio::process::Command::from(command)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await?;
        if !output.status.success() {
            return Err(Error::State);
        }
        let changes: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|_| Error::State)?;
        if !changes.is_array() {
            return Err(Error::State);
        }
        Ok(changes)
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

    pub(crate) async fn wait_for_observer_stop(&self) -> Result<()> {
        self.status
            .clone()
            .wait_for(|state| state.container.is_none())
            .await
            .map_err(|_| Error::Disconnected)?;
        Ok(())
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

struct HostSession {
    process: host::HostProcess,
    workspace: HostWorkspace,
    _repository: RepositoryEndpoint,
    _http: Option<RepositoryHttp>,
}

#[derive(Clone)]
struct HostWorkspace {
    editable: bool,
    cwd: PathBuf,
    server: McpServer,
}

async fn start_host_agent(
    process: &mut ObserverProcess,
    host: HostAgent,
    editable: bool,
) -> Result<HostSession> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let stdout = ChildStdout::from_std(process.take_stdout().ok_or(Error::Disconnected)?)?;
    let mut ready = String::new();
    timeout(
        Duration::from_secs(10),
        BufReader::new(stdout).read_line(&mut ready),
    )
    .await
    .map_err(|_| Error::TimedOut)??;
    if ready != "ready\n" {
        return Err(Error::Disconnected);
    }
    let repository = RepositoryEndpoint::start(process, editable)?;
    let http = if host.uses_http() {
        Some(RepositoryHttp::start(host.node(), &repository.socket(), editable).await?)
    } else {
        None
    };
    let server = match &http {
        Some(http) => McpServer::Http(McpServerHttp::new("howl_repository", http.url())),
        None => repository.mcp_server(host.node())?,
    };
    let process = host.start(http.as_ref(), editable)?;
    let workspace = HostWorkspace {
        editable,
        cwd: process.cwd.clone(),
        server,
    };
    Ok(HostSession {
        process,
        workspace,
        _repository: repository,
        _http: http,
    })
}

async fn supervise(
    mut process: ObserverProcess,
    _broker: Option<provider_broker::BrokerTask>,
    client: Driver,
    prefer_v2: bool,
    mut host: Option<HostSession>,
) {
    let (input, output, errors) = match &mut host {
        Some(host) => (
            host.process.child.stdin.take(),
            host.process.child.stdout.take(),
            host.process.child.stderr.take(),
        ),
        None => (
            process.take_stdin(),
            process.take_stdout(),
            process.take_stderr(),
        ),
    };
    let result = (
        input.map(ChildStdin::from_std).transpose(),
        output.map(ChildStdout::from_std).transpose(),
        errors.map(ChildStderr::from_std).transpose(),
    );
    let journal = client.journal.clone();
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
        let transport = Lines::new(outgoing, incoming);
        if prefer_v2 {
            let fallback = client.clone();
            let v2 = client.clone();
            let mut transport = Some(transport);
            let connection = Client
                .protocol_connector()
                .with_v1(move || Driver {
                    mode: ClientMode::FallbackV1,
                    ..fallback.clone()
                })
                .with_v2(move || Driver {
                    mode: ClientMode::V2,
                    ..v2.clone()
                })
                .connect_to(move || OnceTransport(transport.take()));
            let mut startup = journal.subscribe();
            let started = async {
                startup
                    .wait_for(|state| {
                        matches!(state.phase, Phase::Ready | Phase::Active | Phase::Closed)
                    })
                    .await
                    .map(|_| ())
            };
            tokio::pin!(connection);
            let result = tokio::select! {
                result = &mut connection => result.map_err(remote_error),
                result = timeout(REQUEST_LIMIT * 2, started) => {
                    match result {
                        Ok(Ok(_)) => connection.await.map_err(remote_error),
                        Ok(Err(_)) => Err(Error::Disconnected),
                        Err(_) => Err(Error::TimedOut),
                    }
                }
            };
            client.fail_uninitialized(result.err().unwrap_or(Error::Disconnected));
        } else {
            let result = client.clone().connect_to(transport).await;
            client.fail_uninitialized(result.err().map_or(Error::Disconnected, remote_error));
        }
        discard.abort();
    } else {
        client.fail_uninitialized(Error::Disconnected);
    }
    if journal.state().phase != Phase::Closed {
        let _ = journal.update(|state| state.phase = Phase::Interrupted);
    }
    if matches!(
        tokio::task::spawn_blocking(move || {
            drop(host);
            process.stop()
        })
        .await,
        Ok(Ok(()))
    ) {
        let _ = journal.update(|state| state.container = None);
    }
}

struct OnceTransport<T>(Option<T>);

impl<T: ConnectTo<Client>> ConnectTo<Client> for OnceTransport<T> {
    async fn connect_to(self, peer: impl ConnectTo<Agent>) -> agent_client_protocol::Result<()> {
        match self.0 {
            Some(transport) => transport.connect_to(peer).await,
            None => Err(agent_client_protocol::Error::internal_error()),
        }
    }
}

type DriverChannels = (mpsc::Receiver<Command>, oneshot::Sender<Result<()>>);

#[derive(Clone)]
struct Driver {
    journal: Arc<Journal>,
    events: broadcast::Sender<Event>,
    restore: Restore,
    channels: Arc<Mutex<Option<DriverChannels>>>,
    mode: ClientMode,
    workspace: Option<HostWorkspace>,
}

impl Driver {
    fn fail_uninitialized(&self, error: Error) {
        if let Some((_, ready)) = self.channels.lock().unwrap().take() {
            let _ = ready.send(Err(error));
        }
    }
}

#[derive(Clone, Copy)]
enum ClientMode {
    V1,
    FallbackV1,
    V2,
}

impl ConnectTo<Agent> for Driver {
    async fn connect_to(
        self,
        transport: impl ConnectTo<Client>,
    ) -> agent_client_protocol::Result<()> {
        match self.mode {
            ClientMode::V1 | ClientMode::FallbackV1 => drive_v1(transport, self).await,
            ClientMode::V2 => v2::drive(transport, self).await,
        }
    }
}

async fn drive_v1(
    transport: impl ConnectTo<Client>,
    driver: Driver,
) -> agent_client_protocol::Result<()> {
    let Driver {
        journal,
        events,
        restore,
        channels,
        mode,
        workspace,
    } = driver;
    let notifications = journal.subscribe();
    let permission_state = journal.subscribe();
    let updates = events.clone();
    let host_workspace = workspace.is_some();
    let editable = workspace.as_ref().is_some_and(|work| work.editable);
    Client
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
                let repository_read = host_workspace
                    && matches!(
                        request.tool_call.fields.name.as_deref(),
                        Some(
                            "mcp__howl_repository__read_file"
                                | "mcp__howl_repository__list_directory"
                        )
                    );
                let repository_edit = editable
                    && matches!(
                        request.tool_call.fields.name.as_deref(),
                        Some(
                            "mcp__howl_repository__write_file"
                                | "mcp__howl_repository__delete_file"
                                | "mcp__howl_repository__run_tests"
                        )
                    );
                let (kind, selected) = if repository_read || repository_edit {
                    (
                        PermissionOptionKind::AllowOnce,
                        PermissionDecision::AllowOnce,
                    )
                } else {
                    (
                        PermissionOptionKind::RejectOnce,
                        PermissionDecision::RejectOnce,
                    )
                };
                let option = in_turn
                    .then(|| request.options.iter().find(|option| option.kind == kind))
                    .flatten();
                let (decision, outcome) = if let Some(option) = option {
                    (
                        selected,
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
                let session = initialize_v1(&connection, &journal, restore, mode, workspace).await;
                let Some((requests, ready)) = channels.lock().unwrap().take() else {
                    return;
                };
                match session {
                    Ok(session) => {
                        if ready.send(Ok(())).is_ok() {
                            serve_session(
                                &V1Session {
                                    connection: &connection,
                                    session,
                                },
                                &journal,
                                requests,
                            )
                            .await;
                        }
                    }
                    Err(error) => {
                        let _ = journal.update(|state| state.phase = Phase::Interrupted);
                        let _ = ready.send(Err(error));
                    }
                }
            };
            tokio::select! {
                biased;
                _ = closed => {}
                _ = serve => {}
            }
            Ok(())
        })
        .await
}

async fn initialize_v1(
    connection: &ConnectionTo<Agent>,
    journal: &Journal,
    restore: Restore,
    mode: ClientMode,
    workspace: Option<HostWorkspace>,
) -> Result<SessionId> {
    let mut request = InitializeRequest::new(ProtocolVersion::V1);
    if matches!(mode, ClientMode::FallbackV1) {
        use agent_client_protocol::v1::schema::{
            BooleanConfigOptionCapabilities, ClientCapabilities, ClientSessionCapabilities,
            Implementation, SessionConfigOptionsCapabilities,
        };
        request = request
            .client_info(Implementation::new("howl", env!("CARGO_PKG_VERSION")))
            .client_capabilities(
                ClientCapabilities::new().session(
                    ClientSessionCapabilities::new().config_options(
                        SessionConfigOptionsCapabilities::new()
                            .boolean(BooleanConfigOptionCapabilities::new()),
                    ),
                ),
            );
    }
    let initialized = call(connection.send_request(request)).await?;
    if initialized.protocol_version != ProtocolVersion::V1 {
        return Err(Error::Unsupported("ACP v1"));
    }
    let reported = initialized.agent_capabilities;
    let capabilities = Capabilities {
        load: workspace.is_none() && reported.load_session,
        resume: workspace.is_none() && reported.session_capabilities.resume.is_some(),
        close: reported.session_capabilities.close.is_some(),
    };
    record_capabilities(journal, ProtocolVersion::V1, capabilities, restore)?;
    let session = if restore == Restore::Fresh {
        let request = match workspace {
            Some(workspace) => {
                NewSessionRequest::new(workspace.cwd).mcp_servers(vec![workspace.server])
            }
            None => NewSessionRequest::new(WORKSPACE),
        };
        call(connection.send_request(request)).await?.session_id
    } else {
        let state = journal.state();
        check_restore(restore, &state)?;
        let session = SessionId::new(state.remote_session.ok_or(Error::State)?);
        load(connection, restore, session.clone()).await?;
        session
    };
    record_session(journal, &session.0)?;
    Ok(session)
}

fn record_capabilities(
    journal: &Journal,
    version: ProtocolVersion,
    capabilities: Capabilities,
    restore: Restore,
) -> Result<()> {
    let state = journal.state();
    if restore != Restore::Fresh
        && state.remote_session.is_some()
        && state.protocol_version.unwrap_or(ProtocolVersion::V1) != version
    {
        return Err(Error::ScopeChanged);
    }
    journal.update(|state| {
        state.protocol_version = Some(version);
        state.capabilities = capabilities;
    })
}

fn record_session(journal: &Journal, id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 1024 || id.chars().any(char::is_control) {
        return Err(Error::State);
    }
    journal.update(|state| {
        state.remote_session = Some(id.to_owned());
        state.phase = Phase::Ready;
    })
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

trait SessionWire: Sync {
    fn prompt(&self, text: String) -> impl Future<Output = Result<StopReason>> + Send;
    fn cancel(&self) -> Result<()>;

    fn cancel_idle(&self) -> Result<()> {
        Err(Error::Idle)
    }

    fn restore(&self, mode: Restore) -> impl Future<Output = Result<()>> + Send;
    fn close(&self) -> impl Future<Output = Result<()>> + Send;
}

struct V1Session<'a> {
    connection: &'a ConnectionTo<Agent>,
    session: SessionId,
}

impl SessionWire for V1Session<'_> {
    async fn prompt(&self, text: String) -> Result<StopReason> {
        self.connection
            .send_request(PromptRequest::new(self.session.clone(), vec![text.into()]))
            .block_task()
            .await
            .map(|response| response.stop_reason)
            .map_err(remote_error)
    }

    fn cancel(&self) -> Result<()> {
        self.connection
            .send_notification(CancelNotification::new(self.session.clone()))
            .map_err(|_| Error::Disconnected)
    }

    async fn restore(&self, mode: Restore) -> Result<()> {
        load(self.connection, mode, self.session.clone()).await
    }

    async fn close(&self) -> Result<()> {
        call(
            self.connection
                .send_request(CloseSessionRequest::new(self.session.clone())),
        )
        .await
        .map(|_| ())
    }
}

async fn serve_session(
    wire: &impl SessionWire,
    journal: &Journal,
    mut requests: mpsc::Receiver<Command>,
) {
    while let Some(request) = requests.recv().await {
        match request {
            Command::Prompt { text, limit, reply } => {
                if let Err(error) = journal.update(|state| state.phase = Phase::Active) {
                    let _ = reply.send(Err(error));
                    return;
                }
                let (result, keep_running) = drive_turn(wire, &mut requests, text, limit).await;
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
                let _ = reply.send(wire.cancel_idle());
            }
            Command::Restore { mode, reply } => {
                let result = match check_restore(mode, &journal.state()) {
                    Ok(()) => wire.restore(mode).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Command::Close(reply) => {
                let result = match journal.update(|state| state.phase = Phase::Closed) {
                    Ok(()) if journal.state().capabilities.close => {
                        wire.close().await.map(|_| Close::Remote)
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
    wire: &impl SessionWire,
    requests: &mut mpsc::Receiver<Command>,
    text: String,
    limit: Duration,
) -> (Result<StopReason>, bool) {
    let turn = wire.prompt(text);
    let deadline = sleep(limit);
    tokio::pin!(turn, deadline);
    let mut interruption = Interruption::None;
    loop {
        tokio::select! {
            result = &mut turn => {
                if interruption == Interruption::Timeout {
                    return (Err(Error::TimedOut), true);
                }
                return (result, true);
            }
            _ = &mut deadline => {
                if interruption != Interruption::None {
                    let error = if interruption == Interruption::Cancel { Error::Disconnected } else { Error::TimedOut };
                    return (Err(error), false);
                }
                if wire.cancel().is_err() {
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
                        let sent = wire.cancel();
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

async fn call<T: Send + 'static, P: Protocol>(
    request: agent_client_protocol::SentRequest<T, P>,
) -> Result<T> {
    timeout(REQUEST_LIMIT, request.block_task())
        .await
        .map_err(|_| Error::TimedOut)?
        .map_err(remote_error)
}

fn remote_error(error: agent_client_protocol::Error) -> Error {
    Error::Remote(error.code.value())
}

#[cfg(test)]
mod provider_tests;
