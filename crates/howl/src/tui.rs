use std::{
    collections::{HashMap, VecDeque},
    io::{self, IsTerminal},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use crossterm::{
    event::{
        DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event as Input, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton,
        MouseEvent, MouseEventKind,
    },
    execute,
};
use futures_util::StreamExt;
use howl_envelope::{AgentRole, Id};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout, Position, Rect},
    style::{Modifier, Style},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use serde::Deserialize;
use tokio::{
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
    sync::mpsc,
    time::{MissedTickBehavior, interval, timeout},
};

use crate::{
    delivery::DeliveryStatus,
    identity::StateDirectory,
    interaction::{
        AgentAddress, ChannelSummary, Event, EventPage, LocalDevice, LocalInteraction, Wake,
    },
    node,
};

const MAX_EVENTS: usize = 160;
const MAX_VIEWS: usize = 32;
const REFRESH: Duration = Duration::from_millis(350);
const CATALOG_REFRESH: Duration = Duration::from_secs(2);
const WAKE_LIFETIME: u16 = 120;

type Conversation = (Id, Option<Id>);
type Delivery = (Id, Id);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Channels,
    Peers,
    Messages,
    Device,
    Compose,
}

impl Focus {
    const PANES: [Self; 5] = [
        Self::Channels,
        Self::Peers,
        Self::Messages,
        Self::Device,
        Self::Compose,
    ];

    fn step(self, backwards: bool) -> Self {
        let panes = Self::PANES;
        let index = panes.iter().position(|pane| *pane == self).unwrap();
        panes[(index + if backwards { panes.len() - 1 } else { 1 }) % panes.len()]
    }
}

#[derive(Default)]
struct ConversationView {
    cursor: u64,
    events: VecDeque<Event>,
    selected: usize,
    gap: bool,
    more: bool,
    workflows: Vec<WorkflowView>,
    agents: Vec<AgentAddress>,
}

impl ConversationView {
    fn append(&mut self, page: EventPage) {
        let following = self.selected.saturating_add(1) >= self.events.len();
        self.gap |= page.gap;
        self.more = page.more;
        for event in page.events {
            if event.cursor <= self.cursor {
                continue;
            }
            self.cursor = event.cursor;
            self.events.push_back(event);
            if self.events.len() > MAX_EVENTS {
                self.events.pop_front();
                self.selected = self.selected.saturating_sub(1);
            }
        }
        self.cursor = self.cursor.max(page.cursor);
        if following {
            self.selected = self.events.len().saturating_sub(1);
        }
    }
}

#[derive(Deserialize)]
struct WorkflowView {
    target: String,
    state: String,
    root: Option<String>,
    paused: bool,
}

struct Catalog {
    device: io::Result<LocalDevice>,
    channels: io::Result<Vec<ChannelSummary>>,
}

struct ViewUpdate {
    key: Conversation,
    page: io::Result<EventPage>,
    agents: Option<Vec<AgentAddress>>,
    workflows: Option<Vec<WorkflowView>>,
}

struct Update {
    catalog: Option<Catalog>,
    view: Option<ViewUpdate>,
    delivery: Option<(Delivery, Vec<DeliveryStatus>)>,
}

struct RefreshRequest {
    catalog: bool,
    conversation: Option<(Conversation, u64)>,
    delivery: Option<Delivery>,
}

impl RefreshRequest {
    fn load(self, state: &Path) -> Update {
        let local = LocalInteraction::new(state);
        let catalog = self.catalog.then(|| Catalog {
            device: local.device(),
            channels: local.channels(),
        });
        let view = self.conversation.map(|(key @ (channel, peer), cursor)| {
            let page = local.event_page(channel, peer, cursor, 32);
            let workflows = self
                .catalog
                .then(|| {
                    local
                        .status(channel)
                        .ok()
                        .and_then(|status| serde_json::from_value(status).ok())
                })
                .flatten();
            let agents = self.catalog.then(|| local.agents(channel).ok()).flatten();
            ViewUpdate {
                key,
                page,
                agents,
                workflows,
            }
        });
        let delivery = self.delivery.and_then(|key @ (channel, message)| {
            local
                .delivery_status(channel, message)
                .ok()
                .map(|items| (key, items))
        });
        Update {
            catalog,
            view,
            delivery,
        }
    }
}

struct App {
    focus: Focus,
    device: Option<LocalDevice>,
    channels: Vec<ChannelSummary>,
    channel: Option<Id>,
    peer: Option<Id>,
    views: HashMap<Conversation, ConversationView>,
    routes: HashMap<Id, String>,
    peer_labels: HashMap<String, String>,
    draft: String,
    notice: String,
    device_output: String,
    catalog_at: Option<Instant>,
    pending: bool,
    confirm: Option<Action>,
    detail: bool,
    scroll: u16,
    mesh: Option<Child>,
    mesh_available: bool,
    last_delivery: Option<Delivery>,
    delivery: Vec<DeliveryStatus>,
}

impl App {
    fn new() -> Self {
        Self {
            focus: Focus::Channels,
            device: None,
            channels: Vec::new(),
            channel: None,
            peer: None,
            views: HashMap::new(),
            routes: HashMap::new(),
            peer_labels: HashMap::new(),
            draft: String::new(),
            notice: String::new(),
            device_output: String::new(),
            catalog_at: None,
            pending: false,
            confirm: None,
            detail: false,
            scroll: 0,
            mesh: None,
            mesh_available: false,
            last_delivery: None,
            delivery: Vec::new(),
        }
    }

    fn conversation(&self) -> Option<Conversation> {
        self.channel.map(|channel| (channel, self.peer))
    }

    fn peers(&self) -> &[Id] {
        self.channels
            .iter()
            .find(|channel| Some(channel.id) == self.channel)
            .map_or(&[], |channel| channel.peers.as_slice())
    }

    fn peer_label(&self, peer: &Id) -> String {
        let id = hex::encode(peer);
        self.peer_labels
            .get(&id)
            .map(|label| visible(label).chars().take(32).collect::<String>())
            .filter(|label| !label.trim().is_empty())
            .unwrap_or_else(|| short(&id).to_owned())
    }

    fn refresh(&mut self) -> RefreshRequest {
        let catalog = self
            .catalog_at
            .is_none_or(|last| last.elapsed() >= CATALOG_REFRESH);
        if catalog {
            self.catalog_at = Some(Instant::now());
        }
        let conversation = self
            .conversation()
            .map(|key| (key, self.views.get(&key).map_or(0, |view| view.cursor)));
        RefreshRequest {
            catalog,
            conversation,
            delivery: self.last_delivery,
        }
    }

    fn update(&mut self, update: Update) {
        if let Some(Catalog { device, channels }) = update.catalog {
            self.device = device.ok();
            match channels {
                Ok(channels) => {
                    self.channels = channels;
                    self.views.retain(|(channel, peer), _| {
                        self.channels.iter().any(|entry| {
                            entry.id == *channel
                                && peer.is_none_or(|peer| entry.peers.contains(&peer))
                        })
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    self.channels.clear();
                    self.views.clear();
                    if self.focus == Focus::Channels {
                        self.focus = Focus::Device;
                    }
                }
                Err(error) => self.notice = error.to_string(),
            }
            if !self
                .channels
                .iter()
                .any(|entry| Some(entry.id) == self.channel)
            {
                self.channel = self.channels.first().map(|entry| entry.id);
                self.peer = None;
            } else if self.peer.is_some_and(|peer| !self.peers().contains(&peer)) {
                self.peer = None;
            }
        }
        if let Some(ViewUpdate {
            key,
            page,
            agents,
            workflows,
        }) = update.view
            && self.channels.iter().any(|channel| {
                channel.id == key.0 && key.1.is_none_or(|peer| channel.peers.contains(&peer))
            })
        {
            match page {
                Ok(page) => {
                    if self.views.len() >= MAX_VIEWS
                        && !self.views.contains_key(&key)
                        && let Some(old) = self.views.keys().next().copied()
                    {
                        self.views.remove(&old);
                    }
                    let view = self.views.entry(key).or_default();
                    view.append(page);
                    if let Some(agents) = agents {
                        view.agents = agents;
                    }
                    if let Some(workflows) = workflows {
                        view.workflows = workflows;
                    }
                }
                Err(error) => {
                    if matches!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                    ) {
                        self.views.remove(&key);
                    }
                    if self.conversation() == Some(key) {
                        self.notice = error.to_string();
                    }
                }
            }
        }
        if let Some((key, items)) = update.delivery
            && self.last_delivery == Some(key)
        {
            self.delivery = items;
        }
    }

    fn move_selection(&mut self, backwards: bool) {
        let offset = if backwards { -1 } else { 1 };
        match self.focus {
            Focus::Channels => {
                let selected = self
                    .channels
                    .iter()
                    .position(|entry| Some(entry.id) == self.channel)
                    .unwrap_or(0);
                self.select(
                    Focus::Channels,
                    shift(selected, self.channels.len(), offset),
                );
            }
            Focus::Peers => {
                let peers = self.peers();
                let selected = peers
                    .iter()
                    .position(|peer| Some(*peer) == self.peer)
                    .map_or(0, |index| index + 1);
                self.select(Focus::Peers, shift(selected, peers.len() + 1, offset));
            }
            Focus::Messages if !self.detail => {
                if let Some(view) = self.conversation().and_then(|key| self.views.get_mut(&key)) {
                    view.selected = shift(view.selected, view.events.len(), offset);
                }
            }
            Focus::Device | Focus::Messages => {
                self.scroll = self.scroll.saturating_add_signed(offset as i16);
            }
            Focus::Compose => {}
        }
    }

    fn select(&mut self, pane: Focus, index: usize) {
        match pane {
            Focus::Channels => {
                if let Some(entry) = self.channels.get(index) {
                    self.channel = Some(entry.id);
                    self.peer = None;
                }
            }
            Focus::Peers => {
                self.peer = index
                    .checked_sub(1)
                    .and_then(|index| self.peers().get(index))
                    .copied();
            }
            _ => return,
        }
        self.detail = false;
        self.catalog_at = None;
    }

    fn set_focus(&mut self, focus: Focus) {
        self.focus = focus;
        self.detail = false;
        self.scroll = 0;
    }

    fn insert(&mut self, value: &str) {
        if self.focus != Focus::Compose || self.pending {
            return;
        }
        for ch in value
            .chars()
            .filter(|ch| matches!(ch, '\n' | '\t') || !ch.is_control())
        {
            if self.draft.len() + ch.len_utf8() > node::CHAT_LIMIT {
                break;
            }
            self.draft.push(ch);
        }
    }
}

enum Action {
    Post {
        channel: Id,
        text: String,
    },
    Direct {
        channel: Id,
        peer: Id,
        route: String,
        text: String,
    },
    Wake {
        channel: Id,
        peer: Id,
        route: String,
        target: Id,
        text: String,
    },
    Cancel {
        channel: Id,
        root: Id,
    },
    CancelWake {
        channel: Id,
        peer: Id,
        route: String,
        wake: Id,
    },
    Enroll(Vec<String>),
    Connect(Vec<String>),
    Disconnect,
}

enum Outcome {
    Sent(Delivery),
    Notice(&'static str),
    Device(String),
    Connected(Child),
}

impl App {
    fn submit(&mut self) -> io::Result<Option<Action>> {
        let input = self.draft.trim();
        if input.is_empty() || self.pending {
            return Ok(None);
        }
        if let Some(command) = input.strip_prefix(':') {
            return self.command(command.to_owned().as_str());
        }
        let (channel, peer) = self
            .conversation()
            .ok_or_else(|| invalid("Select a signed channel first."))?;
        let route = peer
            .and_then(|peer| self.routes.get(&peer).cloned())
            .unwrap_or_else(|| "-".into());
        if let Some((role, text)) = mention(input)? {
            let peer =
                peer.ok_or_else(|| invalid("Select the agent’s peer before sending a wake."))?;
            return Ok(Some(Action::Wake {
                channel,
                peer,
                route,
                target: role.agent_id(&peer),
                text: text.to_owned(),
            }));
        }
        let text = self
            .draft
            .strip_prefix("@@")
            .map_or_else(|| self.draft.clone(), |text| format!("@{text}"));
        Ok(Some(match peer {
            Some(peer) => Action::Direct {
                channel,
                peer,
                route,
                text,
            },
            None => Action::Post { channel, text },
        }))
    }

    fn command(&mut self, command: &str) -> io::Result<Option<Action>> {
        let args = command.split_whitespace().collect::<Vec<_>>();
        match args.as_slice() {
            ["device"] => self.set_focus(Focus::Device),
            ["refresh"] => self.catalog_at = None,
            ["route", value] => {
                let peer = self
                    .peer
                    .ok_or_else(|| invalid("Select a direct peer before setting its route."))?;
                node::parse_route(value.as_bytes())?;
                self.routes.insert(peer, (*value).to_owned());
                self.notice = "Peer route saved for this terminal session".into();
            }
            ["connect", listen, relay @ ..] if relay.len() <= 1 => {
                if self.mesh.is_some() {
                    return Err(invalid("A local mesh process is already available."));
                }
                if *listen != "-" {
                    listen
                        .parse::<std::net::SocketAddr>()
                        .map_err(io::Error::other)?;
                }
                return Ok(Some(Action::Connect(
                    std::iter::once(*listen)
                        .chain(relay.iter().copied())
                        .map(str::to_owned)
                        .collect(),
                )));
            }
            ["disconnect"] => return Ok(Some(Action::Disconnect)),
            ["cancel", args @ ..] if args.len() <= 1 => {
                let channel = self
                    .channel
                    .ok_or_else(|| invalid("Select a signed channel first."))?;
                let root = args
                    .first()
                    .copied()
                    .or_else(|| {
                        self.conversation()
                            .and_then(|key| self.views.get(&key))
                            .and_then(|view| {
                                view.workflows.iter().find_map(|work| {
                                    (!work.paused).then_some(work.root.as_deref()).flatten()
                                })
                            })
                    })
                    .ok_or_else(|| invalid("No local signed workflow root is available."))?;
                self.confirm = Some(Action::Cancel {
                    channel,
                    root: id(root)?,
                });
            }
            ["cancel-wake", args @ ..] if args.len() <= 1 => {
                self.confirm = Some(self.remote_cancel(args.first().copied())?);
            }
            ["enroll", args @ ..] => return Ok(Some(Action::Enroll(enrollment_args(args)?))),
            _ => return Err(invalid("Commands available in Device (4).")),
        }
        self.draft.clear();
        Ok(None)
    }

    fn remote_cancel(&self, message: Option<&str>) -> io::Result<Action> {
        let unavailable = || invalid("Select an outgoing wake in the direct conversation first.");
        let (channel, Some(peer)) = self.conversation().ok_or_else(unavailable)? else {
            return Err(unavailable());
        };
        let view = self
            .views
            .get(&(channel, Some(peer)))
            .ok_or_else(unavailable)?;
        let event = match message {
            Some(message) => {
                let expected = hex::encode(id(message)?);
                view.events
                    .iter()
                    .find(|event| event.message.message == expected)
            }
            None => view.events.get(view.selected),
        }
        .ok_or_else(unavailable)?;
        let sender = self
            .device
            .as_ref()
            .map(|device| hex::encode(device.id))
            .ok_or_else(unavailable)?;
        if event.message.role != Some("wake")
            || event.message.integration.is_some()
            || event.message.sender != sender
            || event.recipient.as_deref() != Some(hex::encode(peer).as_str())
        {
            return Err(unavailable());
        }
        Ok(Action::CancelWake {
            channel,
            peer,
            route: self
                .routes
                .get(&peer)
                .cloned()
                .unwrap_or_else(|| "-".into()),
            wake: id(&event.message.message)?,
        })
    }

    fn completed(&mut self, result: io::Result<Outcome>) {
        self.pending = false;
        match result {
            Ok(outcome) => {
                self.draft.clear();
                self.catalog_at = None;
                match outcome {
                    Outcome::Sent(key) => {
                        self.last_delivery = Some(key);
                        self.delivery.clear();
                        self.notice = format!("Queued {}", short(&hex::encode(key.1)));
                    }
                    Outcome::Notice(notice) => self.notice = notice.into(),
                    Outcome::Device(output) => {
                        self.device_output = output;
                        self.set_focus(Focus::Device);
                    }
                    Outcome::Connected(child) => {
                        self.mesh = Some(child);
                        self.notice = "Starting client-only mesh".into();
                    }
                }
            }
            Err(error) => self.notice = error.to_string(),
        }
    }
}

impl Action {
    async fn execute(self, state: PathBuf) -> io::Result<Outcome> {
        let local = LocalInteraction::new(&state);
        let (channel, receipt) = match self {
            Self::Post { channel, text } => (channel, local.post(channel, &text).await?),
            Self::Direct {
                channel,
                peer,
                route,
                text,
            } => (channel, local.send(channel, peer, &route, &text).await?),
            Self::Wake {
                channel,
                peer,
                route,
                target,
                text,
            } => (
                channel,
                local
                    .wake(Wake {
                        channel,
                        peer,
                        route: &route,
                        target,
                        lifetime: WAKE_LIFETIME,
                        text: &text,
                    })
                    .await?,
            ),
            Self::Cancel { channel, root } => {
                local.cancel(channel, root)?;
                return Ok(Outcome::Notice("Signed pause recorded"));
            }
            Self::CancelWake {
                channel,
                peer,
                route,
                wake,
            } => (
                channel,
                local.cancel_remote(channel, peer, &route, wake).await?,
            ),
            Self::Enroll(args) => {
                let (command, opts) = args
                    .split_first()
                    .ok_or_else(|| invalid("Missing enrollment action."))?;
                let output = Command::new(std::env::current_exe()?)
                    .args(["enrollment", command])
                    .arg(state)
                    .args(opts)
                    .stdin(Stdio::null())
                    .kill_on_drop(true)
                    .output()
                    .await?;
                if !output.status.success() {
                    return Err(io::Error::other(
                        String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                    ));
                }
                return Ok(Outcome::Device(
                    String::from_utf8_lossy(&output.stdout)
                        .chars()
                        .take(4096)
                        .collect(),
                ));
            }
            Self::Connect(args) => {
                local.require_enrolled()?;
                let child = Command::new(std::env::current_exe()?)
                    .args(["mesh", "run", "--client-only"])
                    .arg(state)
                    .args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()?;
                return Ok(Outcome::Connected(child));
            }
            Self::Disconnect => {
                node::stop(&state).await?;
                return Ok(Outcome::Notice("Mesh stopped"));
            }
        };
        Ok(Outcome::Sent((channel, id(&receipt.message)?)))
    }
}

fn enrollment_args(args: &[&str]) -> io::Result<Vec<String>> {
    match args {
        ["identity" | "peer", _]
        | ["authority"]
        | ["respond", _, _, _, _, _]
        | ["accept", _, _, _, _] => Ok(args.iter().map(|arg| (*arg).to_owned()).collect()),
        _ => Err(invalid("Choose an enrollment action shown in Device (4).")),
    }
}

fn mention(input: &str) -> io::Result<Option<(AgentRole, &str)>> {
    let Some((prefix, text)) = input.split_once(char::is_whitespace) else {
        return match input {
            "@architect" | "@reviewer" => Err(invalid("Add a message after the role to wake.")),
            _ => Ok(None),
        };
    };
    let role = match prefix {
        "@architect" => AgentRole::Architect,
        "@reviewer" => AgentRole::Reviewer,
        _ => return Ok(None),
    };
    let text = text.trim();
    if text.is_empty() || text.len() > node::WAKE_LIMIT {
        return Err(invalid("Enter a wake message within the size limit."));
    }
    Ok(Some((role, text)))
}

fn shift(selected: usize, count: usize, offset: isize) -> usize {
    selected
        .saturating_add_signed(offset)
        .min(count.saturating_sub(1))
}

fn id(text: &str) -> io::Result<Id> {
    let mut id = [0; 32];
    hex::decode_to_slice(text, &mut id)
        .map_err(|_| invalid("Enter the complete 64-character identifier."))?;
    Ok(id)
}

fn invalid(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, text)
}

fn display_char(ch: char) -> char {
    match ch {
        '\r' | '\n' | '\t' => ' ',
        '\u{061c}'
        | '\u{200e}'
        | '\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}' => '�',
        ch if ch.is_control() => '�',
        ch => ch,
    }
}

fn visible(text: &str) -> String {
    text.chars().map(display_char).collect()
}

fn short(text: &str) -> &str {
    text.get(..10).unwrap_or(text)
}

struct TerminalCleanup;

impl Drop for TerminalCleanup {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableBracketedPaste, DisableMouseCapture);
        let _ = ratatui::try_restore();
    }
}

pub async fn run(state: &Path) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(invalid(
            "Howl’s terminal client requires interactive input and output.",
        ));
    }
    let cleanup = TerminalCleanup;
    let mut terminal = ratatui::try_init()?;
    execute!(io::stdout(), EnableBracketedPaste, EnableMouseCapture)?;
    let mut app = App::new();
    app.peer_labels = StateDirectory::open(state)
        .and_then(|state| state.read_bounded("peer-labels.json", 16 * 1024))
        .ok()
        .and_then(|labels| serde_json::from_slice(&labels).ok())
        .unwrap_or_default();
    let result = drive(state, &mut terminal, &mut app).await;
    drop(terminal);
    drop(cleanup);
    if let Some(child) = &mut app.mesh
        && child.try_wait().is_ok_and(|status| status.is_none())
    {
        let _ = timeout(Duration::from_secs(2), node::stop(state)).await;
        let _ = timeout(Duration::from_secs(2), child.wait()).await;
    }
    result
}

async fn drive(state: &Path, terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    let mut inputs = EventStream::new();
    let mut tick = interval(REFRESH);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let (refresh_tx, mut refresh_rx) = mpsc::channel(1);
    let (action_tx, mut action_rx) = mpsc::channel(1);
    let mut refreshing = false;
    loop {
        let mut hits = HitMap::default();
        terminal.draw(|frame| hits = draw(frame, app))?;
        tokio::select! {
            _ = terminate.recv() => break,
            _ = hangup.recv() => break,
            _ = interrupt.recv() => break,
            _ = tick.tick() => {
                app.mesh_available = state.join("mesh.sock").symlink_metadata().is_ok_and(|metadata| metadata.file_type().is_socket());
                if let Some(child) = &mut app.mesh && let Some(status) = child.try_wait()? {
                    app.mesh = None;
                    if !status.success() {
                        app.notice = format!("Client mesh exited with {status}");
                    }
                }
                if !refreshing {
                    refreshing = true;
                    let request = app.refresh();
                    let state = state.to_owned();
                    let updates = refresh_tx.clone();
                    tokio::task::spawn_blocking(move || {
                        let _ = updates.blocking_send(request.load(&state));
                    });
                }
            },
            Some(update) = refresh_rx.recv() => {
                refreshing = false;
                app.update(update);
            },
            Some(result) = action_rx.recv() => app.completed(result),
            input = inputs.next() => {
                let outcome = match input {
                    None => break,
                    Some(Err(error)) => return Err(error),
                    Some(Ok(Input::Paste(text))) => {
                        app.insert(&text);
                        InputOutcome::Nothing
                    }
                    Some(Ok(Input::Key(event))) if event.kind != KeyEventKind::Release => key(app, event),
                    Some(Ok(Input::Mouse(event))) => mouse(app, &hits, event),
                    Some(Ok(_)) => InputOutcome::Nothing,
                };
                match outcome {
                    InputOutcome::Exit => break,
                    InputOutcome::Nothing => {}
                    InputOutcome::Action(action) => {
                        app.pending = true;
                        let state = state.to_owned();
                        let actions = action_tx.clone();
                        tokio::spawn(async move { let _ = actions.send(action.execute(state).await).await; });
                    }
                }
            },
        }
    }
    Ok(())
}

enum InputOutcome {
    Exit,
    Nothing,
    Action(Action),
}

fn key(app: &mut App, event: KeyEvent) -> InputOutcome {
    if event.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(event.code, KeyCode::Char('c' | 'q'))
    {
        return InputOutcome::Exit;
    }
    if let Some(action) = app.confirm.take() {
        if event.code == KeyCode::Char('y') && !app.pending {
            return InputOutcome::Action(action);
        }
        return InputOutcome::Nothing;
    }
    match event.code {
        KeyCode::Tab => app.set_focus(app.focus.step(false)),
        KeyCode::BackTab => app.set_focus(app.focus.step(true)),
        KeyCode::Char(ch @ '1'..='5')
            if app.focus != Focus::Compose && event.modifiers.is_empty() =>
        {
            app.set_focus(Focus::PANES[ch as usize - '1' as usize]);
        }
        KeyCode::Esc if app.focus == Focus::Compose => app.set_focus(Focus::Messages),
        KeyCode::Up => app.move_selection(true),
        KeyCode::Down => app.move_selection(false),
        KeyCode::Enter if app.focus == Focus::Messages => {
            app.detail = !app.detail;
            app.scroll = 0;
        }
        KeyCode::Enter if app.focus == Focus::Compose && event.kind == KeyEventKind::Press => {
            return submit(app);
        }
        KeyCode::Backspace if app.focus == Focus::Compose && !app.pending => {
            app.draft.pop();
        }
        KeyCode::Esc if app.focus == Focus::Messages => app.detail = false,
        KeyCode::Char('r') if app.focus != Focus::Compose => app.catalog_at = None,
        KeyCode::Char('q') if app.focus != Focus::Compose => return InputOutcome::Exit,
        KeyCode::Char('i') if app.focus != Focus::Compose => app.set_focus(Focus::Compose),
        KeyCode::Char(':') if app.focus != Focus::Compose => {
            app.set_focus(Focus::Compose);
            if app.draft.is_empty() {
                app.insert(":");
            }
        }
        KeyCode::Char(ch)
            if !event
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            let mut buffer = [0; 4];
            app.insert(ch.encode_utf8(&mut buffer));
        }
        _ => {}
    }
    InputOutcome::Nothing
}

fn submit(app: &mut App) -> InputOutcome {
    match app.submit() {
        Ok(Some(action)) => InputOutcome::Action(action),
        Ok(None) => InputOutcome::Nothing,
        Err(error) => {
            app.notice = error.to_string();
            InputOutcome::Nothing
        }
    }
}

#[derive(Clone, Copy)]
enum Hit {
    Pane(Focus),
    Row(Focus, usize),
    Tab(Focus),
    Send,
    Confirm,
    Dismiss,
    Refresh,
    Quit,
}

#[derive(Default)]
struct HitMap(Vec<(Rect, Hit)>);

fn mouse(app: &mut App, hits: &HitMap, event: MouseEvent) -> InputOutcome {
    let position = Position::new(event.column, event.row);
    match event.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let hit = hits
                .0
                .iter()
                .rev()
                .find(|(area, _)| area.contains(position));
            if app.confirm.is_some() {
                return match hit {
                    Some((_, Hit::Confirm)) if !app.pending => app
                        .confirm
                        .take()
                        .map_or(InputOutcome::Nothing, InputOutcome::Action),
                    Some((_, Hit::Dismiss)) => {
                        app.confirm = None;
                        InputOutcome::Nothing
                    }
                    _ => InputOutcome::Nothing,
                };
            }
            match hit.map(|(_, hit)| *hit) {
                Some(Hit::Pane(focus)) if app.focus != focus => app.set_focus(focus),
                Some(Hit::Tab(focus)) => app.set_focus(focus),
                Some(Hit::Row(Focus::Messages, index)) => {
                    app.set_focus(Focus::Messages);
                    if let Some(view) = app.conversation().and_then(|key| app.views.get_mut(&key))
                        && index < view.events.len()
                    {
                        view.selected = index;
                        app.detail = true;
                    }
                }
                Some(Hit::Row(focus, index)) => {
                    app.set_focus(focus);
                    app.select(focus, index);
                }
                Some(Hit::Send) => {
                    app.set_focus(Focus::Compose);
                    return submit(app);
                }
                Some(Hit::Refresh) => app.catalog_at = None,
                Some(Hit::Quit) => return InputOutcome::Exit,
                _ => {}
            }
        }
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown if app.confirm.is_none() => {
            if let Some(focus) = hits.0.iter().find_map(|(area, hit)| match hit {
                Hit::Pane(focus) if area.contains(position) => Some(*focus),
                _ => None,
            }) {
                if app.focus != focus {
                    app.set_focus(focus);
                }
                app.move_selection(event.kind == MouseEventKind::ScrollUp);
            }
        }
        _ => {}
    }
    InputOutcome::Nothing
}

fn draw(frame: &mut Frame<'_>, app: &App) -> HitMap {
    let mut hits = HitMap::default();
    let [header, body, status, compose, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let device = app.device.as_ref().map_or_else(
        || "loading identity".to_owned(),
        |device| hex::encode(device.id),
    );
    let mesh = if app.mesh_available {
        "Mesh socket available"
    } else {
        "Mesh offline"
    };
    frame.render_widget(
        Paragraph::new(format!("Howl   {}   {mesh}", short(&device))),
        header,
    );

    if app.focus == Focus::Device {
        hits.0.push((body, Hit::Pane(Focus::Device)));
        draw_device(frame, body, app);
    } else {
        let [channels, peers, messages] = Layout::horizontal([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(60),
        ])
        .areas(body);
        draw_navigation(frame, app, &mut hits, channels, peers);
        draw_messages(frame, app, &mut hits, messages);
    }
    frame.render_widget(
        Paragraph::new(status_text(app))
            .block(panel("Delivery and work", false))
            .wrap(Wrap { trim: false }),
        status,
    );
    let [compose, controls] = Layout::horizontal([
        Constraint::Min(1),
        Constraint::Length(if app.confirm.is_some() { 20 } else { 8 }),
    ])
    .areas(compose);
    let composer = if let Some(action) = &app.confirm {
        match action {
            Action::Cancel { root, .. } => format!(
                "Pause run {}? Press y to confirm.",
                short(&hex::encode(root))
            ),
            Action::CancelWake { peer, wake, .. } => format!(
                "Cancel wake {} to peer {}? Press y to confirm.",
                short(&hex::encode(wake)),
                short(&hex::encode(peer)),
            ),
            _ => String::new(),
        }
    } else if app.pending {
        "Working…".into()
    } else if app.draft.is_empty() {
        "Type a message, or @architect / @reviewer from a direct conversation".into()
    } else {
        let shown = compose.width.saturating_sub(2) as usize;
        let tail = app.draft.chars().rev().take(shown).collect::<Vec<_>>();
        tail.into_iter().rev().map(display_char).collect()
    };
    hits.0.push((compose, Hit::Pane(Focus::Compose)));
    frame.render_widget(
        Paragraph::new(composer).block(panel(
            if app.focus == Focus::Compose {
                "Compose · Esc to leave"
            } else {
                "Compose"
            },
            app.focus == Focus::Compose,
        )),
        compose,
    );
    let mut controls = Rect::new(
        controls.x,
        controls.y.saturating_add(1),
        controls.width,
        controls.height.min(2).saturating_sub(1),
    );
    if app.confirm.is_some() {
        button(
            frame,
            &mut hits,
            &mut controls,
            "[Confirm]",
            Hit::Confirm,
            true,
        );
        button(
            frame,
            &mut hits,
            &mut controls,
            "[Back]",
            Hit::Dismiss,
            false,
        );
    } else if !app.pending && !app.draft.trim().is_empty() {
        button(frame, &mut hits, &mut controls, "[Send]", Hit::Send, true);
    }
    let mut footer = footer;
    for (label, focus) in [
        "1 Channels",
        "2 Direct",
        "3 Messages",
        "4 Device",
        "5 Compose",
    ]
    .into_iter()
    .zip(Focus::PANES)
    {
        button(
            frame,
            &mut hits,
            &mut footer,
            label,
            Hit::Tab(focus),
            app.focus == focus,
        );
    }
    button(
        frame,
        &mut hits,
        &mut footer,
        "r Refresh",
        Hit::Refresh,
        false,
    );
    button(
        frame,
        &mut hits,
        &mut footer,
        "Ctrl+Q Quit",
        Hit::Quit,
        false,
    );
    hits
}

fn button(
    frame: &mut Frame<'_>,
    hits: &mut HitMap,
    row: &mut Rect,
    label: &str,
    hit: Hit,
    active: bool,
) {
    let width = label.len() as u16;
    if width > row.width || row.height == 0 {
        return;
    }
    let area = Rect::new(row.x, row.y, width, 1);
    let style = Style::default().add_modifier(if active {
        Modifier::REVERSED
    } else {
        Modifier::UNDERLINED
    });
    frame.render_widget(Paragraph::new(label).style(style), area);
    hits.0.push((area, hit));
    let used = (width + 2).min(row.width);
    row.x = row.x.saturating_add(used);
    row.width -= used;
}

fn panel(title: &str, focused: bool) -> Block<'_> {
    let style = if focused {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Block::bordered().title(title).border_style(style)
}

fn draw_navigation(
    frame: &mut Frame<'_>,
    app: &App,
    hits: &mut HitMap,
    channels: Rect,
    peers: Rect,
) {
    let channel_selection = app
        .channels
        .iter()
        .position(|entry| Some(entry.id) == app.channel);
    let channel_list = app
        .channels
        .iter()
        .map(|entry| ListItem::new(short(&hex::encode(entry.id)).to_owned()));
    draw_list(
        frame,
        hits,
        Focus::Channels,
        channels,
        panel("Channels", app.focus == Focus::Channels),
        channel_list,
        channel_selection,
    );
    let selected = app
        .peers()
        .iter()
        .position(|peer| Some(*peer) == app.peer)
        .map_or(0, |index| index + 1);
    let peers_list = std::iter::once(ListItem::new("Whole channel")).chain(
        app.peers()
            .iter()
            .map(|peer| ListItem::new(app.peer_label(peer))),
    );
    draw_list(
        frame,
        hits,
        Focus::Peers,
        peers,
        panel("Direct peers", app.focus == Focus::Peers),
        peers_list,
        Some(selected),
    );
}

fn draw_list<'a>(
    frame: &mut Frame<'_>,
    hits: &mut HitMap,
    focus: Focus,
    area: Rect,
    block: Block<'a>,
    items: impl IntoIterator<Item = ListItem<'a>>,
    selected: Option<usize>,
) {
    hits.0.push((area, Hit::Pane(focus)));
    let inner = block.inner(area);
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let len = list.len();
    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(list, area, &mut state);
    for (row, index) in (state.offset()..len).take(inner.height.into()).enumerate() {
        hits.0.push((
            Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
            Hit::Row(focus, index),
        ));
    }
}

fn draw_messages(frame: &mut Frame<'_>, app: &App, hits: &mut HitMap, area: Rect) {
    let block = panel("Messages", app.focus == Focus::Messages);
    let Some(view) = app.conversation().and_then(|key| app.views.get(&key)) else {
        hits.0.push((area, Hit::Pane(Focus::Messages)));
        frame.render_widget(
            Paragraph::new("Select an enrolled channel to view messages.").block(block),
            area,
        );
        return;
    };
    if app.detail
        && let Some(event) = view.events.get(view.selected)
    {
        hits.0.push((area, Hit::Pane(Focus::Messages)));
        let message = &event.message;
        let mut text = format!("Message {}\nFrom {}", message.message, message.sender);
        if let Some(reply) = &message.in_reply_to {
            text.push_str(&format!("\nReply to {reply}"));
        }
        if let Some(actor) = message.agent.as_ref().or(message.target.as_ref()) {
            text.push_str(&format!("\nAgent {actor}"));
        }
        text.push_str(&format!("\n\n{}", visible(&message.text)));
        frame.render_widget(
            Paragraph::new(text)
                .block(block)
                .wrap(Wrap { trim: false })
                .scroll((app.scroll, 0)),
            area,
        );
        return;
    }
    if view.events.is_empty() {
        hits.0.push((area, Hit::Pane(Focus::Messages)));
        frame.render_widget(Paragraph::new("No messages yet.").block(block), area);
        return;
    }
    let items = view.events.iter().map(|event| {
        let message = &event.message;
        let sender = message.integration.as_deref().unwrap_or(&message.sender);
        let role = message.role.unwrap_or(if message.integration.is_some() {
            "integration"
        } else {
            "human"
        });
        let thread = message
            .in_reply_to
            .as_ref()
            .map_or_else(String::new, |id| format!(" ↳{}", short(id)));
        let text: String = message.text.chars().take(320).map(display_char).collect();
        ListItem::new(format!("{role} {}{thread}  {text}", short(sender)))
    });
    draw_list(
        frame,
        hits,
        Focus::Messages,
        area,
        block,
        items,
        Some(view.selected),
    );
}

fn status_text(app: &App) -> String {
    let Some(view) = app.conversation().and_then(|key| app.views.get(&key)) else {
        return visible(&app.notice);
    };
    let peer = app.peer.map(hex::encode);
    let mut agents = view
        .agents
        .iter()
        .filter(|agent| peer.as_ref() == Some(&agent.device))
        .map(|agent| format!("{} {}", visible(agent.role), visible(agent.availability)))
        .collect::<Vec<_>>();
    let workflow = view.workflows.iter().find(|work| {
        peer.is_none()
            || view
                .agents
                .iter()
                .any(|agent| peer.as_ref() == Some(&agent.device) && agent.id == work.target)
    });
    if let Some(work) = workflow {
        agents.push(if work.paused {
            "paused".into()
        } else {
            visible(&work.state)
        });
        if let Some(root) = &work.root {
            agents.push(format!("root {}", visible(root)));
        }
    }
    if !app.delivery.is_empty() {
        let delivered = app
            .delivery
            .iter()
            .filter(|status| status.acknowledged)
            .count();
        let attempts: u64 = app
            .delivery
            .iter()
            .map(|status| u64::from(status.attempts))
            .sum();
        agents.push(format!(
            "Last delivery {delivered}/{} acknowledged · {attempts} attempts",
            app.delivery.len()
        ));
    }
    if view.gap {
        agents.push("Older events unavailable".into());
    } else if view.more {
        agents.push("Replaying events".into());
    }
    if !app.notice.is_empty() {
        agents.push(visible(&app.notice));
    }
    agents.join(" · ")
}

fn draw_device(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = Vec::new();
    if let Some(device) = &app.device {
        lines.push(format!(
            "Device {}  {}",
            hex::encode(device.id),
            if device.enrolled {
                "Enrolled"
            } else {
                "Enrollment needed"
            }
        ));
        lines.push(format!("Fingerprint {}", visible(&device.fingerprint)));
        lines.push(format!("Certificate {}", visible(&device.certificate)));
    }
    lines.extend([
        String::new(),
        "Enter commands in Compose (5)".into(),
        ":connect LISTEN [RELAY]   :disconnect   :refresh   :device".into(),
        ":route ADDRESS  (with a direct peer selected)".into(),
        ":cancel [ROOT]  (pause a signed local workflow)".into(),
        ":cancel-wake [MESSAGE]  (cancel an outgoing wake in the direct conversation)".into(),
        ":enroll authority".into(),
        ":enroll identity EXCHANGE".into(),
        ":enroll respond EXCHANGE ACCOUNT HEAD DESIGNATION SECRET_DIR".into(),
        ":enroll accept EXCHANGE ACCOUNT HEAD DESIGNATION".into(),
        ":enroll peer EXCHANGE".into(),
    ]);
    lines.extend(app.device_output.lines().map(visible));
    frame.render_widget(
        Paragraph::new(lines.join("\n"))
            .block(panel("Device", true))
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0)),
        area,
    );
}

#[cfg(test)]
mod tests;
