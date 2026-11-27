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
        DisableBracketedPaste, EnableBracketedPaste, Event as Input, EventStream, KeyCode,
        KeyEvent, KeyEventKind, KeyModifiers,
    },
    execute,
};
use futures_util::StreamExt;
use howl_envelope::{AgentRole, Id};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout, Rect},
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
    fn step(self, backwards: bool) -> Self {
        let panes = [
            Self::Channels,
            Self::Peers,
            Self::Messages,
            Self::Device,
            Self::Compose,
        ];
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
                self.channel = self
                    .channels
                    .get(shift(selected, self.channels.len(), offset))
                    .map(|entry| entry.id);
                self.peer = None;
                self.detail = false;
                self.catalog_at = None;
            }
            Focus::Peers => {
                let peers = self.peers();
                let selected = peers
                    .iter()
                    .position(|peer| Some(*peer) == self.peer)
                    .map_or(0, |index| index + 1);
                let next = shift(selected, peers.len() + 1, offset);
                self.peer = next
                    .checked_sub(1)
                    .and_then(|next| peers.get(next))
                    .copied();
                self.detail = false;
                self.catalog_at = None;
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
            _ => return Err(invalid("Commands available in Device (F4).")),
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
        _ => Err(invalid("Choose an enrollment action shown in Device (F4).")),
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
        let _ = execute!(io::stdout(), DisableBracketedPaste);
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
    execute!(io::stdout(), EnableBracketedPaste)?;
    let mut app = App::new();
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
        terminal.draw(|frame| draw(frame, app))?;
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
            input = inputs.next() => match input {
                None => break,
                Some(Err(error)) => return Err(error),
                Some(Ok(Input::Paste(text))) => app.insert(&text),
                Some(Ok(Input::Key(event))) if event.kind != KeyEventKind::Release => {
                    match key(app, event) {
                        InputOutcome::Exit => break,
                        InputOutcome::Nothing => {}
                        InputOutcome::Action(action) => {
                            app.pending = true;
                            let state = state.to_owned();
                            let actions = action_tx.clone();
                            tokio::spawn(async move { let _ = actions.send(action.execute(state).await).await; });
                        }
                    }
                }
                Some(Ok(_)) => {}
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
        KeyCode::F(1) => app.set_focus(Focus::Channels),
        KeyCode::F(2) => app.set_focus(Focus::Peers),
        KeyCode::F(3) => app.set_focus(Focus::Messages),
        KeyCode::F(4) => app.set_focus(Focus::Device),
        KeyCode::F(5) => app.set_focus(Focus::Compose),
        KeyCode::Up => app.move_selection(true),
        KeyCode::Down => app.move_selection(false),
        KeyCode::Enter if app.focus == Focus::Messages => {
            app.detail = !app.detail;
            app.scroll = 0;
        }
        KeyCode::Enter if app.focus == Focus::Compose && event.kind == KeyEventKind::Press => {
            match app.submit() {
                Ok(Some(action)) => return InputOutcome::Action(action),
                Ok(None) => {}
                Err(error) => app.notice = error.to_string(),
            }
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

fn draw(frame: &mut Frame<'_>, app: &App) {
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
        draw_device(frame, body, app);
    } else {
        let [channels, peers, messages] = Layout::horizontal([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(60),
        ])
        .areas(body);
        draw_navigation(frame, app, channels, peers);
        draw_messages(frame, messages, app);
    }
    frame.render_widget(
        Paragraph::new(status_text(app))
            .block(panel("Delivery and work", false))
            .wrap(Wrap { trim: false }),
        status,
    );
    let composer = if let Some(action) = &app.confirm {
        match action {
            Action::Cancel { root, .. } => format!("Pause run {}? y confirms.", hex::encode(root)),
            Action::CancelWake { peer, wake, .. } => format!(
                "Cancel wake {} to peer {}? y confirms.",
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
    frame.render_widget(
        Paragraph::new(composer).block(panel("Compose", app.focus == Focus::Compose)),
        compose,
    );
    frame.render_widget(
        Paragraph::new(
            "F1 Channels  F2 Direct  F3 Messages  F4 Device  F5 Compose  r Refresh  Ctrl+Q Quit",
        ),
        footer,
    );
}

fn panel(title: &str, focused: bool) -> Block<'_> {
    let style = if focused {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Block::bordered().title(title).border_style(style)
}

fn draw_navigation(frame: &mut Frame<'_>, app: &App, channels: Rect, peers: Rect) {
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
            .map(|peer| ListItem::new(short(&hex::encode(peer)).to_owned())),
    );
    draw_list(
        frame,
        peers,
        panel("Direct peers", app.focus == Focus::Peers),
        peers_list,
        Some(selected),
    );
}

fn draw_list<'a>(
    frame: &mut Frame<'_>,
    area: Rect,
    block: Block<'a>,
    items: impl IntoIterator<Item = ListItem<'a>>,
    selected: Option<usize>,
) {
    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut state,
    );
}

fn draw_messages(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let block = panel("Messages", app.focus == Focus::Messages);
    let Some(view) = app.conversation().and_then(|key| app.views.get(&key)) else {
        frame.render_widget(
            Paragraph::new("Select an enrolled channel to view messages.").block(block),
            area,
        );
        return;
    };
    if app.detail
        && let Some(event) = view.events.get(view.selected)
    {
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
    draw_list(frame, area, block, items, Some(view.selected));
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
        "Enter commands in Compose (F5)".into(),
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
