use ratatui::{Terminal, backend::TestBackend};

use super::*;
use crate::interaction::Message;

const CHANNEL: Id = [1; 32];
const PEER: Id = [2; 32];

fn event(cursor: u64, text: &str) -> Event {
    Event {
        cursor,
        recipient: None,
        message: Message {
            message: hex::encode([3u8; 32]),
            sender: hex::encode(PEER),
            time: 4,
            text: text.into(),
            role: Some("agent"),
            integration: None,
            agent: Some(hex::encode([5u8; 32])),
            target: None,
            in_reply_to: Some(hex::encode([6u8; 32])),
            context_digest: None,
        },
    }
}

fn app() -> App {
    let mut app = App::new();
    app.channels.push(ChannelSummary {
        id: CHANNEL,
        peers: vec![PEER],
    });
    app.channel = Some(CHANNEL);
    app
}

#[test]
fn legacy_mentions_preserve_existing_targets_and_escape_as_chat() {
    let mut app = app();
    app.focus = Focus::Compose;
    app.insert("@reviewer inspect the changes");
    assert!(app.submit().is_err());
    app.peer = Some(PEER);
    let Some(Action::Wake {
        channel,
        peer,
        route,
        target,
        text,
    }) = app.submit().unwrap()
    else {
        panic!("expected a direct reviewer wake");
    };
    assert_eq!(channel, CHANNEL);
    assert_eq!(peer, PEER);
    assert_eq!(route, "-");
    assert_eq!(target, AgentRole::Reviewer.agent_id(&PEER));
    assert_eq!(text, "inspect the changes");

    app.draft = "@@reviewer was mentioned".into();
    let Some(Action::Direct { text, .. }) = app.submit().unwrap() else {
        panic!("escaped mention must remain chat");
    };
    assert_eq!(text, "@reviewer was mentioned");
    app.peer = None;
    app.draft = "Channel hello".into();
    assert!(matches!(
        app.submit().unwrap(),
        Some(Action::Post {
            channel: CHANNEL,
            ..
        })
    ));
}

#[test]
fn cursor_deduplicates_reconnect_and_permission_loss_clears_the_view() {
    let mut app = app();
    let key = (CHANNEL, None);
    let mut view = ConversationView::default();
    view.append(EventPage {
        events: vec![event(1, "first"), event(3, "second")],
        cursor: 3,
        gap: false,
        more: false,
    });
    view.append(EventPage {
        events: vec![event(3, "duplicate"), event(4, "third")],
        cursor: 8,
        gap: true,
        more: false,
    });
    assert_eq!(view.events.len(), 3);
    assert_eq!(view.cursor, 8);
    assert!(view.gap);
    app.views.insert(key, view);
    assert_eq!(app.refresh().conversation, Some((key, 8)));
    app.update(Update {
        catalog: Some(Catalog {
            device: Err(invalid("Unavailable")),
            channels: Err(io::ErrorKind::PermissionDenied.into()),
        }),
        view: Some(ViewUpdate {
            project: None,
            key,
            page: Ok(EventPage {
                events: vec![event(10, "old grant")],
                cursor: 10,
                gap: false,
                more: false,
            }),
            workflows: None,
        }),
        delivery: None,
    });
    assert!(app.views.is_empty());
    assert!(app.channel.is_none());
    assert!(app.focus == Focus::Device);
}

#[test]
fn enrollment_is_allowlisted_and_pause_requires_confirmation() {
    assert!(enrollment_args(&["recover", "test"]).is_err());
    assert!(enrollment_args(&["accept", "missing"]).is_err());
    assert_eq!(
        enrollment_args(&["identity", "literal;$file"]).unwrap(),
        ["identity", "literal;$file"]
    );
    let mut app = app();
    app.focus = Focus::Compose;
    let root = [9u8; 32];
    app.draft = format!(":cancel {}", hex::encode(root));
    assert!(app.submit().unwrap().is_none());
    assert!(matches!(
        key(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)
        ),
        InputOutcome::Nothing
    ));
    app.draft = format!(":cancel {}", hex::encode(root));
    assert!(app.submit().unwrap().is_none());
    assert!(matches!(
        key(&mut app, KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
        InputOutcome::Action(Action::Cancel { channel: CHANNEL, root: actual }) if actual == root
    ));
}

#[test]
fn remote_cancellation_is_scoped_to_an_outgoing_human_wake() {
    let mut app = app();
    let local = [7u8; 32];
    app.device = Some(LocalDevice {
        id: local,
        certificate: String::new(),
        fingerprint: String::new(),
        enrolled: true,
    });
    app.peer = Some(PEER);
    let mut wake = event(1, "review");
    wake.message.role = Some("wake");
    wake.message.sender = hex::encode(local);
    wake.recipient = Some(hex::encode(PEER));
    let key = (CHANNEL, Some(PEER));
    app.views.entry(key).or_default().append(EventPage {
        events: vec![wake],
        cursor: 1,
        gap: false,
        more: false,
    });
    assert!(matches!(
        app.remote_cancel(None).unwrap(),
        Action::CancelWake { channel: CHANNEL, peer: PEER, wake, route }
            if wake == [3; 32] && route == "-"
    ));
    app.command("route 127.0.0.1:4711").unwrap();
    assert!(matches!(
        app.remote_cancel(None).unwrap(),
        Action::CancelWake { route, .. } if route == "127.0.0.1:4711"
    ));
    assert!(app.remote_cancel(Some(&hex::encode([4u8; 32]))).is_err());
    app.views.get_mut(&key).unwrap().events[0]
        .message
        .integration = Some(hex::encode([8u8; 32]));
    assert!(app.remote_cancel(None).is_err());
    app.peer = None;
    assert!(app.remote_cancel(None).is_err());
}

#[test]
fn display_cannot_execute_terminal_controls_from_a_signed_message() {
    let mut app = app();
    app.focus = Focus::Messages;
    let message = "safe\x1b[2J\u{202e}review";
    app.views
        .entry((CHANNEL, None))
        .or_default()
        .append(EventPage {
            events: vec![event(1, message)],
            cursor: 1,
            gap: false,
            more: false,
        });
    let mut terminal = Terminal::new(TestBackend::new(110, 23)).unwrap();
    terminal
        .draw(|frame| {
            draw(frame, &app);
        })
        .unwrap();
    let rendered: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(rendered.contains("safe�[2J�review"), "{rendered}");
    assert!(!rendered.contains('\x1b'));
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("↳0606060606"));
}

fn render_hits(app: &App) -> HitMap {
    let mut terminal = Terminal::new(TestBackend::new(80, 16)).unwrap();
    let mut hits = HitMap::default();
    terminal.draw(|frame| hits = draw(frame, app)).unwrap();
    hits
}

fn click(app: &mut App, target: impl Fn(Hit) -> bool) -> InputOutcome {
    let hits = render_hits(app);
    let area = hits.0.iter().find(|(_, hit)| target(*hit)).unwrap().0;
    mouse(
        app,
        &hits,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x,
            row: area.y,
            modifiers: KeyModifiers::NONE,
        },
    )
}

#[test]
fn numbers_switch_panes_and_remain_text_in_the_composer() {
    let mut app = app();
    for (digit, focus) in ('1'..='5').zip(Focus::PANES) {
        key(
            &mut app,
            KeyEvent::new(KeyCode::Char(digit), KeyModifiers::NONE),
        );
        assert!(app.focus == focus);
    }
    key(
        &mut app,
        KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE),
    );
    assert_eq!(app.draft, "2");
    key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.focus == Focus::Messages);
    key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert!(app.focus == Focus::Device);
}

#[test]
fn mouse_opens_visible_rows_and_sends_to_the_selected_peer() {
    let mut app = app();
    app.channels.push(ChannelSummary {
        id: [8; 32],
        peers: vec![PEER],
    });
    click(&mut app, |hit| matches!(hit, Hit::Row(Focus::Channels, 1)));
    assert_eq!(app.channel, Some([8; 32]));
    click(&mut app, |hit| matches!(hit, Hit::Row(Focus::Peers, 1)));
    assert_eq!(app.peer, Some(PEER));
    let view = app.views.entry(([8; 32], Some(PEER))).or_default();
    view.events
        .extend((1..=20).map(|cursor| event(cursor, "message")));
    view.selected = 19;
    let hits = render_hits(&app);
    let first_visible = hits
        .0
        .iter()
        .find_map(|(_, hit)| match hit {
            Hit::Row(Focus::Messages, index) => Some(*index),
            _ => None,
        })
        .unwrap();
    assert!(first_visible > 0);
    click(
        &mut app,
        |hit| matches!(hit, Hit::Row(Focus::Messages, index) if index == first_visible),
    );
    assert!(app.detail);
    assert_eq!(app.views[&([8; 32], Some(PEER))].selected, first_visible);
    click(&mut app, |hit| matches!(hit, Hit::Tab(Focus::Device)));
    assert!(app.focus == Focus::Device);
    click(&mut app, |hit| matches!(hit, Hit::Pane(Focus::Compose)));
    app.insert("hello");
    assert!(matches!(click(&mut app, |hit| matches!(hit, Hit::Send)),
        InputOutcome::Action(Action::Direct { peer: PEER, text, .. }) if text == "hello"));
}

#[test]
fn mouse_confirmation_requires_the_confirm_button() {
    let mut app = app();
    app.draft = format!(":cancel {}", hex::encode([9; 32]));
    app.submit().unwrap();
    assert!(matches!(
        click(&mut app, |hit| matches!(hit, Hit::Tab(Focus::Peers))),
        InputOutcome::Nothing
    ));
    assert!(app.confirm.is_some());
    click(&mut app, |hit| matches!(hit, Hit::Dismiss));
    assert!(app.confirm.is_none());
    app.draft = format!(":cancel {}", hex::encode([9; 32]));
    app.submit().unwrap();
    assert!(matches!(
        click(&mut app, |hit| matches!(hit, Hit::Confirm)),
        InputOutcome::Action(Action::Cancel { .. })
    ));
}

#[test]
fn named_worker_controls_are_direct_messages_to_the_completed_recipient() {
    let mut app = app();
    app.peer_labels.insert(hex::encode(PEER), "Claude".into());
    app.routes.insert(PEER, "127.0.0.1:3000".into());
    app.set_focus(Focus::Compose);
    for body in [
        "/work run",
        "/steer run keep both names",
        "/cancel run",
        "/work",
    ] {
        app.peer = None;
        app.draft = "@cl".into();
        assert!(app.complete());
        app.draft.push_str(body);
        assert!(
            matches!(app.submit().unwrap(), Some(Action::Direct { channel: CHANNEL, peer: PEER, route, text })
            if route == "127.0.0.1:3000" && text == body)
        );
    }
    app.draft = "@claude /workflow example".into();
    assert!(matches!(
        app.submit().unwrap(),
        Some(Action::Wake { peer: PEER, .. })
    ));
}

#[test]
fn completes_agent_names_for_tasks_and_channel_names_for_chat() {
    let mut app = App::new();
    let channel = [2; 32];
    let other_channel = [3; 32];
    let peer = [4; 32];
    app.channels = vec![
        ChannelSummary {
            id: channel,
            peers: vec![peer],
        },
        ChannelSummary {
            id: other_channel,
            peers: vec![],
        },
    ];
    app.channel = Some(channel);
    app.peer_labels
        .insert(hex::encode(peer), "Claude Code".into());
    app.set_focus(Focus::Compose);
    app.draft = "@cl".into();
    assert!(app.complete());
    assert_eq!(app.draft, "@claude-code ");
    assert!(app.submit().is_err());
    app.draft.push_str("Review the test");
    assert!(
        matches!(app.submit().unwrap(), Some(Action::Wake { peer: actual, target, text, .. })
        if actual == peer && target == AgentRole::default().agent_id(&peer) && text == "Review the test")
    );
    app.draft = "Hello".into();
    assert!(
        matches!(app.submit().unwrap(), Some(Action::Direct { peer: actual, text, .. })
        if actual == peer && text == "Hello")
    );
    let second = [5; 32];
    app.channels[0].peers.push(second);
    app.peer_labels
        .insert(hex::encode(second), "Claude Code".into());
    app.peer = None;
    app.draft = "@claude-code Review the test".into();
    assert!(app.submit().is_err());
    app.peer = Some(second);
    assert!(matches!(app.submit().unwrap(), Some(Action::Wake { peer, .. }) if peer == second));
    app.draft = "#03".into();
    assert!(app.complete());
    app.draft.push_str("Hello channel");
    assert!(
        matches!(app.submit().unwrap(), Some(Action::Post { channel: actual, text })
        if actual == other_channel && text == "Hello channel")
    );
}
