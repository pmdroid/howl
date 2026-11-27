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
            role: Some("reviewer"),
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
fn wake_requires_a_selected_peer_and_an_explicit_role_mention() {
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
            key,
            page: Ok(EventPage {
                events: vec![event(10, "old grant")],
                cursor: 10,
                gap: false,
                more: false,
            }),
            agents: None,
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
    terminal.draw(|frame| draw(frame, &app)).unwrap();
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
