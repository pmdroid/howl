use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use agent_client_protocol::v1::schema::{
    ContentBlock, PermissionOptionKind, SessionUpdate, StopReason,
};
use howl::{
    managed_acp::{
        Capabilities, ChatGptPlanAuth, Close, Error, Event, Harness, ManagedSession,
        PermissionDecision, Phase, Restore,
    },
    observer::{ObserverProvider, Snapshot},
    provider_broker::Provider,
};
use tokio::time::{sleep, timeout};

const LIMIT: Duration = Duration::from_secs(5);

fn repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("tracked.txt"), "approved\n").unwrap();
    fs::write(root.path().join("other.txt"), "different approved scope\n").unwrap();
    for args in [
        &["init", "-q", "--template="][..],
        &["add", "--all"],
        &["commit", "-qm", "fixture"],
    ] {
        let output = Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .arg("-C")
            .arg(root.path())
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    root
}

fn snapshot(repo: &Path, name: &str) -> Snapshot {
    Snapshot::from_commit(repo, "HEAD", &[PathBuf::from(name)]).unwrap()
}

fn fixture(minimal: bool) -> Harness {
    let args = if minimal {
        &["/fixture/agent.mjs", "--minimal"][..]
    } else {
        &["/fixture/agent.mjs"]
    };
    Harness::new(
        "controlled-acp",
        std::env::var("HOWL_MANAGED_FIXTURE_IMAGE").unwrap(),
        "/usr/local/bin/node",
        args,
    )
}

fn provider() -> ObserverProvider {
    let socket = std::env::var_os("HOWL_OBSERVER_DOCKER_SOCKET").unwrap();
    ObserverProvider::connect(Path::new(&socket)).unwrap()
}

async fn stopped(session: &ManagedSession, phase: Phase) {
    timeout(LIMIT, async {
        loop {
            let state = session.status();
            if state.phase == phase && state.container.is_none() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

fn fixture_v2(script: &str, args: &[&str]) -> Harness {
    let args = std::iter::once(script)
        .chain(args.iter().copied())
        .collect::<Vec<_>>();
    Harness::new(
        "controlled-acp",
        std::env::var("HOWL_MANAGED_FIXTURE_IMAGE").unwrap(),
        "/usr/local/bin/node",
        &args,
    )
    .with_acp_v2()
}

#[tokio::test]
#[ignore = "requires a local Linux engine and disposable ACP fixture image"]
async fn returns_the_entire_turn_when_the_event_subscriber_lags() {
    let repo = repository();
    let root = tempfile::tempdir().unwrap();
    let chunks: String = (0..160).map(|index| format!("{index}/")).collect();
    for (harness, expected) in [
        (fixture(false), chunks.clone()),
        (
            fixture_v2("/fixture/agent-v2.mjs", &[]),
            format!("{chunks}\nrun-42"),
        ),
    ] {
        let session = ManagedSession::start(
            &root.path().join("journal"),
            &provider(),
            snapshot(repo.path(), "tracked.txt"),
            harness,
        )
        .await
        .unwrap();
        let mut stream = session.subscribe();
        let turn = session.prompt_text("burst".into(), LIMIT);
        tokio::pin!(turn);
        assert!(futures_util::poll!(turn.as_mut()).is_pending());
        timeout(LIMIT, async {
            while stream.len() <= 64 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(turn.await.unwrap(), expected);
        assert!(matches!(
            stream.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_))
        ));
        let next = session.prompt_text("hello".into(), LIMIT).await.unwrap();
        assert!(next == "fixture reply" || next == "v2 fixture reply");
        session.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires a local Linux engine and disposable ACP fixture image"]
async fn negotiates_v2_and_handles_authoritative_turn_completion() {
    use agent_client_protocol::{schema::ProtocolVersion, v2::schema};

    let provider = provider();
    let repo = repository();
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("state");
    let start = || fixture_v2("/fixture/agent-v2.mjs", &[]);
    let session = ManagedSession::start(
        &journal,
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        start(),
    )
    .await
    .unwrap();
    let initial = session.status();
    assert_eq!(initial.protocol_version, Some(ProtocolVersion::V2));
    assert_eq!(
        initial.capabilities,
        Capabilities {
            load: false,
            resume: true,
            close: true
        }
    );
    let mut events = session.subscribe();
    assert_eq!(
        session.prompt("hello".into(), LIMIT).await.unwrap(),
        StopReason::EndTurn
    );
    timeout(LIMIT, async {
        loop {
            if let Event::UpdateV2(update) = events.recv().await.unwrap()
                && let schema::SessionUpdate::AgentMessageChunk(chunk) = update.update
                && let schema::ContentBlock::Text(text) = chunk.content
            {
                assert_eq!(text.text, "v2 fixture reply");
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        session.prompt("error".into(), LIMIT).await,
        Err(Error::Remote(-32030))
    ));

    for (prompt, expected) in [
        ("hold", PermissionDecision::RejectOnce),
        ("permanent", PermissionDecision::Cancelled),
    ] {
        let inspect = async {
            let (offered, decision) = timeout(LIMIT, async {
                loop {
                    if let Event::PermissionV2 { offered, decision } = events.recv().await.unwrap()
                    {
                        break (offered, decision);
                    }
                }
            })
            .await
            .unwrap();
            assert!(offered.contains(&schema::PermissionOptionKind::AllowAlways));
            assert_eq!(decision, expected);
            assert_eq!(session.status().phase, Phase::Active);
            assert!(matches!(
                session.prompt("overlap".into(), LIMIT).await,
                Err(Error::Busy)
            ));
            session.cancel().await.unwrap();
        };
        let (result, ()) = tokio::join!(session.prompt(prompt.into(), LIMIT), inspect);
        assert_eq!(result.unwrap(), StopReason::Cancelled);
    }

    assert!(matches!(
        session
            .prompt("wait".into(), Duration::from_millis(100))
            .await,
        Err(Error::TimedOut)
    ));
    assert_eq!(session.status().phase, Phase::Ready);
    assert!(matches!(
        session.restore(Restore::Load).await,
        Err(Error::Unsupported("session/load"))
    ));
    assert!(session.prompt("crash".into(), LIMIT).await.is_err());
    stopped(&session, Phase::Interrupted).await;

    let recovered = ManagedSession::recover(
        &journal,
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        start(),
        &initial.id,
        Restore::Resume,
    )
    .await
    .unwrap();
    assert_eq!(recovered.status().remote_session, initial.remote_session);
    assert_eq!(
        recovered.prompt("again".into(), LIMIT).await.unwrap(),
        StopReason::EndTurn
    );
    assert_eq!(recovered.close().await.unwrap(), Close::Remote);
    stopped(&recovered, Phase::Closed).await;
}

#[tokio::test]
#[ignore = "requires a local Linux engine and disposable ACP fixture image"]
async fn initial_v2_foreground_state_blocks_prompt_until_cancelled() {
    use agent_client_protocol::v2::schema::{SessionUpdate, StateUpdate};

    let repo = repository();
    let root = tempfile::tempdir().unwrap();
    let session = ManagedSession::start(
        &root.path().join("state"),
        &provider(),
        snapshot(repo.path(), "tracked.txt"),
        fixture_v2("/fixture/agent-v2.mjs", &["--initial-active"]),
    )
    .await
    .unwrap();
    let mut events = session.subscribe();
    assert!(matches!(
        session.prompt("unexpected".into(), LIMIT).await,
        Err(Error::Busy)
    ));
    session.cancel().await.unwrap();
    timeout(LIMIT, async {
        loop {
            if let Event::UpdateV2(update) = events.recv().await.unwrap()
                && matches!(
                    update.update,
                    SessionUpdate::StateUpdate(StateUpdate::Idle(_))
                )
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        session.prompt("hello".into(), LIMIT).await.unwrap(),
        StopReason::EndTurn
    );
    assert_eq!(session.close().await.unwrap(), Close::Remote);
    stopped(&session, Phase::Closed).await;
}

#[tokio::test]
#[ignore = "requires a local Linux engine and disposable ACP fixture image"]
async fn an_opt_in_probe_can_negotiate_back_to_v1() {
    use agent_client_protocol::schema::ProtocolVersion;

    let repo = repository();
    let root = tempfile::tempdir().unwrap();
    let session = ManagedSession::start(
        &root.path().join("state"),
        &provider(),
        snapshot(repo.path(), "tracked.txt"),
        fixture_v2("/fixture/agent.mjs", &["--expect-v2-offer"]),
    )
    .await
    .unwrap();
    assert_eq!(session.status().protocol_version, Some(ProtocolVersion::V1));
    assert_eq!(
        session.prompt("v1 turn".into(), LIMIT).await.unwrap(),
        StopReason::EndTurn
    );
    assert_eq!(session.close().await.unwrap(), Close::Remote);
    stopped(&session, Phase::Closed).await;
}

#[tokio::test]
#[ignore = "requires a local Linux engine and disposable ACP fixture image"]
async fn manages_capabilities_cancellation_and_crash_recovery() {
    let provider = provider();
    let repo = repository();
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("state");
    let session = ManagedSession::start(
        &journal,
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        fixture(false),
    )
    .await
    .unwrap();
    let state = session.status();
    assert_eq!(state.phase, Phase::Ready);
    assert_eq!(
        state.capabilities,
        Capabilities {
            load: true,
            resume: true,
            close: true
        }
    );
    assert!(state.container.is_some());
    let mut events = session.subscribe();
    assert_eq!(
        session.prompt("hello".into(), LIMIT).await.unwrap(),
        StopReason::EndTurn
    );
    assert!(matches!(
        timeout(LIMIT, events.recv()).await.unwrap().unwrap(),
        Event::Update(_)
    ));
    assert!(matches!(
        ManagedSession::recover(
            &journal,
            &provider,
            snapshot(repo.path(), "tracked.txt"),
            fixture(false),
            &state.id,
            Restore::Resume
        )
        .await,
        Err(Error::InUse),
    ));

    for (prompt, expected) in [
        ("hold", PermissionDecision::RejectOnce),
        ("permanent", PermissionDecision::Cancelled),
    ] {
        let permission = async {
            let event = timeout(LIMIT, events.recv()).await.unwrap().unwrap();
            let Event::Permission { offered, decision } = event else {
                panic!("expected permission audit event")
            };
            assert!(offered.contains(&PermissionOptionKind::AllowAlways));
            assert_eq!(decision, expected);
            assert_eq!(session.status().phase, Phase::Active);
            assert!(matches!(
                session.prompt("unexpected".into(), LIMIT).await,
                Err(Error::Busy)
            ));
            session.cancel().await.unwrap();
        };
        let (result, ()) = tokio::join!(session.prompt(prompt.into(), LIMIT), permission);
        assert_eq!(result.unwrap(), StopReason::Cancelled);
    }
    session.restore(Restore::Load).await.unwrap();

    assert!(session.prompt("crash".into(), LIMIT).await.is_err());
    stopped(&session, Phase::Interrupted).await;
    assert!(matches!(
        ManagedSession::recover(
            &journal,
            &provider,
            snapshot(repo.path(), "other.txt"),
            fixture(false),
            &state.id,
            Restore::Fresh
        )
        .await,
        Err(Error::ScopeChanged),
    ));
    let recovered = ManagedSession::recover(
        &journal,
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        fixture(false),
        &state.id,
        Restore::Resume,
    )
    .await
    .unwrap();
    assert_eq!(recovered.status().remote_session, state.remote_session);
    assert_ne!(recovered.status().container, state.container);
    assert_eq!(
        recovered.prompt("again".into(), LIMIT).await.unwrap(),
        StopReason::EndTurn
    );
    assert_eq!(recovered.close().await.unwrap(), Close::Remote);
    stopped(&recovered, Phase::Closed).await;
}

#[tokio::test]
#[ignore = "requires a local Linux engine and disposable ACP fixture image"]
async fn bounds_stuck_turns_and_degrades_unsupported_methods() {
    let provider = provider();
    let repo = repository();
    let root = tempfile::tempdir().unwrap();
    let journal = root.path().join("state");
    let session = ManagedSession::start(
        &journal,
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        fixture(true),
    )
    .await
    .unwrap();
    assert_eq!(session.status().capabilities, Capabilities::default());
    assert!(matches!(
        session.restore(Restore::Load).await,
        Err(Error::Unsupported("session/load"))
    ));
    assert!(matches!(
        session.restore(Restore::Resume).await,
        Err(Error::Unsupported("session/resume"))
    ));
    assert_eq!(session.close().await.unwrap(), Close::Local);
    stopped(&session, Phase::Closed).await;

    let session = ManagedSession::start(
        &journal,
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        fixture(true),
    )
    .await
    .unwrap();
    assert!(matches!(
        session
            .prompt("ignore".into(), Duration::from_millis(100))
            .await,
        Err(Error::TimedOut)
    ));
    stopped(&session, Phase::Interrupted).await;

    let session = ManagedSession::start(
        &journal,
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        fixture(true),
    )
    .await
    .unwrap();
    assert!(session.prompt("oversize".into(), LIMIT).await.is_err());
    stopped(&session, Phase::Interrupted).await;
}

async fn provider_reply(harness: Harness) {
    let provider = provider();
    let repo = repository();
    let store = tempfile::tempdir().unwrap();
    let session = ManagedSession::start(
        &store.path().join("journal"),
        &provider,
        snapshot(repo.path(), "tracked.txt"),
        harness,
    )
    .await
    .unwrap();
    let mut events = session.subscribe();
    let result = session
        .prompt(
            "Reply with the single word HOWL_OK. Do not use tools.".to_owned(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert!(matches!(result, StopReason::EndTurn));
    let saw_reply = timeout(LIMIT, async {
        let mut output = String::new();
        while let Ok(event) = events.recv().await {
            if let Event::Update(update) = event
                && let SessionUpdate::AgentMessageChunk(chunk) = update.update
                && let ContentBlock::Text(text) = chunk.content
            {
                output.push_str(&text.text);
                if output.contains("HOWL_OK") {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(saw_reply, "no expected provider reply received");
    session.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the pinned Codex image, configured model, and a host OpenAI API key"]
async fn live_brokered_codex() {
    let model = std::env::var("HOWL_CODEX_MODEL").expect("set HOWL_CODEX_MODEL");
    provider_reply(
        Harness::new(
            "codex-brokered",
            std::env::var("HOWL_CODEX_IMAGE").expect("set HOWL_CODEX_IMAGE"),
            "/usr/local/bin/node",
            &["/fixture/codex-wrapper.mjs", &model],
        )
        .with_provider(Provider::OpenAi, &model),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires the pinned Codex image and ChatGPT plan consent"]
async fn live_chatgpt_plan_codex() {
    let model = std::env::var("HOWL_CODEX_MODEL").expect("set HOWL_CODEX_MODEL");
    let host_node = std::env::var_os("HOWL_CHATGPT_NODE").expect("set HOWL_CHATGPT_NODE");
    let store = std::env::var_os("HOWL_CHATGPT_STORE").expect("set HOWL_CHATGPT_STORE");
    let helper =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/chatgpt-auth/chatgpt-auth.mjs");
    let auth = ChatGptPlanAuth::new(host_node.into(), helper, store.into()).unwrap();
    provider_reply(
        Harness::new(
            "codex-chatgpt",
            std::env::var("HOWL_CODEX_IMAGE").expect("set HOWL_CODEX_IMAGE"),
            "/usr/local/bin/node",
            &["/fixture/codex-wrapper.mjs", &model],
        )
        .with_chatgpt_plan(&model, auth),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires the pinned Grok image, configured model, and a host xAI API key"]
async fn live_brokered_grok() {
    let model = std::env::var("HOWL_GROK_MODEL").unwrap_or_else(|_| "grok-4.7".to_owned());
    provider_reply(
        Harness::new(
            "grok-brokered",
            std::env::var("HOWL_GROK_IMAGE").expect("set HOWL_GROK_IMAGE"),
            "/bin/sh",
            &["/usr/local/share/howl/grok-provider.sh", &model],
        )
        .with_provider(Provider::XAi, &model),
    )
    .await;
}
