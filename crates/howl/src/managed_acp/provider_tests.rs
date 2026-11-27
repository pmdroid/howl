use std::{fs, process::Stdio};

use agent_client_protocol::v1::schema::{ContentBlock, SessionUpdate};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

use super::*;

#[tokio::test]
#[ignore = "requires both pinned harness images, Node, and a local Linux observer engine"]
async fn both_brokered_harnesses_stream_from_a_host_fixture() {
    exercise_brokers(&[
        (
            Provider::OpenAi,
            "HOWL_CODEX_IMAGE",
            "/usr/local/bin/node",
            "/fixture/codex-wrapper.mjs",
            "howl-fixture-model",
        ),
        (
            Provider::ChatGptPlan,
            "HOWL_CODEX_IMAGE",
            "/usr/local/bin/node",
            "/fixture/codex-wrapper.mjs",
            "howl-fixture-model",
        ),
        (
            Provider::XAi,
            "HOWL_GROK_IMAGE",
            "/bin/sh",
            "/usr/local/share/howl/grok-provider.sh",
            "grok-4.7",
        ),
    ])
    .await;
}

#[tokio::test]
#[ignore = "requires a pinned OpenCode image, Node, and a local Linux observer engine"]
async fn opencode_go_streams_from_the_host_broker() {
    exercise_brokers(&[(
        Provider::OpenCodeGo,
        "HOWL_OPENCODE_GO_IMAGE",
        "/usr/local/bin/node",
        "/usr/local/share/howl/opencode-provider.mjs",
        "howl-fixture-model",
    )])
    .await;
}

async fn exercise_brokers(cases: &[(Provider, &str, &str, &str, &str)]) {
    let socket = env_path("HOWL_OBSERVER_DOCKER_SOCKET");
    let provider = ObserverProvider::connect(&socket).unwrap();
    let repo = tempfile::tempdir().unwrap();
    fs::write(
        repo.path().join("selected.txt"),
        "synthetic observer test\n",
    )
    .unwrap();
    for args in [
        &["init", "--quiet", "--template="][..],
        &["add", "selected.txt"],
        &["commit", "-qm", "fixture"],
    ] {
        let status = std::process::Command::new("git")
            .current_dir(repo.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.test",
            ])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }
    let state = tempfile::tempdir().unwrap();
    for &(kind, image_variable, executable, wrapper, model) in cases {
        let id = match kind {
            Provider::OpenAi => "a",
            Provider::XAi => "b",
            Provider::ChatGptPlan => "c",
            Provider::OpenCodeGo => "d",
        }
        .repeat(32);
        let recorded_id = if kind == Provider::OpenCodeGo {
            &id
        } else {
            ""
        };
        let mut upstream = Command::new("node")
            .arg(format!(
                "{}/tests/fixtures/codex-acp/responses-fixture.mjs",
                env!("CARGO_MANIFEST_DIR")
            ))
            .args(["fixture-host-key", "0", model, recorded_id])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = BufReader::new(upstream.stdout.take().unwrap()).lines();
        let line = timeout(Duration::from_secs(5), ready.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let port = line.strip_prefix("Ready ").unwrap().parse().unwrap();
        let image = std::env::var(image_variable).expect("set the pinned fixture image ID");
        let harness = Harness::new("broker-fixture", image, executable, &[wrapper, model])
            .with_provider(kind, model);
        let snapshot =
            Snapshot::from_commit(repo.path(), "HEAD", &[PathBuf::from("selected.txt")]).unwrap();
        let session = ManagedSession::open_with_broker(
            &state.path().join("journal"),
            &provider,
            snapshot,
            harness,
            id,
            None,
            Some(Broker::fixture(kind, model, port)),
        )
        .await
        .unwrap();
        let mut events = session.subscribe();
        let result = session
            .prompt(
                "Reply only with a short acknowledgment.".to_owned(),
                Duration::from_secs(45),
            )
            .await
            .unwrap();
        assert!(matches!(result, StopReason::EndTurn));
        let mut text = String::new();
        let response = timeout(Duration::from_secs(5), async {
            while let Ok(event) = events.recv().await {
                if let Event::Update(update) = event
                    && let SessionUpdate::AgentMessageChunk(chunk) = update.update
                    && let ContentBlock::Text(chunk) = chunk.content
                {
                    text.push_str(&chunk.text);
                    if text.contains("howl-responses-fixture-ok") {
                        return true;
                    }
                }
            }
            false
        })
        .await
        .unwrap_or(false);
        assert!(
            response,
            "{kind:?} mock reply missing: {}",
            text.chars().take(300).collect::<String>()
        );
        session.close().await.unwrap();
        upstream.kill().await.unwrap();
    }
}

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect("set the observer Docker socket"))
}
