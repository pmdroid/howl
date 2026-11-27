use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use agent_client_protocol::v1::schema::{ContentBlock, SessionUpdate, StopReason};
use howl::{
    managed_acp::{Event, Harness, HostClaude, HostCodex, HostGrok, ManagedSession},
    observer::{ObserverProvider, Snapshot},
};

fn configured(name: &str) -> PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("set {name}"))
        .into()
}

#[tokio::test]
#[ignore = "requires a Linux Docker engine, Node.js and a pinned repository image"]
async fn host_acp_uses_only_the_docker_repository_mcp() {
    let node = configured("HOWL_HOST_NODE");
    let temp = tempfile::tempdir().unwrap();
    let adapter = temp.path().join("acp-fixture");
    fs::write(
        &adapter,
        format!(
            "#!{}\n{}",
            node.display(),
            include_str!("fixtures/host-agent/agent.cjs")
        ),
    )
    .unwrap();
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
    let host = HostClaude::new(node, adapter, "/bin/false".into(), temp.path().into()).unwrap();
    check_repository_prompt(|image| Harness::host_claude(image, host)).await;
}

#[tokio::test]
#[ignore = "requires a native Claude login and the installed official CLI and pinned ACP adapter"]
async fn live_host_claude_uses_docker_repository_tools() {
    let host = HostClaude::new(
        configured("HOWL_HOST_NODE"),
        configured("HOWL_HOST_CLAUDE_ADAPTER"),
        configured("HOWL_HOST_CLAUDE"),
        configured("HOME"),
    )
    .unwrap();
    check_repository_prompt(|image| Harness::host_claude(image, host)).await;
}

#[tokio::test]
#[ignore = "requires an installed, natively signed-in Grok CLI and a Linux Docker observer"]
async fn live_host_grok_uses_docker_repository_tools() {
    let host = HostGrok::new(
        configured("HOWL_HOST_NODE"),
        configured("HOWL_HOST_GROK"),
        configured("HOWL_HOST_GROK_AUTH_PATH"),
    )
    .unwrap();
    check_repository_prompt(|image| Harness::host_grok(image, host)).await;
}

#[tokio::test]
#[ignore = "requires an installed, natively signed-in Codex CLI and a Linux Docker observer"]
async fn live_host_codex_uses_docker_repository_tools() {
    let mut host = HostCodex::new(
        configured("HOWL_HOST_NODE"),
        configured("HOWL_HOST_CODEX"),
        configured("HOME"),
    )
    .unwrap();
    if let Some(path) = std::env::var_os("CODEX_HOME") {
        host = host.with_state_home(path.into()).unwrap();
    }
    check_repository_prompt(|image| Harness::host_codex(image, host)).await;
}

async fn check_repository_prompt(harness: impl FnOnce(String) -> Harness) {
    let socket = configured("HOWL_OBSERVER_DOCKER_SOCKET");
    let image = std::env::var("HOWL_HOST_REPOSITORY_IMAGE").unwrap();
    let provider = ObserverProvider::connect(&socket).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repository");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("selected.txt"), "HOWL_HOST_REPOSITORY_OK\n").unwrap();
    fs::write(repo.join("unselected.txt"), "OUTSIDE_APPROVED_SNAPSHOT\n").unwrap();
    for args in [
        &["init", "-q", "--template="][..],
        &["add", "--all"],
        &["commit", "-qm", "fixture"],
    ] {
        assert!(git(&repo).args(args).status().unwrap().success());
    }
    let snapshot = Snapshot::from_commit(&repo, "HEAD", &["selected.txt".into()]).unwrap();
    let session = ManagedSession::start(
        &temp.path().join("journal"),
        &provider,
        snapshot,
        harness(image),
    )
    .await
    .unwrap();
    let mut events = session.subscribe();
    let stop = session
        .prompt(
            "Use the howl_repository read_file tool to read selected.txt from the Docker snapshot. Reply with its exact text.".into(),
            Duration::from_secs(80),
        )
        .await
        .unwrap();
    assert!(matches!(stop, StopReason::EndTurn));
    let mut output = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(event) = events.recv().await {
            if let Event::Update(update) = event
                && let SessionUpdate::AgentMessageChunk(chunk) = update.update
                && let ContentBlock::Text(text) = chunk.content
            {
                output.push_str(&text.text);
                if output.contains("HOWL_HOST_REPOSITORY_OK") {
                    return;
                }
            }
        }
    })
    .await;
    assert!(
        output.contains("HOWL_HOST_REPOSITORY_OK"),
        "missing fixture marker in reply: {}",
        output.chars().take(240).collect::<String>()
    );
    session.close().await.unwrap();
}

fn git(repo: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
        ]);
    command
}
