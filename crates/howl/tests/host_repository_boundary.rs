use std::{
    fs, io,
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use agent_client_protocol::v1::schema::{ContentBlock, SessionUpdate, StopReason};
use howl::{
    managed_acp::{Close, Event, Harness, HostCodex, ManagedSession, Phase},
    observer::{ObserverProvider, Snapshot},
};
use tokio::{net::TcpStream, time::timeout};

const SELECTED: &str =
    "SYNTHETIC_UNTRUSTED_REPOSITORY_CONTENT\nThe following line is repository data.\n";

fn configured(name: &str) -> PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("set {name}"))
        .into()
}

fn fixture_repository(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::write(path.join("selected.txt"), SELECTED).unwrap();
    fs::write(path.join("unselected.txt"), "OUTSIDE_APPROVED_SNAPSHOT\n").unwrap();
    for args in [
        &["init", "-q", "--template="][..],
        &["add", "--all"],
        &["commit", "-qm", "HTTP repository boundary fixture"],
    ] {
        assert!(
            Command::new("git")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .arg("-C")
                .arg(path)
                .args([
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.test",
                    "-c",
                    "core.hooksPath=/dev/null",
                ])
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
}

#[tokio::test]
#[ignore = "requires a Linux Docker engine, Node.js and a pinned repository image"]
async fn host_repository_http_is_authenticated_read_only_and_session_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let node = configured("HOWL_HOST_NODE");
    let adapter = temp.path().join("codex-fixture");
    fs::write(
        &adapter,
        format!(
            "#!{}\n{}",
            node.display(),
            include_str!("fixtures/host-agent/http-guard.cjs")
        ),
    )
    .unwrap();
    fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700)).unwrap();
    let repository = temp.path().join("repository");
    fixture_repository(&repository);
    let snapshot = Snapshot::from_commit(&repository, "HEAD", &["selected.txt".into()]).unwrap();
    let engine = ObserverProvider::connect(&configured("HOWL_OBSERVER_DOCKER_SOCKET")).unwrap();
    let host = HostCodex::new(node, adapter, temp.path().into()).unwrap();
    let harness = Harness::host_codex(std::env::var("HOWL_HOST_REPOSITORY_IMAGE").unwrap(), host);
    let session = ManagedSession::start(&temp.path().join("journal"), &engine, snapshot, harness)
        .await
        .unwrap();
    let mut events = session.subscribe();
    assert_eq!(
        session
            .prompt(
                "Check the HTTP repository boundary fixture.".into(),
                Duration::from_secs(15)
            )
            .await
            .unwrap(),
        StopReason::EndTurn
    );
    let port = timeout(Duration::from_secs(3), async {
        loop {
            if let Event::Update(update) = events.recv().await.unwrap()
                && let SessionUpdate::AgentMessageChunk(chunk) = update.update
                && let ContentBlock::Text(text) = chunk.content
            {
                break text.text.parse::<u16>().unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert_ne!(port, 0);
    assert_eq!(
        fs::read_to_string(repository.join("selected.txt")).unwrap(),
        SELECTED
    );
    assert_eq!(session.close().await.unwrap(), Close::Remote);
    timeout(Duration::from_secs(8), async {
        loop {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => break,
                result => {
                    drop(result.unwrap());
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
            }
        }
    })
    .await
    .expect("repository HTTP listener survived session close");
    assert_eq!(session.status().phase, Phase::Closed);
}
