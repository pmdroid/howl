use std::{fs, path::Path, process::Command, time::Duration};

use agent_client_protocol::v1::schema::{ContentBlock, SessionUpdate, StopReason};
use howl::{
    managed_acp::{Event, Harness, ManagedSession},
    observer::{NativeClaudeProfile, ObserverProvider, Snapshot},
};
use tokio::time::timeout;

#[test]
fn claude_profile_names_cannot_select_arbitrary_volumes() {
    assert!(NativeClaudeProfile::new("subscription-smoke").is_ok());
    for name in [
        "",
        "../user-credentials",
        "other:volume",
        "org/team",
        "A",
        "a b",
    ] {
        assert!(NativeClaudeProfile::new(name).is_err());
    }
}

#[tokio::test]
#[ignore = "requires the pinned Claude image and a dedicated Docker profile signed in to Claude Code"]
async fn live_native_claude_reads_only_the_selected_snapshot() {
    let socket = std::env::var_os("HOWL_OBSERVER_DOCKER_SOCKET").expect("set the Docker socket");
    let image = std::env::var("HOWL_CLAUDE_IMAGE").expect("set the pinned Claude image ID");
    let profile = std::env::var("HOWL_CLAUDE_PROFILE").expect("set the dedicated Claude profile");
    let provider = ObserverProvider::connect(Path::new(&socket)).unwrap();
    let profile = NativeClaudeProfile::new(&profile).unwrap();
    let repo = tempfile::tempdir().unwrap();
    fs::write(repo.path().join("selected.txt"), "HOWL_CLAUDE_OK\n").unwrap();
    fs::write(repo.path().join("other.txt"), "OUTSIDE_SELECTED_SNAPSHOT\n").unwrap();
    for args in [
        &["init", "-q", "--template="][..],
        &["add", "--all"],
        &["commit", "-qm", "fixture"],
    ] {
        assert!(
            Command::new("git")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .arg("-C")
                .arg(repo.path())
                .args([
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.test"
                ])
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let snapshot = Snapshot::from_commit(repo.path(), "HEAD", &["selected.txt".into()]).unwrap();
    let root = tempfile::tempdir().unwrap();
    let session = ManagedSession::start(
        &root.path().join("journal"),
        &provider,
        snapshot,
        Harness::native_claude(image, profile),
    )
    .await
    .unwrap();
    let mut events = session.subscribe();
    let stop = session
        .prompt(
            "Read /workspace/selected.txt and reply with its exact text. Do not use other files."
                .into(),
            Duration::from_secs(80),
        )
        .await
        .unwrap();
    assert!(matches!(stop, StopReason::EndTurn));
    let saw_reply = timeout(Duration::from_secs(5), async {
        let mut content = String::new();
        while let Ok(event) = events.recv().await {
            if let Event::Update(update) = event
                && let SessionUpdate::AgentMessageChunk(chunk) = update.update
                && let ContentBlock::Text(text) = chunk.content
            {
                content.push_str(&text.text);
                if content.contains("HOWL_CLAUDE_OK") {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(
        saw_reply,
        "Claude did not return the selected file's marker"
    );
    session.close().await.unwrap();
}
