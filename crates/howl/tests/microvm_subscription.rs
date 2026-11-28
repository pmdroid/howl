use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn run(state: &Path, repository: &Path, prompt: &str) -> Output {
    let mut worker = Command::new(env!("CARGO_BIN_EXE_howl"))
        .arg("worker")
        .arg("run")
        .arg(state)
        .arg(repository)
        .arg("HEAD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    worker
        .stdin
        .take()
        .unwrap()
        .write_all(prompt.as_bytes())
        .unwrap();
    worker.wait_with_output().unwrap()
}

#[test]
#[ignore = "requires HOWL_TEST_MICROVM_STATE with a ChatGPT plan, a Codex guest and hardware virtualization"]
fn subscription_worker_tests_files_and_reports_an_unsupported_native_handoff() {
    let active = PathBuf::from(std::env::var_os("HOWL_TEST_MICROVM_STATE").unwrap());
    let profile = fs::read(active.join("microvm.json")).unwrap();
    let config: serde_json::Value = serde_json::from_slice(&profile).unwrap();
    assert_eq!(config["provider"]["provider"], "chatgpt_plan");
    let model = config["provider"]["model"].as_str().unwrap();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let repo = root.path().join("repo");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let local = state.join("microvm.json");
    fs::write(&local, profile).unwrap();
    fs::set_permissions(local, fs::Permissions::from_mode(0o600)).unwrap();
    fs::create_dir(&repo).unwrap();
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let marker = hex::encode(random);
    fs::write(repo.join("input.txt"), format!("{marker}\n")).unwrap();
    for args in [
        &["init", "-q", "--template="][..],
        &["add", "input.txt"],
        &["commit", "-qm", "Synthetic worker fixture"],
    ] {
        assert!(
            Command::new("git")
                .current_dir(&repo)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args([
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "core.hooksPath=/dev/null"
                ])
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let ordinary = run(
        &state,
        &repo,
        "Use the shell to verify uname -s is Linux, id -u is nonzero, and /sys/class/net contains only lo. Copy input.txt to result.txt and run cmp input.txt result.txt. Make no other changes.",
    );
    assert!(
        ordinary.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    let patches = state.join("worker-patches");
    let mut entries = fs::read_dir(&patches).unwrap();
    let patch = fs::read_to_string(entries.next().unwrap().unwrap().path()).unwrap();
    assert!(
        patch.contains("+++ b/result.txt")
            && patch.lines().any(|line| line == format!("+{marker}"))
    );
    assert!(entries.next().is_none());
    let delegation = run(
        &state,
        &repo,
        &format!(
            "Use the native spawn_agent tool with model {model} to start one child now. Ask the child to copy input.txt to child-result.txt. Wait for its reply. Only the child may write this file."
        ),
    );
    assert!(!delegation.status.success());
    assert!(
        String::from_utf8_lossy(&delegation.stderr)
            .contains("ChatGPT subscription sharing rejected the native sub-agent handoff.")
    );
    assert_eq!(fs::read_dir(patches).unwrap().count(), 1);
    assert!(!repo.join("result.txt").exists());
    assert!(!repo.join("child-result.txt").exists());
}
