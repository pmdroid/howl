use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    thread,
    time::Duration,
};

use howl::observer::{Error, ObserverProvider, Snapshot, WORKSPACE};

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.name=Howl fixture",
            "-c",
            "user.email=howl@example.test",
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
    String::from_utf8(output.stdout).unwrap()
}

fn repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path();
    git(repo, &["init", "--quiet", "--template="]);
    fs::write(repo.join("tracked.txt"), "selected snapshot\n").unwrap();
    fs::create_dir(repo.join("module")).unwrap();
    fs::write(repo.join("module/helper.rs"), "fn fixture() {}\n").unwrap();
    fs::write(repo.join("unselected.txt"), "excluded file").unwrap();
    fs::write(repo.join("private.bin"), [0, 1, 2, 3]).unwrap();
    fs::write(repo.join(".env"), "unrelated fixture").unwrap();
    fs::write(repo.join("credentials.json"), "{}").unwrap();
    fs::write(
        repo.join("misnamed.txt"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic",
    )
    .unwrap();
    fs::write(
        repo.join("settings.toml"),
        "AWS_SECRET_ACCESS_KEY=syntheticobserverkeyexample",
    )
    .unwrap();
    symlink("tracked.txt", repo.join("alias.txt")).unwrap();
    git(repo, &["add", "--force", "--all"]);
    git(repo, &["commit", "--quiet", "-m", "synthetic fixture"]);
    fs::write(repo.join("tracked.txt"), "dirty working copy\n").unwrap();
    fs::write(repo.join("untracked.txt"), "not in Git").unwrap();
    root
}

#[test]
fn pins_explicit_regular_files_to_a_commit() {
    let repo = repository();
    let commit = git(repo.path(), &["rev-parse", "HEAD"]);
    let paths = [
        PathBuf::from("tracked.txt"),
        PathBuf::from("module/helper.rs"),
    ];
    let old = Snapshot::from_commit(repo.path(), "HEAD", &paths).unwrap();
    assert_eq!(old.commit(), commit.trim());
    git(repo.path(), &["add", "tracked.txt"]);
    git(
        repo.path(),
        &["commit", "--quiet", "-m", "change working copy"],
    );
    let new = Snapshot::from_commit(repo.path(), "HEAD", &paths).unwrap();
    assert_ne!(new.commit(), old.commit());
    assert_eq!(
        Snapshot::from_commit(repo.path(), old.commit(), &paths)
            .unwrap()
            .commit(),
        old.commit()
    );
}

#[test]
fn refuses_untracked_files_unsafe_paths_links_and_sensitive_content() {
    let repo = repository();
    for file in [
        "untracked.txt",
        "module",
        "tracked.txt/",
        "alias.txt",
        "../tracked.txt",
        "/tracked.txt",
        ".env",
        "credentials.json",
        "misnamed.txt",
        "private.bin",
        "settings.toml",
        "module//helper.rs",
    ] {
        assert!(
            Snapshot::from_commit(repo.path(), "HEAD", &[PathBuf::from(file)]).is_err(),
            "accepted {file}",
        );
    }
    assert!(Snapshot::from_commit(repo.path(), "HEAD", &[]).is_err());
    assert!(
        Snapshot::from_commit(
            &repo.path().join("module"),
            "HEAD",
            &[PathBuf::from("tracked.txt")]
        )
        .is_err()
    );
    assert!(Snapshot::from_commit(repo.path(), "--help", &[PathBuf::from("tracked.txt")]).is_err());
}

#[test]
fn requires_a_local_engine_socket() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("not-a-socket");
    fs::write(&path, "fixture").unwrap();
    assert!(matches!(
        ObserverProvider::connect(&path),
        Err(Error::UnsupportedEngine)
    ));
}

#[test]
#[ignore = "requires local Linux Docker socket and pinned OpenCode fixture image"]
fn real_harness_is_read_only_and_replies_over_stdio() {
    let socket = std::env::var_os("HOWL_OBSERVER_DOCKER_SOCKET").unwrap();
    let image = std::env::var("HOWL_OBSERVER_IMAGE").unwrap();
    let provider = ObserverProvider::connect(Path::new(&socket)).unwrap();
    let repo = repository();
    let snapshot =
        Snapshot::from_commit(repo.path(), "HEAD", &[PathBuf::from("tracked.txt")]).unwrap();

    let sentinel_path = serde_json::to_string(&repo.path().join("unselected.txt")).unwrap();
    let preload = format!("data:text/javascript,process.env.HOWL_PROBE_HOST_PATH={sentinel_path}");
    let mut proof = provider
        .launch(
            &snapshot,
            &image,
            Path::new("/usr/local/bin/node"),
            &["--import", &preload, "/observer/probe.mjs"],
        )
        .unwrap();
    let mut stdout = proof.take_stdout().unwrap();
    let mut stderr = proof.take_stderr().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut output = String::new();
        stdout.read_to_string(&mut output).unwrap();
        send.send(output).ok();
    });
    let errors = thread::spawn(move || {
        let mut errors = String::new();
        stderr.read_to_string(&mut errors).unwrap();
        errors
    });
    proof.take_stdin().unwrap();
    let output = receive.recv_timeout(Duration::from_secs(45)).unwrap();
    let status = proof.wait().unwrap();
    assert!(status.success(), "{}", errors.join().unwrap());
    assert!(output.contains("HOWL_OBSERVER_BOUNDARY_OK"), "{output}");
    drop(proof);
    assert_eq!(
        fs::read_to_string(repo.path().join("tracked.txt")).unwrap(),
        "dirty working copy\n"
    );

    let mut harness = provider
        .launch(
            &snapshot,
            &image,
            Path::new("/usr/local/bin/opencode"),
            &["acp", "--pure", "--cwd", WORKSPACE],
        )
        .unwrap();
    let mut request = harness.take_stdin().unwrap();
    let mut response = BufReader::new(harness.take_stdout().unwrap());
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        response.read_line(&mut line).unwrap();
        send.send(line).ok();
    });
    writeln!(
        request,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":1,\"clientCapabilities\":{{}}}}}}"
    ).unwrap();
    request.flush().unwrap();
    let response: serde_json::Value =
        serde_json::from_str(&receive.recv_timeout(Duration::from_secs(15)).unwrap()).unwrap();
    assert_eq!(response["result"]["protocolVersion"], 1);
    assert_eq!(response["result"]["agentInfo"]["version"], "1.18.33");

    let mut broker = harness.start_broker(
        Path::new("/usr/local/bin/node"),
        &[
            "-e",
            r#"const fs = require('node:fs');
               const assert = require('node:assert/strict');
               assert.equal(fs.readFileSync('/workspace/tracked.txt', 'utf8'), 'selected snapshot\n');
               assert.throws(() => fs.readFileSync('/workspace/unselected.txt'), {code: 'ENOENT'});
               process.stdin.pipe(process.stdout);"#,
        ],
    ).unwrap();
    let mut broker_request = broker.stdin.take().unwrap();
    broker_request.write_all(b"scoped broker fixture").unwrap();
    drop(broker_request);
    let output = broker.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"scoped broker fixture");
}
