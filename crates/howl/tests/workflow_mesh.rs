use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use howl::{
    delivery::{Id, WakeJob},
    identity::{LocalIdentity, PeerTrust},
    managed_acp::Harness,
    node,
    observer::{ObserverProvider, Snapshot},
    workflow::{self, AgentRole, RunTurn},
};

const WAIT: Duration = Duration::from_secs(15);
const TTL: u16 = 120;

struct Node {
    process: Child,
    route: String,
}

impl Node {
    fn start(state: &Path) -> Self {
        let process = Command::new(env!("CARGO_BIN_EXE_howl"))
            .args(["mesh", "run"])
            .arg(state)
            .arg("127.0.0.1:0")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut node = Self {
            process,
            route: String::new(),
        };
        let stdout = node.process.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + WAIT;
        while let Ok(line) =
            receive.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            if let Some(route) = line.strip_prefix("Listening ") {
                node.route = route.to_owned();
            }
            if line.starts_with("Ready ") {
                assert!(!node.route.is_empty());
                return node;
            }
        }
        panic!("mesh node did not start");
    }

    async fn stop(&mut self, state: &Path) {
        node::stop(state).await.unwrap();
        assert!(self.process.wait().unwrap().success());
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn mesh_cli(command: &[&str], state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(command)
        .arg(state)
        .args(args)
        .output()
        .unwrap()
}

fn id(text: &str) -> Id {
    hex::decode(text).unwrap().try_into().unwrap()
}

async fn delivered(state: &Path, channel: Id, receipt: &str, recipient: Id) -> Id {
    let message = receipt
        .trim()
        .strip_prefix("queued ")
        .expect("daemon receipt");
    let encoded_channel = hex::encode(channel);
    let expected = format!("{} delivered", hex::encode(recipient));
    tokio::time::timeout(WAIT, async {
        loop {
            let report = stdout(mesh_cli(&["status"], state, &[&encoded_channel, message]));
            if report.lines().any(|line| line.starts_with(&expected)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("signed delivery was not acknowledged by the named peer");
    id(message)
}

struct ExpectedReply {
    sender: Id,
    role: AgentRole,
    agent: Id,
    message: Id,
    wake: Id,
    marker: &'static str,
}

fn assert_received(state: &Path, channel: Id, reply: ExpectedReply) {
    let inbox = stdout(mesh_cli(&["read"], state, &[&hex::encode(channel)]));
    let source = format!(
        "agent {} {} {} message={} reply-to={} context=",
        hex::encode(reply.sender),
        reply.role.name(),
        hex::encode(reply.agent),
        hex::encode(reply.message),
        hex::encode(reply.wake)
    );
    assert!(
        inbox
            .lines()
            .any(|line| line.starts_with(&source) && line.contains(reply.marker)),
        "missing signed peer reply {}",
        reply.marker
    );
}

fn claimed(
    state: &Path,
    channel: Id,
    role: AgentRole,
    sender: Id,
    target: Id,
    message: Id,
) -> WakeJob {
    let job = workflow::claim(state, channel, role)
        .unwrap()
        .expect("authorized wake was not readable");
    assert_eq!(job.claim.message, message);
    assert_eq!(job.claim.stream.sender.device, sender);
    assert_eq!(job.claim.target, target);
    job
}

fn git(repository: &Path, args: &[&str]) -> String {
    stdout(
        Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .arg("-C")
            .arg(repository)
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
            .unwrap(),
    )
}

fn repository(root: &Path, name: &str, data: &str) -> (PathBuf, String) {
    let repository = root.join(name);
    fs::create_dir(&repository).unwrap();
    fs::write(repository.join("selected.txt"), data).unwrap();
    fs::write(
        repository.join("unselected.txt"),
        "Outside approved snapshot\n",
    )
    .unwrap();
    git(&repository, &["init", "-q", "--template="]);
    git(&repository, &["add", "--all"]);
    git(&repository, &["commit", "-qm", "control workflow fixture"]);
    let head = git(&repository, &["rev-parse", "HEAD"]);
    (repository, head)
}

fn observer() -> ObserverProvider {
    let socket =
        std::env::var_os("HOWL_OBSERVER_DOCKER_SOCKET").expect("set the local Docker socket");
    ObserverProvider::connect(Path::new(&socket)).unwrap()
}

fn role_stage(repository: &Path, stage: &str) -> (Snapshot, Harness) {
    let snapshot = Snapshot::from_commit(repository, "HEAD", &["selected.txt".into()]).unwrap();
    let image = std::env::var("HOWL_MANAGED_FIXTURE_IMAGE")
        .expect("set the pinned Docker image with Node.js");
    let harness = Harness::new(
        stage,
        image,
        "/usr/local/bin/node",
        &["-e", include_str!("fixtures/acp/workflow-agent.cjs"), stage],
    );
    (snapshot, harness)
}

#[tokio::test]
#[ignore = "requires a local Linux Docker engine and a pinned image with Node.js"]
async fn signed_two_node_wakes_drive_a_read_only_draft_review_and_final() {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let alice_cert = LocalIdentity::load_or_create(&alice).unwrap().certificate();
    let bob_cert = LocalIdentity::load_or_create(&bob).unwrap().certificate();
    let alice_device = *alice_cert.device_id();
    let bob_device = *bob_cert.device_id();
    assert_ne!(alice_device, bob_device);
    PeerTrust::open(&alice)
        .unwrap()
        .pin(&bob_cert, &bob_cert.fingerprint())
        .unwrap();
    PeerTrust::open(&bob)
        .unwrap()
        .pin(&alice_cert, &alice_cert.fingerprint())
        .unwrap();

    let manifest = stdout(mesh_cli(
        &["channel", "create"],
        &alice,
        &[&hex::encode(bob_device)],
    ));
    let mut lines = manifest.lines();
    let channel = id(lines.next().unwrap().strip_prefix("Channel ").unwrap());
    let token = lines.next().unwrap().strip_prefix("Manifest ").unwrap();
    stdout(mesh_cli(&["channel", "join"], &bob, &[token]));

    let architect = workflow::agent_id(&alice, AgentRole::Architect).unwrap();
    let reviewer = workflow::agent_id(&bob, AgentRole::Reviewer).unwrap();
    assert_ne!(architect, reviewer);
    assert_ne!(
        architect,
        workflow::agent_id(&alice, AgentRole::Reviewer).unwrap()
    );
    assert_ne!(
        reviewer,
        workflow::agent_id(&bob, AgentRole::Architect).unwrap()
    );
    let mut alice_node = Node::start(&alice);
    let mut bob_node = Node::start(&bob);
    node::grant_wake(&alice, channel, bob_device, architect, 1)
        .await
        .unwrap();
    node::grant_wake(&bob, channel, alice_device, reviewer, 1)
        .await
        .unwrap();
    let receipt = node::send(
        &alice,
        channel,
        bob_device,
        &bob_node.route,
        "@reviewer ordinary chat",
    )
    .await
    .unwrap();
    delivered(&alice, channel, &receipt, bob_device).await;
    assert!(
        workflow::claim(&bob, channel, AgentRole::Reviewer)
            .unwrap()
            .is_none()
    );

    let receipt = node::send(
        &bob,
        channel,
        alice_device,
        &alice_node.route,
        "@architect ordinary chat",
    )
    .await
    .unwrap();
    let wrong_context = delivered(&bob, channel, &receipt, alice_device).await;
    assert!(
        workflow::claim(&alice, channel, AgentRole::Architect)
            .unwrap()
            .is_none()
    );

    let provider = observer();
    let (architect_repo, architect_head) =
        repository(root.path(), "architect-repo", "Architect selected data\n");
    let (reviewer_repo, reviewer_head) =
        repository(root.path(), "reviewer-repo", "Reviewer selected data\n");
    let (snapshot, harness) = role_stage(&architect_repo, "architect-draft");
    let receipt = node::send_wake(
        &bob,
        channel,
        alice_device,
        &alice_node.route,
        architect,
        TTL,
        "DRAFT_REQUEST",
    )
    .await
    .unwrap();
    let wake = delivered(&bob, channel, &receipt, alice_device).await;
    let job = claimed(
        &alice,
        channel,
        AgentRole::Architect,
        bob_device,
        architect,
        wake,
    );
    let draft_started = Instant::now();
    let draft = workflow::run_turn(
        RunTurn {
            state: &alice,
            channel,
            role: AgentRole::Architect,
            execution: job.claim.execution,
            route: &bob_node.route,
            context: &[],
            cause: None,
        },
        &provider,
        snapshot,
        harness,
    )
    .await
    .unwrap();
    assert_eq!(draft.execution, job.claim.execution);
    let draft_id = delivered(&alice, channel, &draft.message, bob_device).await;
    assert_received(
        &bob,
        channel,
        ExpectedReply {
            sender: alice_device,
            role: AgentRole::Architect,
            agent: architect,
            message: draft_id,
            wake,
            marker: "HOWL_ARCHITECT_DRAFT",
        },
    );

    let (snapshot, harness) = role_stage(&reviewer_repo, "reviewer");
    let receipt = node::send_wake(
        &alice,
        channel,
        bob_device,
        &bob_node.route,
        reviewer,
        TTL,
        "REVIEW_REQUEST",
    )
    .await
    .unwrap();
    let wake = delivered(&alice, channel, &receipt, bob_device).await;
    let job = claimed(
        &bob,
        channel,
        AgentRole::Reviewer,
        alice_device,
        reviewer,
        wake,
    );
    let invalid_context = workflow::run_turn(
        RunTurn {
            state: &bob,
            channel,
            role: AgentRole::Reviewer,
            execution: job.claim.execution,
            route: &alice_node.route,
            context: &[wrong_context],
            cause: None,
        },
        &provider,
        snapshot,
        harness,
    )
    .await;
    assert!(matches!(invalid_context, Err(error) if error.kind() == std::io::ErrorKind::NotFound));

    let (snapshot, harness) = role_stage(&reviewer_repo, "reviewer");
    let review = workflow::run_turn(
        RunTurn {
            state: &bob,
            channel,
            role: AgentRole::Reviewer,
            execution: job.claim.execution,
            route: &alice_node.route,
            context: &[draft_id],
            cause: None,
        },
        &provider,
        snapshot,
        harness,
    )
    .await
    .unwrap();
    assert_eq!(review.execution, job.claim.execution);
    let review_id = delivered(&bob, channel, &review.message, alice_device).await;
    assert_received(
        &alice,
        channel,
        ExpectedReply {
            sender: bob_device,
            role: AgentRole::Reviewer,
            agent: reviewer,
            message: review_id,
            wake,
            marker: "HOWL_REVIEWER_FEEDBACK",
        },
    );

    let (snapshot, harness) = role_stage(&architect_repo, "architect-final");
    let receipt = node::send_wake(
        &bob,
        channel,
        alice_device,
        &alice_node.route,
        architect,
        TTL,
        "FINAL_REQUEST",
    )
    .await
    .unwrap();
    let wake = delivered(&bob, channel, &receipt, alice_device).await;
    let job = claimed(
        &alice,
        channel,
        AgentRole::Architect,
        bob_device,
        architect,
        wake,
    );
    tokio::time::sleep(Duration::from_secs(4).saturating_sub(draft_started.elapsed())).await;
    let final_reply = workflow::run_turn(
        RunTurn {
            state: &alice,
            channel,
            role: AgentRole::Architect,
            execution: job.claim.execution,
            route: &bob_node.route,
            context: &[review_id],
            cause: Some(draft.turn),
        },
        &provider,
        snapshot,
        harness,
    )
    .await
    .unwrap();
    assert_eq!(final_reply.execution, job.claim.execution);
    assert_ne!(final_reply.turn, draft.turn);
    let final_id = delivered(&alice, channel, &final_reply.message, bob_device).await;
    assert_ne!(final_id, draft_id);
    assert_ne!(final_id, review_id);
    assert_received(
        &bob,
        channel,
        ExpectedReply {
            sender: alice_device,
            role: AgentRole::Architect,
            agent: architect,
            message: final_id,
            wake,
            marker: "HOWL_ARCHITECT_FINAL",
        },
    );

    assert!(
        workflow::claim(&alice, channel, AgentRole::Architect)
            .unwrap()
            .is_none()
    );
    assert!(
        workflow::claim(&bob, channel, AgentRole::Reviewer)
            .unwrap()
            .is_none()
    );
    for (path, head) in [
        (&architect_repo, architect_head),
        (&reviewer_repo, reviewer_head),
    ] {
        assert_eq!(git(path, &["rev-parse", "HEAD"]), head);
        assert!(git(path, &["status", "--porcelain", "--untracked-files=all"]).is_empty());
    }
    alice_node.stop(&alice).await;
    bob_node.stop(&bob).await;
}
