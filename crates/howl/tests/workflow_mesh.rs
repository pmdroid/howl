use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use howl::{
    delivery::{Id, WakeJob},
    identity::{LocalIdentity, PeerTrust},
    managed_acp::{Harness, HostClaude, HostCodex},
    node,
    observer::{ObserverProvider, Snapshot},
    workflow::{self, AgentRole, RunTurn},
};

const WAIT: Duration = Duration::from_secs(15);
const TTL: u16 = 180;

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

struct ExpectedReply<'a> {
    sender: Id,
    agent: Id,
    message: Id,
    wake: Id,
    markers: &'a [&'a str],
}

fn assert_received(state: &Path, channel: Id, reply: ExpectedReply<'_>) {
    let inbox = stdout(mesh_cli(&["read"], state, &[&hex::encode(channel)]));
    let source = format!(
        "agent {} {} message={} reply-to={} context=",
        hex::encode(reply.sender),
        hex::encode(reply.agent),
        hex::encode(reply.message),
        hex::encode(reply.wake)
    );
    assert!(
        inbox.lines().any(|line| line.starts_with(&source)
            && reply.markers.iter().all(|marker| line.contains(marker))),
        "missing signed peer reply containing {:?}",
        reply.markers
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

fn snapshot(repository: &Path) -> Snapshot {
    Snapshot::from_commit(repository, "HEAD", &["selected.txt".into()]).unwrap()
}

fn fixture_harness(stage: &str) -> Harness {
    let image = std::env::var("HOWL_MANAGED_FIXTURE_IMAGE")
        .expect("set the pinned Docker image with Node.js");
    let agent = if stage == "reviewer" {
        "reviewer"
    } else {
        "architect"
    };
    Harness::new(
        agent,
        image,
        "/usr/local/bin/node",
        &["-e", include_str!("fixtures/acp/workflow-agent.cjs"), agent],
    )
}

#[tokio::test]
#[ignore = "requires a local Linux Docker engine and a pinned image with Node.js"]
async fn signed_two_node_wakes_drive_a_read_only_draft_review_and_final() {
    exercise_workflow(
        TestWorkflow {
            architect_data: "Architect selected data\n",
            reviewer_data: "Reviewer selected data\n",
            draft: ("DRAFT_REQUEST", &["HOWL_ARCHITECT_DRAFT"]),
            review: ("REVIEW_REQUEST", &["HOWL_REVIEWER_FEEDBACK"]),
            final_reply: ("FINAL_REQUEST", &["HOWL_ARCHITECT_FINAL"]),
        },
        fixture_harness,
    )
    .await;
}

fn configured(name: &str) -> PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("set {name}"))
        .into()
}

#[tokio::test]
#[ignore = "requires a local Linux Docker engine and a pinned image with Node.js"]
async fn ordinary_direct_messages_continue_the_same_acp_session() {
    direct_conversation_script(
        None,
        vec![
            ("remember".into(), "turn-1-remember".into()),
            ("recall".into(), "turn-2-recall".into()),
        ],
    )
    .await;
}

#[tokio::test]
#[ignore = "requires a local Linux Docker engine and a pinned image with Node.js"]
async fn configured_context_compacts_at_threshold_and_keeps_the_shared_fact() {
    let fact = format!("archive-{:016x}", getrandom::u64().unwrap());
    let mut script = vec![
        ("private-context-canary".to_owned(), "ack".to_owned()),
        (format!("/thread review fact={fact}"), "ack".to_owned()),
    ];
    for index in 1..10 {
        script.push((format!("/thread review note-{index}"), "ack".into()));
    }
    script.push((
        "/thread review inspect-context".into(),
        "history=10 summary=empty raw=true private=false".into(),
    ));
    for index in 0..4 {
        script.push((
            format!("/thread review filler-{index} {}", " word".repeat(380)),
            "ack".into(),
        ));
    }
    script.push((
        "/thread review inspect-context".into(),
        format!("summary={fact} raw=false private=false"),
    ));
    script.push((
        "inspect-context".into(),
        "summary=empty raw=false private=true".into(),
    ));
    direct_conversation_script(
        Some(serde_json::json!({"window_tokens":2048,"compact_at_percent":70})),
        script,
    )
    .await;
}

async fn direct_conversation_script(
    context: Option<serde_json::Value>,
    script: Vec<(String, String)>,
) {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let alice_cert = LocalIdentity::load_or_create(&alice).unwrap().certificate();
    let bob_cert = LocalIdentity::load_or_create(&bob).unwrap().certificate();
    let alice_device = *alice_cert.device_id();
    let bob_device = *bob_cert.device_id();
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
    let mut alice_node = Node::start(&alice);
    let mut bob_node = Node::start(&bob);
    let (repository, revision) = repository(root.path(), "conversation-repo", "selected\n");
    let config = bob.join("conversations.json");
    let mut profile = serde_json::json!({ "conversations": [{
        "channel": hex::encode(channel), "peer": hex::encode(alice_device),
        "route": alice_node.route, "repository": repository, "revision": revision,
    }]});
    if let Some(context) = context {
        profile["context"] = context;
        profile["conversations"][0]["shared_thread"] = "review".into();
    }
    fs::write(&config, profile.to_string()).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let image = std::env::var("HOWL_MANAGED_FIXTURE_IMAGE").unwrap();
    let agent = howl::ongoing::serve(&bob, observer(), move || {
        Ok(Harness::new(
            "conversation-fixture",
            image.clone(),
            "/usr/local/bin/node",
            &["-e", include_str!("fixtures/acp/ongoing-agent.cjs")],
        ))
    });
    let exchange = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        for (prompt, reply) in script {
            let receipt = node::send(&alice, channel, bob_device, &bob_node.route, &prompt)
                .await
                .unwrap();
            let source = delivered(&alice, channel, &receipt, bob_device).await;
            let channel = hex::encode(channel);
            let reply_to = format!("reply-to={}", hex::encode(source));
            let received = tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    let history = stdout(mesh_cli(&["read"], &alice, &[&channel]));
                    if let Some(line) = history
                        .lines()
                        .find(|line| line.starts_with("agent ") && line.contains(&reply_to))
                    {
                        break line.to_owned();
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("agent did not reply to the signed message");
            assert!(received.contains(&reply), "expected {reply} in {received}");
        }
    };
    tokio::select! {
        completed = agent => panic!("agent finished early: {completed:?}"),
        () = exchange => {},
    }
    alice_node.stop(&alice).await;
    bob_node.stop(&bob).await;
}

#[tokio::test]
#[ignore = "requires a local Linux Docker engine and a pinned image with Node.js"]
async fn shared_thread_answers_overlapping_senders_and_keeps_dms_private() {
    let root = tempfile::tempdir().unwrap();
    let states = ["codex", "claude", "grok"].map(|name| root.path().join(name));
    let certs = states
        .each_ref()
        .map(|path| LocalIdentity::load_or_create(path).unwrap().certificate());
    for (i, state) in states.iter().enumerate() {
        for (j, cert) in certs.iter().enumerate() {
            if i != j {
                PeerTrust::open(state)
                    .unwrap()
                    .pin(cert, &cert.fingerprint())
                    .unwrap();
            }
        }
    }
    let devices = certs.each_ref().map(|cert| *cert.device_id());
    let ids = devices.map(hex::encode);
    let manifest = stdout(mesh_cli(
        &["channel", "create"],
        &states[0],
        &[&ids[1], &ids[2]],
    ));
    let mut lines = manifest.lines();
    let channel = id(lines.next().unwrap().strip_prefix("Channel ").unwrap());
    let token = lines.next().unwrap().strip_prefix("Manifest ").unwrap();
    for state in &states[1..] {
        stdout(mesh_cli(&["channel", "join"], state, &[token]));
    }
    let mut nodes = states.each_ref().map(|state| Node::start(state));
    let (repo, rev) = repository(root.path(), "shared-repo", "fixture");
    let conversations = (1..=2)
        .map(|i| {
            serde_json::json!({
                "channel":hex::encode(channel),"peer":ids[i],"route":nodes[i].route,
                "repository":repo,"revision":rev,"shared_thread":"review"
            })
        })
        .collect::<Vec<_>>();
    let config = states[0].join("conversations.json");
    fs::write(
        &config,
        serde_json::json!({"conversations":conversations}).to_string(),
    )
    .unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let image = std::env::var("HOWL_MANAGED_FIXTURE_IMAGE").unwrap();
    let agent = howl::ongoing::serve(&states[0], observer(), move || {
        Ok(Harness::new(
            "shared-fixture",
            image.clone(),
            "/usr/local/bin/node",
            &["-e", include_str!("fixtures/acp/ongoing-agent.cjs")],
        ))
    });
    let send = |i: usize, body| node::send(&states[i], channel, devices[0], &nodes[0].route, body);
    let answer = |i: usize, receipt: String| {
        let state = states[i].clone();
        async move {
            let needle = format!("reply-to={}", receipt.strip_prefix("queued ").unwrap());
            tokio::time::timeout(WAIT, async {
                loop {
                    let history = stdout(mesh_cli(&["read"], &state, &[&hex::encode(channel)]));
                    if let Some(line) = history.lines().find(|s| s.contains(&needle)) {
                        break line.to_owned();
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("expected a reply to this message")
        }
    };
    let exchange = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let private = send(1, "private-canary").await.unwrap();
        answer(1, private).await;
        let slow = send(1, "/thread review slow-canary").await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let fast = send(1, "/thread review probe-one").await.unwrap();
        let other = send(2, "/thread review probe-two").await.unwrap();
        let (one, two) = tokio::join!(answer(1, fast), answer(2, other));
        for reply in [one, two] {
            assert!(
                reply.contains("pending=true") && reply.contains("private=false"),
                "{reply}"
            );
            assert!(reply.contains(&ids[1]), "{reply}");
        }
        let history = stdout(mesh_cli(&["read"], &states[1], &[&hex::encode(channel)]));
        assert!(!history.contains(&format!(
            "reply-to={}",
            slow.strip_prefix("queued ").unwrap()
        )));
        answer(1, slow).await;
        let final_reply = answer(2, send(2, "/thread review probe-summary").await.unwrap()).await;
        assert!(
            final_reply.contains("completed=3") && final_reply.contains("private=false"),
            "{final_reply}"
        );
        let posted = howl::interaction::LocalInteraction::new(&states[1])
            .post(channel, "@review probe-channel")
            .await
            .unwrap();
        let channel_reply = answer(1, format!("queued {}", posted.message)).await;
        assert!(
            channel_reply.contains("completed=4") && channel_reply.contains("private=false"),
            "{channel_reply}"
        );
        let private_reply = answer(1, send(1, "probe-private").await.unwrap()).await;
        assert!(
            private_reply.contains("completed=0") && private_reply.contains("private=true"),
            "{private_reply}"
        );
    };
    tokio::select! { result=agent=>panic!("agent exited: {result:?}"), ()=exchange=>{} }
    for (node, state) in nodes.iter_mut().zip(states) {
        node.stop(&state).await;
    }
}

fn native_harness(stage: &str) -> Harness {
    let image = std::env::var("HOWL_HOST_REPOSITORY_IMAGE").expect("set the pinned Docker image");
    let node = configured("HOWL_HOST_NODE");
    let home = configured("HOME");
    if stage == "reviewer" {
        let host = HostClaude::new(
            node,
            configured("HOWL_HOST_CLAUDE_ADAPTER"),
            configured("HOWL_HOST_CLAUDE"),
            home,
        )
        .unwrap();
        Harness::host_claude(image, host)
    } else {
        let mut host = HostCodex::new(node, configured("HOWL_HOST_CODEX"), home).unwrap();
        if let Some(path) = std::env::var_os("CODEX_HOME") {
            host = host.with_state_home(path.into()).unwrap();
        }
        Harness::host_codex(image, host)
    }
}

#[tokio::test]
#[ignore = "requires installed, natively signed-in Codex and Claude CLIs and a Linux Docker observer"]
async fn native_codex_and_claude_exchange_signed_workflow_context() {
    let draft_proof = format!("draft-proof-{:016x}", getrandom::u64().unwrap());
    let review_proof = format!("review-proof-{:016x}", getrandom::u64().unwrap());
    let architect_data = format!(
        "Design a read-only command that lists explicitly approved snapshot files. Draft proof: {draft_proof}\n"
    );
    let reviewer_data =
        format!("Require a test covering denied unapproved paths. Review proof: {review_proof}\n");

    exercise_workflow(
        TestWorkflow {
            architect_data: &architect_data,
            reviewer_data: &reviewer_data,
            draft: (
                "Use the Docker repository tool to read selected.txt. Start your reply with HOWL_ARCHITECT_DRAFT, copy the draft proof from the file verbatim, then give a short plan for the requested command.",
                &["HOWL_ARCHITECT_DRAFT", &draft_proof],
            ),
            review: (
                "Review the selected signed architect draft. Use the Docker repository tool to read selected.txt for the review criterion. Start your reply with HOWL_REVIEWER_FEEDBACK. Copy the draft proof from the signed draft and the review proof from the file verbatim, then give one concrete recommendation.",
                &["HOWL_REVIEWER_FEEDBACK", &draft_proof, &review_proof],
            ),
            final_reply: (
                "Use the selected signed reviewer feedback. Start your reply with HOWL_ARCHITECT_FINAL, copy the review proof from the signed feedback verbatim, and update the plan to address the recommendation.",
                &["HOWL_ARCHITECT_FINAL", &review_proof],
            ),
        },
        native_harness,
    )
    .await;
}

struct TestWorkflow<'a> {
    architect_data: &'a str,
    reviewer_data: &'a str,
    draft: (&'a str, &'a [&'a str]),
    review: (&'a str, &'a [&'a str]),
    final_reply: (&'a str, &'a [&'a str]),
}

async fn exercise_workflow(input: TestWorkflow<'_>, harness: impl Fn(&str) -> Harness) {
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
        repository(root.path(), "architect-repo", input.architect_data);
    let (reviewer_repo, reviewer_head) =
        repository(root.path(), "reviewer-repo", input.reviewer_data);
    let receipt = node::send_wake(
        &bob,
        channel,
        alice_device,
        &alice_node.route,
        architect,
        TTL,
        input.draft.0,
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
        snapshot(&architect_repo),
        harness("architect-draft"),
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
            agent: architect,
            message: draft_id,
            wake,
            markers: input.draft.1,
        },
    );

    let receipt = node::send_wake(
        &alice,
        channel,
        bob_device,
        &bob_node.route,
        reviewer,
        TTL,
        input.review.0,
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
        snapshot(&reviewer_repo),
        harness("reviewer"),
    )
    .await;
    assert!(matches!(invalid_context, Err(error) if error.kind() == std::io::ErrorKind::NotFound));

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
        snapshot(&reviewer_repo),
        harness("reviewer"),
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
            agent: reviewer,
            message: review_id,
            wake,
            markers: input.review.1,
        },
    );

    let receipt = node::send_wake(
        &bob,
        channel,
        alice_device,
        &alice_node.route,
        architect,
        TTL,
        input.final_reply.0,
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
        snapshot(&architect_repo),
        harness("architect-final"),
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
            agent: architect,
            message: final_id,
            wake,
            markers: input.final_reply.1,
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
