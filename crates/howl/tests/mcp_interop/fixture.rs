use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{self, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use howl::{
    identity::LocalIdentity,
    interaction::LocalInteraction,
    managed_acp::Harness,
    node,
    observer::{ObserverProvider, Snapshot},
    workflow::{self, RunTurn},
};
use howl_envelope::{AgentRole, Id};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::JoinHandle,
};

pub(super) async fn verify(
    reader: &Path,
    writer: &Path,
    reader_route: &str,
    writer_route: &str,
    channel: &str,
    denied_channel: &str,
    image: &str,
) {
    let channel_id: Id = hex::decode(channel).unwrap().try_into().unwrap();
    let writer_peer = LocalIdentity::load_or_create(writer).unwrap().certificate();
    let writer_device = *writer_peer.device_id();
    let hint = node::export_hint(reader, reader_route.parse().unwrap()).unwrap();
    node::import_hint(writer, &hint).unwrap();
    let hint = node::export_hint(writer, writer_route.parse().unwrap()).unwrap();
    node::import_hint(reader, &hint).unwrap();
    let architect = AgentRole::Architect.agent_id(&writer_device);
    let reviewer = AgentRole::Reviewer.agent_id(&writer_device);

    let fixture = tempfile::tempdir().unwrap();
    let observations = fixture.path().join("observations");
    std::fs::create_dir(&observations).unwrap();
    let (reader_address, mut reader_gateway) =
        gateway(reader, fixture.path(), channel, "reader").await;
    let (writer_address, writer_gateway) = gateway(writer, fixture.path(), channel, "writer").await;
    let agent = |target, text, expected| {
        json!({
            "peer": hex::encode(writer_device),
            "target": hex::encode(target),
            "text": text,
            "expect": expected
        })
    };
    protected_file(
        &fixture.path().join("fixture.json"),
        &json!({
            "url": format!("http://{reader_address}/mcp"),
            "tokenFile": "reader.token",
            "channel": channel,
            "deniedChannel": denied_channel,
            "observations": "observations",
            "restartGateway": true,
            "writer": {
                "url": format!("http://{writer_address}/mcp"),
                "tokenFile": "writer.token"
            },
            "targets": [
                agent(architect, "MCP_INTEROP_DRAFT", "HOWL_MCP_ARCHITECT"),
                agent(reviewer, "MCP_INTEROP_REVIEW", "HOWL_MCP_REVIEWER"),
            ],
            "cancelTarget": agent(reviewer, "MCP_INTEROP_CANCEL", "HOWL_MCP_REVIEWER")
        })
        .to_string(),
    );

    let repository = tempfile::tempdir().unwrap();
    std::fs::write(repository.path().join("selected.txt"), "approved fixture\n").unwrap();
    for args in [
        &["init", "-q", "--template="][..],
        &["add", "selected.txt"][..],
        &["commit", "-qm", "MCP observer fixture"][..],
    ] {
        let output = process::Command::new("git")
            .current_dir(repository.path())
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=Howl Fixture",
                "-c",
                "user.email=fixture@example.test",
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

    let mut command = tokio::process::Command::new("docker");
    command.args([
        "run",
        "--rm",
        "--interactive",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ]);
    if cfg!(target_os = "macos") {
        command.args(["--env", "HOWL_MCP_DOCKER_HOST=host.docker.internal"]);
    } else {
        command.args(["--network", "host"]);
    }
    command
        .arg("--user")
        .arg(format!(
            "{}:{}",
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw()
        ))
        .arg("--volume")
        .arg(format!("{}:/fixture:ro", fixture.path().display()))
        .args([image, "/fixture/fixture.json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let socket =
        std::env::var_os("HOWL_OBSERVER_DOCKER_SOCKET").expect("set the local Docker socket");
    let provider = ObserverProvider::connect(Path::new(&socket)).unwrap();
    let agent_image = std::env::var("HOWL_MANAGED_FIXTURE_IMAGE")
        .expect("set the pinned Docker image with Node.js");

    let agents = async {
        loop {
            for role in [AgentRole::Architect, AgentRole::Reviewer] {
                if let Some(job) = workflow::claim(writer, channel_id, role).unwrap()
                    && job.text.starts_with("MCP_INTEROP_")
                {
                    workflow::run_turn(
                        RunTurn {
                            state: writer,
                            channel: channel_id,
                            role,
                            execution: job.claim.execution,
                            route: reader_route,
                            context: &[],
                            cause: None,
                        },
                        &provider,
                        Snapshot::from_commit(repository.path(), "HEAD", &["selected.txt".into()])
                            .unwrap(),
                        Harness::new(
                            role.name(),
                            agent_image.clone(),
                            "/usr/local/bin/node",
                            &["-e", include_str!("fixture.cjs"), role.name()],
                        ),
                    )
                    .await
                    .unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let observe_arrivals = async {
        let reader = reader.to_owned();
        let mut after = 0;
        loop {
            let state = reader.clone();
            let arrivals = tokio::task::spawn_blocking(move || {
                LocalInteraction::new(&state).events(channel_id, after, 100)
            })
            .await
            .unwrap()
            .unwrap();
            let observed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string();
            for event in arrivals {
                after = event.cursor;
                if let Some(marker) = event.message.text.strip_prefix("howl-mcp-interop-")
                    && marker.len() == 36
                    && marker
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
                {
                    protected_file(&observations.join(marker), &observed);
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    let sdk = async {
        let mut child = command.spawn().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let stderr = tokio::spawn(async move {
            let mut bytes = String::new();
            stderr.read_to_string(&mut bytes).await.unwrap();
            bytes
        });
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        if let Some(restart) = lines.next_line().await.unwrap() {
            let phase: Value = serde_json::from_str(&restart).unwrap();
            assert_eq!(phase["phase"], "restart_gateway");
            reader_gateway.abort();
            assert!((&mut reader_gateway).await.unwrap_err().is_cancelled());
            let listener = TcpListener::bind(reader_address).await.unwrap();
            reader_gateway = serve(reader, fixture.path().join("reader.json"), listener);
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"reader-ready\n")
                .await
                .unwrap();
        }
        let report = lines.next_line().await.unwrap();
        let status = child.wait().await.unwrap();
        let errors = stderr.await.unwrap();
        assert!(status.success(), "{errors}");
        serde_json::from_str::<Value>(&report.unwrap()).unwrap()
    };
    let evidence = tokio::time::timeout(Duration::from_secs(180), async {
        tokio::select! {
            evidence = sdk => evidence,
            () = agents => unreachable!(),
            () = observe_arrivals => unreachable!(),
        }
    })
    .await
    .expect("Docker MCP verification timed out");
    reader_gateway.abort();
    writer_gateway.abort();
    assert_eq!(evidence["gatewayRestart"], true);
    assert_eq!(evidence["nativeTasksReconnect"], true);
    assert_eq!(evidence["toolsOnlyFinalResult"], true);
    assert_eq!(evidence["gatewayEventToNotificationMs"]["samples"], 20);
    println!("{evidence}");
}

async fn gateway(
    state: &Path,
    fixture: &Path,
    channel: &str,
    id: &str,
) -> (SocketAddr, JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut token = [0; 32];
    getrandom::fill(&mut token).unwrap();
    let token = hex::encode(token);
    protected_file(&fixture.join(format!("{id}.token")), &token);
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let configuration = fixture.join(format!("{id}.json"));
    protected_file(
        &configuration,
        &json!({
            "resource": format!("http://{address}/mcp"),
            "grants": [{
                "id": id,
                "token_sha256": hex::encode(Sha256::digest(token)),
                "expires_at": expires,
                "channels": [channel],
                "permissions": ["read", "send", "wake", "cancel"]
            }]
        })
        .to_string(),
    );
    (address, serve(state, configuration, listener))
}

fn serve(
    state: &Path,
    configuration: PathBuf,
    listener: TcpListener,
) -> JoinHandle<std::io::Result<()>> {
    let state = state.to_owned();
    tokio::spawn(async move { howl::serve_gateway(&state, &configuration, listener).await })
}

fn protected_file(path: &Path, text: &str) {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}
