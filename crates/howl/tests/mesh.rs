use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use howl::{
    identity::{LocalIdentity, PeerTrust},
    node,
};

#[path = "mcp_interop/fixture.rs"]
mod interop;

struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(command: &[&str], state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(command)
        .arg(state)
        .args(args)
        .output()
        .unwrap()
}

fn successful(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn start(state: &Path) -> (Node, String) {
    start_with(state, &[])
}

fn start_with(state: &Path, flags: &[&str]) -> (Node, String) {
    let mut child = Node(
        Command::new(env!("CARGO_BIN_EXE_howl"))
            .args(["mesh", "run"])
            .args(flags)
            .arg(state)
            .arg("127.0.0.1:0")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let end = Instant::now() + Duration::from_secs(15);
    let mut address = None;
    while let Ok(line) = receive.recv_timeout(end.saturating_duration_since(Instant::now())) {
        if let Some(value) = line.strip_prefix("Listening ") {
            address = Some(value.to_owned());
        }
        if line.starts_with("Ready ") {
            return (child, address.expect("announce loopback address"));
        }
    }
    panic!("node did not start");
}

fn pair(alice: &Path, bob: &Path) -> (String, String, [u8; 32]) {
    let alice_cert = LocalIdentity::load_or_create(alice).unwrap().certificate();
    let bob_cert = LocalIdentity::load_or_create(bob).unwrap().certificate();
    PeerTrust::open(alice)
        .unwrap()
        .pin(&bob_cert, &bob_cert.fingerprint())
        .unwrap();
    PeerTrust::open(bob)
        .unwrap()
        .pin(&alice_cert, &alice_cert.fingerprint())
        .unwrap();
    let bob_device = hex::encode(bob_cert.device_id());
    let alice_device = *alice_cert.device_id();

    let manifest = successful(cli(&["channel", "create"], alice, &[&bob_device]));
    let mut lines = manifest.lines();
    let channel = lines.next().unwrap().strip_prefix("Channel ").unwrap();
    let token = lines.next().unwrap().strip_prefix("Manifest ").unwrap();
    successful(cli(&["channel", "join"], bob, &[token]));

    (channel.to_owned(), bob_device, alice_device)
}

#[tokio::test]
async fn trusted_peers_exchange_durable_chat_through_the_cli() {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let (channel, bob_device, alice_device) = pair(&alice, &bob);
    let channel = channel.as_str();
    let bob_device = bob_device.as_str();
    let (mut alice_node, _) = start(&alice);
    let (mut bob_node, bob_address) = start(&bob);
    let mut sender = Command::new(env!("CARGO_BIN_EXE_howl"))
        .arg("send")
        .arg(&alice)
        .args([channel, bob_device, &bob_address])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    sender
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello from Alice")
        .unwrap();
    let sent = successful(sender.wait_with_output().unwrap());
    let message_id = sent.trim().strip_prefix("queued ").unwrap();
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let report = successful(cli(&["status"], &alice, &[channel, message_id]));
        if report.contains("delivered") {
            break;
        }
        assert!(
            Instant::now() < until,
            "delivery did not complete: {report}"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let inbox = successful(cli(&["read"], &bob, &[channel]));
    assert_eq!(inbox.lines().count(), 1);
    assert!(inbox.contains("hello from Alice"));

    let channel_id = hex::decode(channel).unwrap().try_into().unwrap();
    let bob_id: [u8; 32] = hex::decode(bob_device).unwrap().try_into().unwrap();
    let reviewer = howl_envelope::AgentRole::Reviewer.agent_id(&bob_id);
    let architect = howl_envelope::AgentRole::Architect.agent_id(&bob_id);
    node::grant_wake(&bob, channel_id, alice_device, reviewer, 1)
        .await
        .unwrap();
    let blocked = node::send_wake(
        &alice,
        channel_id,
        bob_id,
        &bob_address,
        architect,
        30,
        "wrong role",
    )
    .await
    .unwrap();
    let allowed = node::send_wake(
        &alice,
        channel_id,
        bob_id,
        &bob_address,
        reviewer,
        30,
        "review the plan",
    )
    .await
    .unwrap();
    let blocked = blocked.strip_prefix("queued ").unwrap();
    let allowed = allowed.strip_prefix("queued ").unwrap();
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let report = successful(cli(&["status"], &alice, &[channel, allowed]));
        if report.contains("delivered") {
            break;
        }
        assert!(
            Instant::now() < until,
            "authorized wake was not delivered: {report}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let report = successful(cli(&["status"], &alice, &[channel, blocked]));
    assert!(
        report.contains("queued"),
        "ungranted role got an ACK: {report}"
    );
    assert_eq!(successful(cli(&["read"], &bob, &[channel])), inbox);

    successful(cli(&["mesh", "stop"], &alice, &[]));
    successful(cli(&["mesh", "stop"], &bob, &[]));
    assert!(alice_node.0.wait().unwrap().success());
    assert!(bob_node.0.wait().unwrap().success());
    let restarted_read = successful(cli(&["read"], &bob, &[channel]));
    assert_eq!(inbox, restarted_read);
}

#[tokio::test]
async fn signed_address_hint_routes_after_reader_restart() {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let (channel, bob_device, _) = pair(&alice, &bob);
    let (mut alice_node, _) = start(&alice);
    let (mut bob_node, bob_address) = start(&bob);

    let unknown = root.path().join("unknown");
    let wrong_hint = successful(cli(&["mesh", "hint", "export"], &unknown, &[&bob_address]));
    assert!(
        !cli(&["mesh", "hint", "import"], &alice, &[wrong_hint.trim()])
            .status
            .success()
    );
    let first_hint = successful(cli(&["mesh", "hint", "export"], &bob, &["127.0.0.1:1"]));
    successful(cli(
        &["mesh", "hint", "import"],
        &alice,
        &[first_hint.trim()],
    ));
    let valid_hint = successful(cli(&["mesh", "hint", "export"], &bob, &[&bob_address]));
    successful(cli(
        &["mesh", "hint", "import"],
        &alice,
        &[valid_hint.trim()],
    ));
    successful(cli(
        &["mesh", "hint", "import"],
        &alice,
        &[valid_hint.trim()],
    ));
    assert!(
        !cli(&["mesh", "hint", "import"], &alice, &[first_hint.trim()])
            .status
            .success()
    );

    successful(cli(&["mesh", "stop"], &alice, &[]));
    assert!(alice_node.0.wait().unwrap().success());
    let (mut alice_node, _) = start(&alice);
    let channel_id = hex::decode(&channel).unwrap().try_into().unwrap();
    let bob_id = hex::decode(bob_device).unwrap().try_into().unwrap();
    let receipt = node::send(
        &alice,
        channel_id,
        bob_id,
        "-",
        "hello through the cached hint",
    )
    .await
    .unwrap();
    let message = receipt.strip_prefix("queued ").unwrap();
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let report = successful(cli(&["status"], &alice, &[&channel, message]));
        if report.contains("delivered") {
            break;
        }
        assert!(
            Instant::now() < until,
            "cached hint did not deliver: {report}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        successful(cli(&["read"], &bob, &[&channel])).contains("hello through the cached hint")
    );

    successful(cli(&["mesh", "stop"], &alice, &[]));
    successful(cli(&["mesh", "stop"], &bob, &[]));
    assert!(alice_node.0.wait().unwrap().success());
    assert!(bob_node.0.wait().unwrap().success());
}

#[tokio::test]
async fn enrolled_peers_stop_new_delivery_after_signed_revocation() {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    use ed25519_dalek::SigningKey;
    use howl::enrollment::{AuthorityRecord, AuthorityStore, Designation, Enroll, PairingTicket};

    fn record(path: &Path, name: &str, bytes: &[u8]) {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    let temp = tempfile::tempdir().unwrap();
    let alice = temp.path().join("alice");
    let bob = temp.path().join("bob");
    let a = LocalIdentity::load_or_create(&alice).unwrap();
    let b = LocalIdentity::load_or_create(&bob).unwrap();
    let a_peer = a.certificate();
    let b_peer = b.certificate();
    let (legacy_channel, _, _) = pair(&alice, &bob);
    let legacy_id = hex::decode(&legacy_channel).unwrap().try_into().unwrap();
    let (mut legacy_a, _) = start(&alice);
    let (mut legacy_b, legacy_address) = start(&bob);
    let legacy_receipt = node::send(
        &alice,
        legacy_id,
        *b_peer.device_id(),
        &legacy_address,
        "recorded before enrollment",
    )
    .await
    .unwrap();
    let legacy_message = legacy_receipt.strip_prefix("queued ").unwrap();
    wait_for_text(&bob, &legacy_channel, "recorded before enrollment").await;
    successful(cli(&["mesh", "stop"], &alice, &[]));
    successful(cli(&["mesh", "stop"], &bob, &[]));
    assert!(legacy_a.0.wait().unwrap().success());
    assert!(legacy_b.0.wait().unwrap().success());
    let root = SigningKey::from_bytes(&[1; 32]);
    let offline = SigningKey::from_bytes(&[2; 32]);
    let signer = SigningKey::from_bytes(&[3; 32]);
    let genesis = AuthorityRecord::genesis(&root, &offline);
    let account = genesis.digest();
    let authority = AuthorityStore::open(&alice).unwrap();
    authority
        .initialize(std::slice::from_ref(&genesis), account, account)
        .unwrap();
    AuthorityStore::open(&bob)
        .unwrap()
        .initialize(std::slice::from_ref(&genesis), account, account)
        .unwrap();
    let designation =
        Designation::issue(authority.current().unwrap(), 1, &root, &signer, &[]).unwrap();
    for (path, identity, peer, other_path) in
        [(&alice, &a, &a_peer, &bob), (&bob, &b, &b_peer, &alice)]
    {
        let (ticket, offer) =
            PairingTicket::create(&designation, &signer, peer, peer.fingerprint(), 1, 100).unwrap();
        let response = offer
            .respond(&designation, identity, ticket.invitation_secret(), 110)
            .unwrap();
        let certificate = ticket
            .enroll(Enroll {
                state: &alice,
                designation: &designation,
                signer: &signer,
                peer,
                offer: &offer,
                response: &response,
                now: 120,
            })
            .unwrap();
        record(path, "enrollment-designation", designation.as_bytes());
        record(path, "enrollment-certificate", certificate.as_bytes());
        record(
            other_path,
            &format!("enrollment-peer-{}", hex::encode(peer.device_id())),
            certificate.as_bytes(),
        );
        PeerTrust::open(other_path)
            .unwrap()
            .pin(peer, &peer.fingerprint())
            .unwrap();
    }
    record(&alice, "enrollment-signer-key", &signer.to_bytes());
    let alice_member = format!("{}:7", hex::encode(a_peer.device_id()));
    let bob_device = hex::encode(b_peer.device_id());
    let bob_member = format!("{bob_device}:7");
    let roster = successful(cli(
        &["roster", "issue"],
        &alice,
        &["-", "active", &alice_member, &bob_member],
    ));
    let channel = roster
        .lines()
        .next()
        .unwrap()
        .strip_prefix("Channel ")
        .unwrap();
    let proof = roster
        .lines()
        .nth(1)
        .unwrap()
        .strip_prefix("Proof ")
        .unwrap();
    successful(cli(&["roster", "apply"], &bob, &[channel, proof]));
    let second = successful(cli(&["channel", "create"], &alice, &[&bob_device]));
    let second_channel = second
        .lines()
        .next()
        .unwrap()
        .strip_prefix("Channel ")
        .unwrap();
    let second_manifest = second
        .lines()
        .nth(1)
        .unwrap()
        .strip_prefix("Manifest ")
        .unwrap();
    successful(cli(&["channel", "join"], &bob, &[second_manifest]));
    let second_id = hex::decode(second_channel).unwrap().try_into().unwrap();

    let (mut a_node, alice_address) = start(&alice);
    let (mut b_node, bob_address) = start_with(&bob, &["--client-only"]);
    let channel_id: [u8; 32] = hex::decode(channel).unwrap().try_into().unwrap();
    let a_device = *a_peer.device_id();
    let b_device = *b_peer.device_id();
    let reviewer = howl_envelope::AgentRole::Reviewer;
    assert!(
        node::grant_wake(&bob, channel_id, a_device, reviewer.agent_id(&b_device), 1)
            .await
            .is_err()
    );
    let agent = reviewer.agent_id(&a_device);
    node::grant_wake(&alice, channel_id, b_device, agent, 1)
        .await
        .unwrap();
    let wake = node::send_wake(
        &bob,
        channel_id,
        a_device,
        &alice_address,
        agent,
        30,
        "review from the human client",
    )
    .await
    .unwrap();
    let message = wake.strip_prefix("queued ").unwrap();
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let report = successful(cli(&["status"], &bob, &[channel, message]));
        if report.contains("delivered") {
            break;
        }
        assert!(
            Instant::now() < until,
            "client wake was not delivered: {report}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let events: Vec<serde_json::Value> =
        serde_json::from_str(&successful(cli(&["events"], &bob, &[channel]))).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["message"], message);
    assert_eq!(events[0]["role"], "wake");
    let cursor = events[0]["cursor"].as_u64().unwrap().to_string();
    let queued = node::send(
        &alice,
        channel_id,
        *b_peer.device_id(),
        &bob_address,
        "signed before removal",
    )
    .await
    .unwrap();
    assert!(queued.starts_with("queued "));
    wait_for_text(&bob, channel, "signed before removal").await;
    let events: Vec<serde_json::Value> =
        serde_json::from_str(&successful(cli(&["events"], &bob, &[channel, &cursor]))).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["text"], "signed before removal");
    let queued = node::send(
        &alice,
        second_id,
        *b_peer.device_id(),
        &bob_address,
        "second channel",
    )
    .await
    .unwrap();
    assert!(queued.starts_with("queued "));
    wait_for_text(&bob, second_channel, "second channel").await;
    let hint = node::export_hint(&alice, alice_address.parse().unwrap()).unwrap();
    node::import_hint(&bob, &hint).unwrap();
    let architect = howl_envelope::AgentRole::Architect.agent_id(&a_device);
    node::grant_wake(&alice, channel_id, b_device, architect, 1)
        .await
        .unwrap();
    check_gateway(&alice, &bob, channel, second_channel, a_device, architect).await;
    if let Ok(image) = std::env::var("HOWL_MCP_INTEROP_IMAGE") {
        interop::verify(
            &bob,
            &alice,
            &bob_address,
            &alice_address,
            channel,
            second_channel,
            &image,
        )
        .await;
    }

    let revocation = successful(cli(
        &["roster", "revoke"],
        &alice,
        &[channel, &bob_device, "1"],
    ));
    let proof = revocation
        .lines()
        .nth(1)
        .unwrap()
        .strip_prefix("Proof ")
        .unwrap();
    successful(cli(
        &["roster", "apply-revocation"],
        &bob,
        &[channel, proof],
    ));
    assert!(
        node::send(
            &alice,
            channel_id,
            *b_peer.device_id(),
            &bob_address,
            "after removal"
        )
        .await
        .is_err()
    );
    assert!(
        node::send(
            &alice,
            second_id,
            *b_peer.device_id(),
            &bob_address,
            "after account revocation"
        )
        .await
        .is_err()
    );
    assert!(successful(cli(&["read"], &bob, &[channel])).contains("signed before removal"));
    assert!(successful(cli(&["read"], &bob, &[second_channel])).contains("second channel"));
    assert!(
        successful(cli(&["read"], &bob, &[&legacy_channel])).contains("recorded before enrollment")
    );
    assert!(
        successful(cli(&["status"], &alice, &[&legacy_channel, legacy_message]))
            .contains(&bob_device)
    );

    successful(cli(&["mesh", "stop"], &alice, &[]));
    successful(cli(&["mesh", "stop"], &bob, &[]));
    assert!(a_node.0.wait().unwrap().success());
    assert!(b_node.0.wait().unwrap().success());
}

async fn check_gateway(
    receiver: &Path,
    state: &Path,
    channel: &str,
    denied_channel: &str,
    peer: [u8; 32],
    target: [u8; 32],
) {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let config = tempfile::NamedTempFile::new().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    let primary = "howl-mcp-test-primary-4c5d44382e232";
    let reader = "howl-mcp-test-reader-3d172d3363427d";
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let grant = |id, token: &str, permissions| {
        json!({
            "id": id,
            "token_sha256": hex::encode(Sha256::digest(token)),
            "expires_at": expires_at,
            "channels": [channel],
            "permissions": permissions,
        })
    };
    std::fs::write(
        config.path(),
        json!({
            "resource": endpoint,
            "grants": [
                grant("primary", primary, json!(["read", "send", "wake", "cancel"])),
                grant("reader", reader, json!(["read"]))
            ]
        })
        .to_string(),
    )
    .unwrap();
    let state = state.to_owned();
    let path = config.path().to_owned();
    let gateway = tokio::spawn(async move { howl::serve_gateway(&state, &path, listener).await });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .no_proxy()
        .build()
        .unwrap();
    let call = |token: &str, name: &str, args: serde_json::Value| {
        client
            .post(&endpoint)
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", name)
            .body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": name,
                        "arguments": args,
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                    },
                })
                .to_string(),
            )
    };
    let list = mcp_response(call(reader, "list_channels", json!({}))).await;
    assert_eq!(
        list["result"]["structuredContent"]["channels"],
        json!([channel])
    );
    let denied = mcp_response(call(reader, "read", json!({"channel": denied_channel}))).await;
    assert!(denied.get("error").is_some(), "{denied}");
    let post = mcp_response(call(
        primary,
        "dm",
        json!({"channel": channel, "peer": hex::encode(peer), "text": "signed integration chat"}),
    ))
    .await;
    assert!(
        post["result"]["structuredContent"]["message"].is_string(),
        "{post}"
    );
    wait_for_text(receiver, channel, "signed integration chat").await;
    let request = json!({
        "channel": channel,
        "peer": hex::encode(peer),
        "target": hex::encode(target),
        "key": "mesh-gateway-test-1",
        "lifetime": 30,
        "text": "wake via remote MCP",
    });
    let denied = mcp_response(call(reader, "wake", request.clone())).await;
    assert!(denied.get("error").is_some(), "{denied}");
    let first = mcp_response(call(primary, "wake", request.clone())).await;
    let retry = mcp_response(call(primary, "wake", request)).await;
    let first_run = &first["result"]["structuredContent"];
    let retry_run = &retry["result"]["structuredContent"];
    assert!(first_run["run"].is_string(), "{first}");
    assert!(first_run["wake_message"].is_string(), "{first}");
    assert_eq!(first_run["run"], retry_run["run"]);
    assert_eq!(first_run["wake_message"], retry_run["wake_message"]);
    let args = json!({ "channel": channel, "run": first_run["run"] });
    let other_owner = mcp_response(call(reader, "get_run", args.clone())).await;
    assert!(other_owner.get("error").is_some(), "{other_owner}");
    let own = mcp_response(call(primary, "get_run", args)).await;
    assert_eq!(own["result"]["structuredContent"]["run"], first_run["run"]);
    let channel_id = hex::decode(channel).unwrap().try_into().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(job) =
            howl::workflow::claim(receiver, channel_id, howl_envelope::AgentRole::Architect)
                .unwrap()
        {
            assert_eq!(job.text, "wake via remote MCP");
            assert_eq!(
                json!(hex::encode(job.claim.message)),
                first_run["wake_message"]
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "remote wake did not reach the mesh"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let events = serde_json::to_value(
        howl::interaction::LocalInteraction::new(receiver)
            .events(channel_id, 0, 100)
            .unwrap(),
    )
    .unwrap();
    let events = events.as_array().unwrap();
    let origin = |text| &events.iter().find(|event| event["text"] == text).unwrap()["integration"];
    assert!(origin("signed integration chat").is_string());
    assert_eq!(
        origin("signed integration chat"),
        origin("wake via remote MCP")
    );
    assert!(origin("review from the human client").is_null());
    gateway.abort();
}

async fn mcp_response(request: reqwest::RequestBuilder) -> serde_json::Value {
    let response = request.send().await.unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{status}: {text}");
    let payload = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("data: ")
                .filter(|data| data.starts_with('{'))
        })
        .unwrap_or(&text);
    serde_json::from_str(payload).unwrap()
}

async fn wait_for_text(state: &Path, channel: &str, text: &str) {
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        if successful(cli(&["read"], state, &[channel])).contains(text) {
            return;
        }
        assert!(Instant::now() < until, "delivery did not reach the reader");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
