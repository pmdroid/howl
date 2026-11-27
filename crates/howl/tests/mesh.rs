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
    let mut child = Node(
        Command::new(env!("CARGO_BIN_EXE_howl"))
            .args(["mesh", "run"])
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

    let (mut a_node, _) = start(&alice);
    let (mut b_node, bob_address) = start(&bob);
    let channel_id: [u8; 32] = hex::decode(channel).unwrap().try_into().unwrap();
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
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        if successful(cli(&["read"], &bob, &[channel])).contains("signed before removal") {
            break;
        }
        assert!(Instant::now() < until, "signed delivery did not reach Bob");
        tokio::time::sleep(Duration::from_millis(50)).await;
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
    assert!(successful(cli(&["read"], &bob, &[channel])).contains("signed before removal"));
    successful(cli(&["mesh", "stop"], &alice, &[]));
    successful(cli(&["mesh", "stop"], &bob, &[]));
    assert!(a_node.0.wait().unwrap().success());
    assert!(b_node.0.wait().unwrap().success());
}
