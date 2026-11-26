use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use howl::identity::{LocalIdentity, PeerTrust};

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

#[test]
fn trusted_peers_exchange_durable_chat_through_the_cli() {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let alice_cert = LocalIdentity::load_or_create(&alice).unwrap().certificate();
    let bob_cert = LocalIdentity::load_or_create(&bob).unwrap().certificate();
    PeerTrust::open(&alice)
        .unwrap()
        .pin(&bob_cert, &bob_cert.fingerprint())
        .unwrap();
    PeerTrust::open(&bob)
        .unwrap()
        .pin(&alice_cert, &alice_cert.fingerprint())
        .unwrap();
    let bob_device = hex::encode(bob_cert.device_id());

    let manifest = successful(cli(&["channel", "create"], &alice, &[&bob_device]));
    let mut lines = manifest.lines();
    let channel = lines.next().unwrap().strip_prefix("Channel ").unwrap();
    let token = lines.next().unwrap().strip_prefix("Manifest ").unwrap();
    successful(cli(&["channel", "join"], &bob, &[token]));

    let (mut alice_node, _) = start(&alice);
    let (mut bob_node, bob_address) = start(&bob);
    let mut sender = Command::new(env!("CARGO_BIN_EXE_howl"))
        .arg("send")
        .arg(&alice)
        .args([channel, &bob_device, &bob_address])
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

    successful(cli(&["mesh", "stop"], &alice, &[]));
    successful(cli(&["mesh", "stop"], &bob, &[]));
    assert!(alice_node.0.wait().unwrap().success());
    assert!(bob_node.0.wait().unwrap().success());
    let restarted_read = successful(cli(&["read"], &bob, &[channel]));
    assert_eq!(inbox, restarted_read);
}
