use std::{
    fs,
    net::TcpListener,
    path::Path,
    process::{Child, Command},
    time::{Duration, Instant},
};

use howl::{
    identity::{LocalIdentity, PeerTrust},
    transport::{EndpointAddr, Network, RelayUrl, Transport},
};
use tokio::{net::TcpStream, time};

struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pin(state: &Path, identity: &LocalIdentity) {
    let certificate = identity.certificate();
    PeerTrust::open(state)
        .unwrap()
        .pin(&certificate, &certificate.fingerprint())
        .unwrap();
}

#[tokio::test]
#[ignore = "requires the official iroh-relay 1.5.0 binary and local networking"]
async fn stock_relay_allows_only_configured_endpoint_identities() {
    let root = tempfile::tempdir().unwrap();
    let alice_state = root.path().join("alice");
    let bob_state = root.path().join("bob");
    let outside_state = root.path().join("outside");
    let alice = LocalIdentity::load_or_create(&alice_state).unwrap();
    let bob = LocalIdentity::load_or_create(&bob_state).unwrap();
    let outside = LocalIdentity::load_or_create(&outside_state).unwrap();
    pin(&alice_state, &bob);
    pin(&bob_state, &alice);
    pin(&bob_state, &outside);
    pin(&outside_state, &bob);

    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = socket.local_addr().unwrap();
    let config = root.path().join("relay.toml");
    fs::write(
        &config,
        format!(
            "http_bind_addr = \"{local}\"\nenable_metrics = false\nenable_quic_addr_discovery = false\naccess.allowlist = [\"{}\", \"{}\"]\n[limits.client.rx]\nbytes_per_second = 65536\nmax_burst_bytes = 8192\n",
            alice.certificate().endpoint(),
            bob.certificate().endpoint(),
        ),
    )
    .unwrap();
    let binary =
        std::env::var_os("HOWL_TEST_IROH_RELAY").expect("set the pinned iroh-relay binary");
    let version = Command::new(&binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        "iroh-relay 1.5.0"
    );
    drop(socket);
    let _relay = Relay(
        Command::new(binary)
            .env("RUST_LOG", "error")
            .args(["--dev", "--config-path"])
            .arg(&config)
            .spawn()
            .unwrap(),
    );
    time::timeout(Duration::from_secs(5), async {
        while TcpStream::connect(local).await.is_err() {
            time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("local iroh relay did not listen");
    let url: RelayUrl = format!("http://{local}").parse().unwrap();
    let sender = Transport::bind(
        &alice,
        PeerTrust::open(&alice_state).unwrap(),
        Network::RelayOnly(url.clone()),
        None,
    )
    .await
    .unwrap();
    let receiver = Transport::bind(
        &bob,
        PeerTrust::open(&bob_state).unwrap(),
        Network::RelayOnly(url.clone()),
        None,
    )
    .await
    .unwrap();
    let denied = Transport::bind(
        &outside,
        PeerTrust::open(&outside_state).unwrap(),
        Network::RelayOnly(url.clone()),
        None,
    )
    .await
    .unwrap();
    let bob_cert = bob.certificate();
    let destination = EndpointAddr::new(bob_cert.endpoint()).with_relay_url(url);
    for text in [b"before".as_slice(), b"after".as_slice()] {
        sender
            .send(bob_cert.device_id(), destination.clone(), text)
            .await
            .unwrap();
        let received = time::timeout(Duration::from_secs(5), receiver.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.peer.device_id(), alice.certificate().device_id());
        assert_eq!(received.bytes, text);
        if text == b"before" {
            let outcome = time::timeout(
                Duration::from_secs(3),
                denied.send(bob_cert.device_id(), destination.clone(), b"unlisted"),
            )
            .await;
            assert!(!matches!(outcome, Ok(Ok(()))));
        }
    }
    let payload = vec![0x5a; 65536];
    let began = Instant::now();
    sender
        .send(bob_cert.device_id(), destination, &payload)
        .await
        .unwrap();
    let received = time::timeout(Duration::from_secs(5), receiver.receive())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.bytes, payload);
    assert!(began.elapsed() >= Duration::from_millis(500));
    sender.close().await;
    receiver.close().await;
    denied.close().await;
}
