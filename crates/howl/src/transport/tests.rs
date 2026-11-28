use std::path::Path;

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const NO_FRAME: Duration = Duration::from_millis(150);

#[test]
fn local_candidates_use_interface_prefixes_and_skip_tailnet_addresses() {
    let networks = ["192.168.8.17/23", "fd00:8::17/64", "100.100.0.1/10"]
        .map(|network| network.parse().unwrap());
    assert!(on_link(&networks, "192.168.9.44".parse().unwrap()));
    assert!(on_link(&networks, "fd00:8::99".parse().unwrap()));
    assert!(!on_link(&networks, "192.168.10.44".parse().unwrap()));
    assert!(!on_link(&networks, "100.100.0.2".parse().unwrap()));
}

fn pair(root: &Path) -> io::Result<((LocalIdentity, PeerTrust), (LocalIdentity, PeerTrust))> {
    let alice = root.join("alice");
    let bob = root.join("bob");
    let alice_identity = LocalIdentity::load_or_create(&alice)?;
    let bob_identity = LocalIdentity::load_or_create(&bob)?;
    let alice_trust = PeerTrust::open(&alice)?;
    let bob_trust = PeerTrust::open(&bob)?;
    let alice_certificate = alice_identity.certificate();
    let bob_certificate = bob_identity.certificate();
    alice_trust.pin(&bob_certificate, &bob_certificate.fingerprint())?;
    bob_trust.pin(&alice_certificate, &alice_certificate.fingerprint())?;
    Ok(((alice_identity, alice_trust), (bob_identity, bob_trust)))
}

async fn loopback(identity: &LocalIdentity, trust: PeerTrust) -> io::Result<Transport> {
    Transport::bind(
        identity,
        trust,
        Network::Direct,
        Some("127.0.0.1:0".parse().unwrap()),
    )
    .await
}

async fn next_frame(transport: &Transport) -> ReceivedFrame {
    timeout(TEST_TIMEOUT, transport.receive())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn sends_a_maximum_frame_and_replies_on_the_cached_connection_after_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let ((alice, alice_trust), (bob, bob_trust)) = pair(root.path()).unwrap();
    let alice_device = alice.certificate();
    let bob_device = bob.certificate();
    let alice = loopback(&alice, alice_trust).await.unwrap();
    let bob_server = loopback(&bob, bob_trust).await.unwrap();
    let address = bob_server.address();
    let frame = vec![0x16; MAX_FRAME_BYTES];

    alice
        .send(bob_device.device_id(), address.clone(), &frame)
        .await
        .unwrap();
    let delivered = next_frame(&bob_server).await;
    assert_eq!(delivered.bytes, frame);
    assert_eq!(delivered.peer.as_bytes(), alice_device.as_bytes());
    delivered.reply(b"first ack").await.unwrap();
    let returned = next_frame(&alice).await;
    assert_eq!(returned.bytes, b"first ack");
    assert_eq!(returned.peer.as_bytes(), bob_device.as_bytes());
    for (transport, peer) in [(&alice, &bob_device), (&bob_server, &alice_device)] {
        timeout(TEST_TIMEOUT, async {
            let expected = PeerPath {
                device: hex::encode(peer.device_id()),
                kind: PathKind::Direct,
            };
            while !transport.peer_paths().await.contains(&expected) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("direct connection was not reported");
    }
    let cached = alice
        .connect(bob_device.device_id(), address.clone())
        .await
        .unwrap();
    assert_eq!(cached.stable_id(), returned.connection.stable_id());
    bob_server.close().await;
    timeout(TEST_TIMEOUT, cached.closed()).await.unwrap();
    assert!(alice.peer_paths().await.is_empty());

    let reloaded = LocalIdentity::load_or_create(&root.path().join("bob")).unwrap();
    let reopened = PeerTrust::open(&root.path().join("bob")).unwrap();
    let bob_server = loopback(&reloaded, reopened).await.unwrap();
    assert_eq!(address.id, bob_server.address().id);
    alice
        .send(bob_device.device_id(), bob_server.address(), b"reconnected")
        .await
        .unwrap();
    let delivered = next_frame(&bob_server).await;
    assert_eq!(delivered.bytes, b"reconnected");
    delivered.reply(b"second ack").await.unwrap();
    let returned = next_frame(&alice).await;
    assert_ne!(cached.stable_id(), returned.connection.stable_id());
    assert_eq!(returned.bytes, b"second ack");
}

#[tokio::test]
async fn rejects_an_unpinned_endpoint_claiming_a_pinned_device() {
    let root = tempfile::tempdir().unwrap();
    let ((alice, _), (bob, bob_trust)) = pair(root.path()).unwrap();
    let bob = loopback(&bob, bob_trust).await.unwrap();
    let stranger = Endpoint::bind(presets::Minimal).await.unwrap();
    let connection = stranger.connect(bob.address(), ALPN).await.unwrap();

    let mut early = connection.open_uni().await.unwrap();
    early.write_all(&[0, 0, 0, 1, 7]).await.unwrap();
    early.finish().unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    send.write_all(alice.certificate().device_id())
        .await
        .unwrap();
    send.finish().unwrap();
    assert!(
        timeout(TEST_TIMEOUT, read_device_id(&mut receive))
            .await
            .unwrap()
            .is_err()
    );
    assert!(timeout(NO_FRAME, bob.receive()).await.is_err());

    assert!(
        timeout(
            TEST_TIMEOUT,
            stranger.connect(bob.address(), b"howl/mesh/2")
        )
        .await
        .unwrap()
        .is_err()
    );
}

#[tokio::test]
async fn rejects_empty_oversized_and_incomplete_frames() {
    let root = tempfile::tempdir().unwrap();
    let ((alice, alice_trust), (bob, bob_trust)) = pair(root.path()).unwrap();
    let server = loopback(&bob, bob_trust).await.unwrap();
    let client = loopback(&alice, alice_trust).await.unwrap();
    let bob_peer = bob.certificate();

    for invalid in [vec![], vec![0; MAX_FRAME_BYTES + 1]] {
        let error = client
            .send(bob_peer.device_id(), server.address(), &invalid)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    for (length, bytes) in [
        (0, &[][..]),
        (MAX_FRAME_BYTES as u32 + 1, &[][..]),
        (2, &[1][..]),
        (1, &[1, 2][..]),
    ] {
        let connection = client
            .connect(bob_peer.device_id(), server.address())
            .await
            .unwrap();
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(&u32::to_be_bytes(length)).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.finish().unwrap();
        timeout(TEST_TIMEOUT, connection.closed()).await.unwrap();
        assert!(timeout(NO_FRAME, server.receive()).await.is_err());
    }
}

#[tokio::test]
async fn a_full_receive_queue_backpressures_the_next_stream() {
    let root = tempfile::tempdir().unwrap();
    let ((alice, alice_trust), (bob, bob_trust)) = pair(root.path()).unwrap();
    let server = loopback(&bob, bob_trust).await.unwrap();
    let client = loopback(&alice, alice_trust).await.unwrap();
    let peer = bob.certificate();

    for _ in 0..=RECEIVE_QUEUE_LEN {
        client
            .send(peer.device_id(), server.address(), b"queued")
            .await
            .unwrap();
    }
    let mut blocked = Box::pin(client.send(peer.device_id(), server.address(), b"last"));
    assert!(timeout(NO_FRAME, &mut blocked).await.is_err());
    assert_eq!(next_frame(&server).await.bytes, b"queued");
    timeout(TEST_TIMEOUT, blocked).await.unwrap().unwrap();
    for _ in 0..RECEIVE_QUEUE_LEN {
        assert_eq!(next_frame(&server).await.bytes, b"queued");
    }
    assert_eq!(next_frame(&server).await.bytes, b"last");
}
