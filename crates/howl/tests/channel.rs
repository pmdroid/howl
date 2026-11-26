use std::process::Command;

use howl::{
    channel::Channel,
    identity::{LocalIdentity, PeerTrust},
};

#[test]
fn cli_create_and_join_require_a_signed_manifest_and_local_membership() {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let eve = root.path().join("eve");
    let alice_identity = LocalIdentity::load_or_create(&alice).unwrap();
    let bob_identity = LocalIdentity::load_or_create(&bob).unwrap();
    let eve_identity = LocalIdentity::load_or_create(&eve).unwrap();
    let alice_certificate = alice_identity.certificate();
    let bob_certificate = bob_identity.certificate();
    PeerTrust::open(&alice)
        .unwrap()
        .pin(&bob_certificate, &bob_certificate.fingerprint())
        .unwrap();
    for state in [&bob, &eve] {
        PeerTrust::open(state)
            .unwrap()
            .pin(&alice_certificate, &alice_certificate.fingerprint())
            .unwrap();
    }
    PeerTrust::open(&eve)
        .unwrap()
        .pin(&bob_certificate, &bob_certificate.fingerprint())
        .unwrap();

    let created = Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(["channel", "create"])
        .arg(&alice)
        .arg(hex::encode(bob_certificate.device_id()))
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let report = String::from_utf8(created.stdout).unwrap();
    let mut lines = report.lines();
    let id: [u8; 32] = hex::decode(lines.next().unwrap().strip_prefix("Channel ").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let manifest = lines.next().unwrap().strip_prefix("Manifest ").unwrap();

    let first = Channel::load(&alice, &alice_identity, &id).unwrap();
    assert_eq!(first.members().len(), 2);

    let joined = Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(["channel", "join"])
        .arg(&bob)
        .arg(manifest)
        .output()
        .unwrap();
    assert!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    let restarted = Channel::load(&bob, &bob_identity, &id).unwrap();
    assert_eq!(first.manifest(), restarted.manifest());

    let mut altered = first.manifest().to_vec();
    let last = altered.last_mut().unwrap();
    *last ^= 1;
    assert!(Channel::join(&bob, &bob_identity, &altered).is_err());
    assert!(Channel::join(&eve, &eve_identity, first.manifest()).is_err());
}
