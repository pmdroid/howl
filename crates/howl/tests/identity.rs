use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
    sync::{Arc, Barrier},
    thread,
};

use howl::identity::{LocalIdentity, PeerCertificate, PeerTrust};

#[test]
fn concurrent_initialization_publishes_one_private_identity() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("device");
    let barrier = Arc::new(Barrier::new(4));

    let fingerprints = thread::scope(|threads| {
        let handles = (0..4)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let state = &state;
                threads.spawn(move || {
                    barrier.wait();
                    LocalIdentity::load_or_create(state)
                        .unwrap()
                        .certificate()
                        .fingerprint()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });

    let restarted = LocalIdentity::load_or_create(&state).unwrap().certificate();
    assert!(
        fingerprints
            .iter()
            .all(|value| *value == restarted.fingerprint())
    );
    assert_eq!(
        fs::metadata(&state).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(state.join("device-v1"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(state).unwrap().count(), 1);
}

#[test]
fn certificate_requires_an_out_of_band_pin_and_matching_endpoint() {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let identity = LocalIdentity::load_or_create(&alice).unwrap();
    let other = LocalIdentity::load_or_create(&bob).unwrap();
    let original = identity.certificate();
    let certificate = PeerCertificate::from_bytes(*original.as_bytes()).unwrap();
    let trust = PeerTrust::open(&bob).unwrap();

    assert!(
        trust
            .authorize(certificate.device_id(), certificate.endpoint())
            .is_err()
    );
    assert!(
        trust
            .pin(&certificate, &other.certificate().fingerprint())
            .is_err()
    );
    assert!(
        trust
            .authorize(certificate.device_id(), certificate.endpoint())
            .is_err()
    );

    trust.pin(&certificate, &certificate.fingerprint()).unwrap();
    let restarted = PeerTrust::open(&bob).unwrap();
    restarted
        .pin(&certificate, &certificate.fingerprint())
        .unwrap();
    assert!(
        restarted
            .authorize(certificate.device_id(), certificate.endpoint())
            .is_ok()
    );
    assert!(
        restarted
            .authorize(certificate.device_id(), other.transport_key().public())
            .is_err()
    );

    let mut tampered = *certificate.as_bytes();
    tampered[97] ^= 1;
    assert!(PeerCertificate::from_bytes(tampered).is_err());
}

#[test]
fn insecure_state_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("device");
    LocalIdentity::load_or_create(&state).unwrap();
    let key_path = state.join("device-v1");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        LocalIdentity::load_or_create(&state).err().unwrap().kind(),
        ErrorKind::PermissionDenied
    );
    let moved = state.join("moved");
    fs::rename(&key_path, &moved).unwrap();
    fs::set_permissions(&moved, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&moved, &key_path).unwrap();
    assert!(LocalIdentity::load_or_create(&state).is_err());
}

#[test]
fn cli_shows_only_public_identity_and_pairs() {
    let root = tempfile::tempdir().unwrap();
    let alice = root.path().join("alice");
    let bob = root.path().join("bob");
    let identity = LocalIdentity::load_or_create(&alice).unwrap();
    let show = Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(["identity", "show"])
        .arg(&alice)
        .output()
        .unwrap();
    assert!(show.status.success());
    let text = String::from_utf8(show.stdout).unwrap();
    let certificate = hex::encode(identity.certificate().as_bytes());
    let fingerprint = hex::encode(identity.certificate().fingerprint());
    let device = hex::encode(identity.certificate().device_id());
    assert_eq!(
        text,
        format!("Certificate {certificate}\nFingerprint {fingerprint}\nDevice {device}\n")
    );
    assert!(show.stderr.is_empty());

    let trust = Command::new(env!("CARGO_BIN_EXE_howl"))
        .args(["peer", "trust"])
        .arg(&bob)
        .args([&certificate, &fingerprint])
        .output()
        .unwrap();
    assert!(trust.status.success());
    let certificate = identity.certificate();
    assert!(
        PeerTrust::open(&bob)
            .unwrap()
            .authorize(certificate.device_id(), certificate.endpoint())
            .is_ok()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn extended_file_acl_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("device");
    LocalIdentity::load_or_create(&state).unwrap();
    let key = state.join("device-v1");
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        LocalIdentity::load_or_create(&state).err().unwrap().kind(),
        ErrorKind::PermissionDenied
    );
}
