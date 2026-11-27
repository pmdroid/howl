use std::{
    ffi::OsStr,
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
    process::{Command, Output},
};

use howl::{
    enrollment::{AuthorityStore, Designation, DeviceCertificate},
    identity::{LocalIdentity, PeerTrust},
};

fn command(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_howl"))
        .arg("enrollment")
        .args(args)
        .output()
        .unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn failed(output: Output) {
    assert!(!output.status.success());
}

fn artifact(destination: &Path, source: &Path, names: &[&str]) {
    match fs::DirBuilder::new().mode(0o700).create(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("{error}"),
    }
    for name in names {
        fs::copy(source.join(name), destination.join(name)).unwrap();
    }
}

fn line<'a>(output: &'a str, name: &str) -> &'a OsStr {
    OsStr::new(
        output
            .lines()
            .find_map(|text| text.strip_prefix(name))
            .unwrap(),
    )
}

#[test]
fn enrollment_transfers_separate_artifacts_and_checks_all_device_proofs() {
    let fixture = tempfile::tempdir().unwrap();
    let operator = fixture.path().join("operator");
    let offline = fixture.path().join("offline");
    let candidate = fixture.path().join("candidate");
    let substitute = fixture.path().join("other-device");
    let candidate_exchange = fixture.path().join("candidate-exchange");
    let operator_exchange = fixture.path().join("operator-exchange");
    let invitation_out = fixture.path().join("invitation-out");
    let invitation_in = fixture.path().join("invitation-in");
    let init = success(command(&[
        "init".as_ref(),
        operator.as_os_str(),
        offline.as_os_str(),
    ]));
    let account = line(&init, "Account ");
    let head = line(&init, "Authority ");
    let designation = line(&init, "Designation ");
    assert_eq!(
        success(command(&["authority".as_ref(), operator.as_os_str()])),
        init
    );
    assert!(!operator.join("enrollment-recovery-key").exists());

    let identity = success(command(&[
        "identity".as_ref(),
        candidate.as_os_str(),
        candidate_exchange.as_os_str(),
    ]));
    let fingerprint = line(&identity, "Fingerprint ");
    artifact(&operator_exchange, &candidate_exchange, &["device"]);
    let wrong = "00".repeat(32);
    let offer = |confirmed: &OsStr| {
        command(&[
            "offer".as_ref(),
            operator.as_os_str(),
            operator_exchange.as_os_str(),
            confirmed,
            "1".as_ref(),
            invitation_out.as_os_str(),
        ])
    };
    failed(offer(wrong.as_ref()));
    assert!(!operator_exchange.join("offer").exists());
    let approved = success(offer(fingerprint));
    assert_eq!(success(offer(fingerprint)), approved);
    let secret = fs::read(invitation_out.join("invitation")).unwrap();
    assert_eq!(secret.len(), 32);
    assert!(!approved.contains(&hex::encode(secret)));
    assert_eq!(
        fs::metadata(invitation_out.join("invitation"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!operator_exchange.join("invitation").exists());

    artifact(
        &candidate_exchange,
        &operator_exchange,
        &["authority-pin", "enrollment-designation", "offer"],
    );
    artifact(&invitation_in, &invitation_out, &["invitation"]);
    let respond = |state: &Path, account: &OsStr, head: &OsStr, designation: &OsStr| {
        command(&[
            "respond".as_ref(),
            state.as_os_str(),
            candidate_exchange.as_os_str(),
            account,
            head,
            designation,
            invitation_in.as_os_str(),
        ])
    };
    failed(respond(&candidate, wrong.as_ref(), head, designation));
    failed(respond(&candidate, account, wrong.as_ref(), designation));
    failed(respond(&candidate, account, head, wrong.as_ref()));
    failed(respond(&substitute, account, head, designation));
    assert!(!candidate_exchange.join("response").exists());
    success(respond(&candidate, account, head, designation));

    artifact(&operator_exchange, &candidate_exchange, &["response"]);
    let response_path = operator_exchange.join("response");
    let proof = fs::read(&response_path).unwrap();
    let certify = || {
        command(&[
            "certify".as_ref(),
            operator.as_os_str(),
            operator_exchange.as_os_str(),
        ])
    };
    for offset in [0, 32, 96] {
        let mut altered = proof.clone();
        altered[offset] ^= 1;
        fs::write(&response_path, altered).unwrap();
        failed(certify());
        assert!(!operator_exchange.join("enrollment-certificate").exists());
    }
    fs::write(response_path, proof).unwrap();
    success(certify());
    failed(certify());
    fs::remove_file(operator_exchange.join("enrollment-certificate")).unwrap();
    success(command(&[
        "certificate".as_ref(),
        operator.as_os_str(),
        operator_exchange.as_os_str(),
    ]));
    failed(certify());

    artifact(
        &candidate_exchange,
        &operator_exchange,
        &["enrollment-certificate"],
    );
    let accept = |state: &Path| {
        command(&[
            "accept".as_ref(),
            state.as_os_str(),
            candidate_exchange.as_os_str(),
            account,
            head,
            designation,
        ])
    };
    failed(accept(&substitute));
    assert!(!substitute.join("authority-pin").exists());
    success(accept(&candidate));
    success(accept(&candidate));

    let peer = LocalIdentity::load_or_create(&candidate)
        .unwrap()
        .certificate();
    let store = AuthorityStore::open(&candidate).unwrap();
    let signed = Designation::verify(
        &fs::read(candidate.join("enrollment-designation")).unwrap(),
        store.current().unwrap(),
    )
    .unwrap();
    assert!(
        DeviceCertificate::verify(
            &fs::read(candidate.join("enrollment-certificate")).unwrap(),
            &signed
        )
        .unwrap()
        .matches(&peer)
    );

    success(command(&[
        "peer".as_ref(),
        operator.as_os_str(),
        operator_exchange.as_os_str(),
    ]));
    let pinned = PeerTrust::open(&operator)
        .unwrap()
        .pinned(peer.device_id())
        .unwrap();
    assert_eq!(pinned.as_bytes(), peer.as_bytes());
    assert_eq!(
        fs::read(operator.join(format!("enrollment-peer-{}", hex::encode(peer.device_id()))))
            .unwrap(),
        fs::read(operator_exchange.join("enrollment-certificate")).unwrap(),
    );
}
