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
    assert_eq!(
        line(&identity, "Endpoint "),
        peer.endpoint().to_string().as_str()
    );
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

#[test]
fn offline_export_recovers_authority_after_loss_of_the_online_root() {
    let fixture = tempfile::tempdir().unwrap();
    let operator = fixture.path().join("online");
    let offline = fixture.path().join("offline");
    let package = fixture.path().join("package");
    let unlock = fixture.path().join("unlock");
    let damaged_unlock = fixture.path().join("damaged-unlock");
    let downloaded_package = fixture.path().join("downloaded-package");
    let recovered = fixture.path().join("recovered");
    let next_offline = fixture.path().join("next-offline");
    let init = success(command(&[
        "init".as_ref(),
        operator.as_os_str(),
        offline.as_os_str(),
    ]));
    let account = line(&init, "Account ");
    let head = line(&init, "Authority ");
    let prior = AuthorityStore::open(&operator).unwrap().current().unwrap();
    let export = |unlock: &Path| {
        command(&[
            "recover-export".as_ref(),
            operator.as_os_str(),
            offline.as_os_str(),
            package.as_os_str(),
            unlock.as_os_str(),
        ])
    };
    failed(export(&package));
    let first = success(export(&unlock));
    let public = fs::read(package.join("recovery-package")).unwrap();
    let key = fs::read(unlock.join("recovery-unlock")).unwrap();
    assert!(public.len() > 32);
    assert_eq!(key.len(), 32);
    assert!(!first.contains(&hex::encode(&key)));
    assert!(!package.join("recovery-unlock").exists());
    assert_eq!(
        fs::metadata(unlock.join("recovery-unlock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(success(export(&unlock)), first);
    assert_eq!(fs::read(package.join("recovery-package")).unwrap(), public);
    assert_eq!(fs::read(unlock.join("recovery-unlock")).unwrap(), key);

    artifact(&damaged_unlock, &unlock, &["recovery-unlock"]);
    let mut wrong_key = key;
    wrong_key[0] ^= 1;
    fs::write(damaged_unlock.join("recovery-unlock"), wrong_key).unwrap();
    artifact(
        &downloaded_package,
        &package,
        &["authority-pin", "recovery-package"],
    );
    let mut tampered = public.clone();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(downloaded_package.join("recovery-package"), tampered).unwrap();

    fs::remove_dir_all(&operator).unwrap();
    fs::remove_dir_all(&offline).unwrap();

    let recover = |package: &Path, unlock: &Path, head: &OsStr| {
        command(&[
            "recover".as_ref(),
            recovered.as_os_str(),
            package.as_os_str(),
            unlock.as_os_str(),
            next_offline.as_os_str(),
            account,
            head,
        ])
    };
    failed(recover(&package, &damaged_unlock, head));
    failed(recover(&downloaded_package, &unlock, head));
    failed(recover(&package, &unlock, "00".repeat(32).as_ref()));
    assert!(!recovered.join("authority-pin").exists());

    fs::write(downloaded_package.join("recovery-package"), public).unwrap();
    let result = success(recover(&downloaded_package, &unlock, head));
    assert_eq!(line(&result, "Account "), account);
    assert_ne!(line(&result, "Authority "), head);
    let authority = AuthorityStore::open(&recovered).unwrap().load().unwrap();
    let successor = authority.head().unwrap();
    assert_eq!(authority.records().len(), 2);
    assert_eq!(successor.account, prior.account);
    assert_eq!(successor.generation, prior.generation + 1);
    assert_ne!(successor.root, prior.root);
    assert_ne!(successor.recovery, prior.recovery);
    assert_eq!(success(recover(&downloaded_package, &unlock, head)), result);
}

#[test]
fn existing_devices_adopt_recovery_and_a_higher_certificate_sequence() {
    let fixture = tempfile::tempdir().unwrap();
    let path = |name: &str| fixture.path().join(name);
    let operator = path("operator");
    let offline = path("offline");
    let candidate = path("candidate");
    let observer = path("observer");
    let first_exchange = path("first-exchange");
    let first = success(command(&[
        "init".as_ref(),
        operator.as_os_str(),
        offline.as_os_str(),
    ]));
    pairing_exchange(
        &operator,
        &candidate,
        &first_exchange,
        &path("first-secret"),
        &first,
        "1",
    );
    success(accept_enrollment(&candidate, &first_exchange, &first));
    let observer_exchange = path("observer-exchange");
    pairing_exchange(
        &operator,
        &observer,
        &observer_exchange,
        &path("observer-secret"),
        &first,
        "1",
    );
    success(accept_enrollment(&observer, &observer_exchange, &first));
    success(command(&[
        "peer".as_ref(),
        observer.as_os_str(),
        first_exchange.as_os_str(),
    ]));
    let first_pin = fs::read(candidate.join("authority-pin")).unwrap();
    let first_cert = fs::read(candidate.join("enrollment-certificate")).unwrap();
    let device = LocalIdentity::load_or_create(&candidate)
        .unwrap()
        .certificate();
    let package = path("package");
    let unlock = path("unlock");
    success(command(&[
        "recover-export".as_ref(),
        operator.as_os_str(),
        offline.as_os_str(),
        package.as_os_str(),
        unlock.as_os_str(),
    ]));
    let recovered = path("recovered");
    let recovered_offline = path("recovered-offline");
    let second = success(command(&[
        "recover".as_ref(),
        recovered.as_os_str(),
        package.as_os_str(),
        unlock.as_os_str(),
        recovered_offline.as_os_str(),
        line(&first, "Account "),
        line(&first, "Authority "),
    ]));
    let old_sequence_exchange = path("old-sequence-exchange");
    pairing_exchange(
        &recovered,
        &candidate,
        &old_sequence_exchange,
        &path("old-sequence-secret"),
        &second,
        "1",
    );
    failed(accept_enrollment(
        &candidate,
        &old_sequence_exchange,
        &second,
    ));
    assert_eq!(
        success(command(&["authority".as_ref(), candidate.as_os_str()])),
        first
    );
    let renewal = path("renewal-exchange");
    pairing_exchange(
        &recovered,
        &candidate,
        &renewal,
        &path("renewal-secret"),
        &second,
        "2",
    );
    failed(accept_enrollment(&observer, &renewal, &second));
    success(accept_enrollment(&candidate, &renewal, &second));
    success(accept_enrollment(&candidate, &renewal, &second));
    failed(accept_enrollment(&candidate, &first_exchange, &first));
    assert_eq!(
        success(command(&["authority".as_ref(), candidate.as_os_str()])),
        second
    );
    assert_eq!(
        fs::read(candidate.join("authority-pin")).unwrap(),
        first_pin
    );
    assert_eq!(
        fs::read(candidate.join("enrollment-certificate")).unwrap(),
        first_cert
    );
    let unrelated = path("unrelated-operator");
    let unrelated_offline = path("unrelated-offline");
    let unrelated_ids = success(command(&[
        "init".as_ref(),
        unrelated.as_os_str(),
        unrelated_offline.as_os_str(),
    ]));
    let unrelated_exchange = path("unrelated-exchange");
    pairing_exchange(
        &unrelated,
        &candidate,
        &unrelated_exchange,
        &path("unrelated-secret"),
        &unrelated_ids,
        "3",
    );
    failed(accept_enrollment(
        &candidate,
        &unrelated_exchange,
        &unrelated_ids,
    ));
    assert_eq!(
        success(command(&["authority".as_ref(), candidate.as_os_str()])),
        second
    );

    let observer_renewal = path("observer-renewal");
    pairing_exchange(
        &recovered,
        &observer,
        &observer_renewal,
        &path("observer-renewal-secret"),
        &second,
        "2",
    );
    success(accept_enrollment(&observer, &observer_renewal, &second));
    let peer =
        |exchange: &Path| command(&["peer".as_ref(), observer.as_os_str(), exchange.as_os_str()]);
    failed(peer(&first_exchange));
    success(peer(&renewal));
    success(peer(&renewal));
    let pinned = PeerTrust::open(&observer)
        .unwrap()
        .pinned(device.device_id())
        .unwrap();
    assert_eq!(pinned.as_bytes(), device.as_bytes());
}

fn accept_enrollment(state: &Path, exchange: &Path, authority: &str) -> Output {
    command(&[
        "accept".as_ref(),
        state.as_os_str(),
        exchange.as_os_str(),
        line(authority, "Account "),
        line(authority, "Authority "),
        line(authority, "Designation "),
    ])
}

fn pairing_exchange(
    issuer: &Path,
    state: &Path,
    exchange: &Path,
    secret: &Path,
    authority: &str,
    sequence: &str,
) {
    let identity = success(command(&[
        "identity".as_ref(),
        state.as_os_str(),
        exchange.as_os_str(),
    ]));
    success(command(&[
        "offer".as_ref(),
        issuer.as_os_str(),
        exchange.as_os_str(),
        line(&identity, "Fingerprint "),
        sequence.as_ref(),
        secret.as_os_str(),
    ]));
    success(command(&[
        "respond".as_ref(),
        state.as_os_str(),
        exchange.as_os_str(),
        line(authority, "Account "),
        line(authority, "Authority "),
        line(authority, "Designation "),
        secret.as_os_str(),
    ]));
    success(command(&[
        "certify".as_ref(),
        issuer.as_os_str(),
        exchange.as_os_str(),
    ]));
}
