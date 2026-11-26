use std::{env, io, path::Path, process::ExitCode};

use howl::{
    HELP,
    identity::{LocalIdentity, PeerCertificate, PeerTrust},
};

fn main() -> ExitCode {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [] => {
            println!("{HELP}");
            Ok(())
        }
        [arg] if arg == "--help" || arg == "-h" => {
            println!("{HELP}");
            Ok(())
        }
        [arg] if arg == "--version" || arg == "-V" => {
            println!("howl {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [group, action, state] if group == "identity" && action == "show" => {
            show_identity(Path::new(state))
        }
        [group, action, state, certificate, fingerprint]
            if group == "peer" && action == "trust" =>
        {
            let Some(certificate) = certificate.to_str() else {
                return invalid_arguments();
            };
            let Some(fingerprint) = fingerprint.to_str() else {
                return invalid_arguments();
            };
            pin_peer(Path::new(state), certificate, fingerprint)
        }
        _ => return invalid_arguments(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("howl: {error}");
            ExitCode::FAILURE
        }
    }
}

fn show_identity(state: &Path) -> io::Result<()> {
    let certificate = LocalIdentity::load_or_create(state)?.certificate();
    println!("Certificate {}", hex::encode(certificate.as_bytes()));
    println!("Fingerprint {}", hex::encode(certificate.fingerprint()));
    Ok(())
}

fn pin_peer(state: &Path, certificate: &str, fingerprint: &str) -> io::Result<()> {
    let mut bytes = [0; howl::identity::CERTIFICATE_LEN];
    let mut confirmed = [0; 32];
    hex::decode_to_slice(certificate, &mut bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid certificate hex"))?;
    hex::decode_to_slice(fingerprint, &mut confirmed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid fingerprint hex"))?;
    let certificate = PeerCertificate::from_bytes(bytes)?;
    PeerTrust::open(state)?.pin(&certificate, &confirmed)?;
    println!("Peer trusted.");
    Ok(())
}

fn invalid_arguments() -> ExitCode {
    eprintln!("Invalid arguments. Run howl --help.");
    ExitCode::from(2)
}
