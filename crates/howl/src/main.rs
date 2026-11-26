use std::{env, io, path::Path, process::ExitCode};

use howl::{
    HELP,
    channel::{Channel, MAX_MANIFEST_LEN},
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
        [group, action, state]
            if (group == "identity" && action == "show")
                || (group == "mesh" && action == "init") =>
        {
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
        [group, action, state, peer_ids @ ..] if group == "channel" && action == "create" => {
            create_channel(Path::new(state), peer_ids)
        }
        [group, action, state, manifest] if group == "channel" && action == "join" => {
            let Some(manifest) = manifest.to_str() else {
                return invalid_arguments();
            };
            join_channel(Path::new(state), manifest)
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
    println!("Device {}", hex::encode(certificate.device_id()));
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

fn create_channel(state: &Path, peers: &[std::ffi::OsString]) -> io::Result<()> {
    let peers = peers
        .iter()
        .map(|peer| parse_id(peer))
        .collect::<io::Result<Vec<_>>>()?;
    let identity = LocalIdentity::load_or_create(state)?;
    let channel = Channel::create(state, &identity, &peers)?;
    println!("Channel {}", hex::encode(channel.id()));
    println!("Manifest {}", hex::encode(channel.manifest()));
    Ok(())
}

fn join_channel(state: &Path, manifest: &str) -> io::Result<()> {
    if manifest.len() > MAX_MANIFEST_LEN * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "channel manifest is too large",
        ));
    }
    let manifest = hex::decode(manifest)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid channel manifest hex"))?;
    let identity = LocalIdentity::load_or_create(state)?;
    let channel = Channel::join(state, &identity, &manifest)?;
    println!("Channel {}", hex::encode(channel.id()));
    Ok(())
}

fn parse_id(value: &std::ffi::OsStr) -> io::Result<[u8; 32]> {
    let mut id = [0; 32];
    hex::decode_to_slice(value.as_encoded_bytes(), &mut id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hex ID"))?;
    Ok(id)
}

fn invalid_arguments() -> ExitCode {
    eprintln!("Invalid arguments. Run howl --help.");
    ExitCode::from(2)
}
