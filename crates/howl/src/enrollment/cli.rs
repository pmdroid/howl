mod recovery;
mod renewal;

pub(super) use renewal::{accept as accept_records, import_peer as import_records};
pub(crate) use renewal::{peer_records, profile_records};

use std::{
    ffi::{OsStr, OsString},
    io,
    path::Path,
};

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::{
    identity::{CERTIFICATE_LEN, LocalIdentity, PeerCertificate, StateDirectory},
    node,
};

use super::{
    Authority, AuthorityHead, AuthorityRecord, AuthorityStore, Designation, DeviceCertificate,
    Enroll, Id, PairingOffer, PairingResponse, PairingTicket,
};

pub(super) const ROOT: &str = "enrollment-root-key";
pub(super) const SIGNER: &str = "enrollment-signer-key";
pub(super) const RECOVERY: &str = "enrollment-recovery-key";
const DESIGNATION: &str = "enrollment-designation";
const CERTIFICATE: &str = "enrollment-certificate";
const PEER: &str = "device";
const OFFER: &str = "offer";
const RESPONSE: &str = "response";
const INVITATION: &str = "invitation";
const RECORD_LIMIT: u64 = 128 * 1024;

pub const HELP: &str = "Usage: howl enrollment init STATE OFFLINE_KEYS\n       howl enrollment identity STATE EXCHANGE\n       howl enrollment authority STATE\n       howl enrollment offer STATE EXCHANGE VERIFIED_FINGERPRINT SEQUENCE SECRET_DIR\n       howl enrollment respond STATE EXCHANGE VERIFIED_ACCOUNT VERIFIED_HEAD VERIFIED_DESIGNATION SECRET_DIR\n       howl enrollment certify STATE EXCHANGE\n       howl enrollment certificate STATE EXCHANGE\n       howl enrollment accept STATE EXCHANGE VERIFIED_ACCOUNT VERIFIED_HEAD VERIFIED_DESIGNATION\n       howl enrollment peer STATE EXCHANGE\n       howl enrollment recover-export STATE OFFLINE_KEYS PACKAGE_DIR UNLOCK_DIR\n       howl enrollment recover NEW_STATE PACKAGE_DIR UNLOCK_DIR NEW_OFFLINE_KEYS VERIFIED_ACCOUNT VERIFIED_HEAD";

pub fn run(args: &[OsString]) -> io::Result<()> {
    match args {
        [command] if command == "--help" || command == "-h" => println!("{HELP}"),
        [command, state, offline] if command == "init" => {
            init(Path::new(state), Path::new(offline))?
        }
        [command, state, exchange] if command == "identity" => {
            let (state, exchange) = (Path::new(state), Path::new(exchange));
            separate(&[state, exchange])?;
            let peer = LocalIdentity::load_or_create(state)?.certificate();
            let exchange = StateDirectory::open(exchange)?;
            write_exact(&exchange, PEER, peer.as_bytes())?;
            println!("Fingerprint {}", hex::encode(peer.fingerprint()));
            println!("Endpoint {}", peer.endpoint());
        }
        [command, state] if command == "authority" => {
            let state = Path::new(state);
            let head = AuthorityStore::open(state)?.current()?;
            let designation = designation(&StateDirectory::open(state)?, head)?;
            show_authority(head, &designation);
        }
        [command, state, exchange, fingerprint, sequence, secret] if command == "offer" => {
            let sequence = sequence
                .to_str()
                .and_then(|value| value.parse().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| invalid("certificate sequence must be positive"))?;
            offer(
                Path::new(state),
                Path::new(exchange),
                id(fingerprint)?,
                sequence,
                Path::new(secret),
            )?;
        }
        [command, state, exchange, account, head, designation, secret] if command == "respond" => {
            respond(
                Path::new(state),
                Path::new(exchange),
                id(account)?,
                id(head)?,
                id(designation)?,
                Path::new(secret),
            )?;
        }
        [command, state, exchange] if command == "certify" => {
            certify(Path::new(state), Path::new(exchange))?;
        }
        [command, state, exchange] if command == "certificate" => {
            export_certificate(Path::new(state), Path::new(exchange))?;
        }
        [command, state, exchange, account, head, designation] if command == "accept" => {
            accept(
                Path::new(state),
                Path::new(exchange),
                id(account)?,
                id(head)?,
                id(designation)?,
            )?;
        }
        [command, state, exchange] if command == "peer" => {
            import_peer(Path::new(state), Path::new(exchange))?;
        }
        [command, state, offline, package, unlock] if command == "recover-export" => {
            recovery::export(
                Path::new(state),
                Path::new(offline),
                Path::new(package),
                Path::new(unlock),
            )?;
        }
        [command, state, package, unlock, offline, account, head] if command == "recover" => {
            recovery::recover(
                Path::new(state),
                Path::new(package),
                Path::new(unlock),
                Path::new(offline),
                id(account)?,
                id(head)?,
            )?;
        }
        _ => {
            return Err(invalid(
                "invalid enrollment arguments; run howl enrollment --help",
            ));
        }
    }
    Ok(())
}

fn init(state: &Path, offline: &Path) -> io::Result<()> {
    separate(&[state, offline])?;
    let directory = StateDirectory::open(state)?;
    let offline = StateDirectory::open(offline)?;
    let root = initialize_key(&directory, ROOT)?;
    let signer = initialize_key(&directory, SIGNER)?;
    let recovery = initialize_key(&offline, RECOVERY)?;
    let genesis = AuthorityRecord::genesis(&root, &recovery);
    let account = genesis.digest();
    let store = AuthorityStore::open(state)?;
    store.initialize(&[genesis], account, account)?;
    let head = store.current()?;
    let designation = Designation::issue(head, 1, &root, &signer, &[])?;
    write_exact(&directory, DESIGNATION, designation.as_bytes())?;
    show_authority(head, &designation);
    Ok(())
}

fn offer(
    state: &Path,
    exchange: &Path,
    fingerprint: Id,
    sequence: u64,
    secret: &Path,
) -> io::Result<()> {
    separate(&[state, exchange, secret])?;
    let directory = StateDirectory::open(state)?;
    let exchange_files = StateDirectory::open(exchange)?;
    let secret = StateDirectory::open(secret)?;
    let authority = AuthorityStore::open(state)?.load()?;
    let head = authority.head()?;
    let designation = designation(&directory, head)?;
    let signer = operator_signer(&directory)?;
    let peer = peer(&exchange_files)?;
    if peer.fingerprint() != fingerprint {
        return Err(invalid(
            "pairing candidate does not match the verified fingerprint",
        ));
    }
    AuthorityStore::open(exchange)?.initialize(authority.records(), head.account, head.digest)?;
    write_exact(&exchange_files, DESIGNATION, designation.as_bytes())?;
    let now = node::unix_time()?;
    let ticket = match exchange_files.read_bounded(OFFER, RECORD_LIMIT) {
        Ok(bytes) => {
            let offer = PairingOffer::from_bytes(&bytes)?;
            offer.verify_sequence(&designation, &peer, sequence, now)?;
            PairingTicket::load(state, &offer)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (ticket, offer) =
                PairingTicket::create(&designation, &signer, &peer, fingerprint, sequence, now)?;
            ticket.save(state)?;
            write_exact(&exchange_files, OFFER, offer.as_bytes())?;
            ticket
        }
        Err(error) => return Err(error),
    };
    write_exact(&secret, INVITATION, ticket.invitation_secret())?;
    show_authority(head, &designation);
    println!("Share the exchange and invitation through separate channels.");
    Ok(())
}

fn respond(
    state: &Path,
    exchange: &Path,
    account: Id,
    head: Id,
    expected_designation: Id,
    secret: &Path,
) -> io::Result<()> {
    separate(&[state, exchange, secret])?;
    let (_, head) = checked_authority(exchange, account, head)?;
    let exchange = StateDirectory::open(exchange)?;
    let designation = checked_designation(&exchange, head, expected_designation)?;
    let identity = LocalIdentity::load_or_create(state)?;
    let invitation = secret_record(&StateDirectory::open(secret)?, INVITATION)?;
    let offer = PairingOffer::from_bytes(&exchange.read_bounded(OFFER, RECORD_LIMIT)?)?;
    let response = offer.respond(&designation, &identity, &invitation, node::unix_time()?)?;
    let encoded = [
        &response.mac[..],
        &response.endpoint_proof,
        &response.device_proof,
    ]
    .concat();
    write_exact(&exchange, RESPONSE, &encoded)?;
    println!("Pairing response ready.");
    Ok(())
}

fn certify(state: &Path, exchange: &Path) -> io::Result<()> {
    separate(&[state, exchange])?;
    let directory = StateDirectory::open(state)?;
    let exchange = StateDirectory::open(exchange)?;
    let designation = designation(&directory, AuthorityStore::open(state)?.current()?)?;
    let offer = PairingOffer::from_bytes(&exchange.read_bounded(OFFER, RECORD_LIMIT)?)?;
    let peer = peer(&exchange)?;
    let bytes = exchange.read_bounded(RESPONSE, 160)?;
    let bytes: [u8; 160] = bytes
        .try_into()
        .map_err(|_| invalid("invalid pairing response size"))?;
    let response = PairingResponse {
        mac: bytes[..32].try_into().unwrap(),
        endpoint_proof: bytes[32..96].try_into().unwrap(),
        device_proof: bytes[96..].try_into().unwrap(),
    };
    let signer = operator_signer(&directory)?;
    let certificate = PairingTicket::load(state, &offer)?.enroll(Enroll {
        state,
        designation: &designation,
        signer: &signer,
        peer: &peer,
        offer: &offer,
        response: &response,
        now: node::unix_time()?,
    })?;
    write_exact(&exchange, CERTIFICATE, certificate.as_bytes())?;
    println!("Device certificate issued.");
    Ok(())
}

fn export_certificate(state: &Path, exchange: &Path) -> io::Result<()> {
    separate(&[state, exchange])?;
    let local = StateDirectory::open(state)?;
    let exchange = StateDirectory::open(exchange)?;
    let designation = designation(&local, AuthorityStore::open(state)?.current()?)?;
    let offer = PairingOffer::from_bytes(&exchange.read_bounded(OFFER, RECORD_LIMIT)?)?;
    let certificate = offer.issued(state, &designation, &peer(&exchange)?)?;
    write_exact(&exchange, CERTIFICATE, certificate.as_bytes())?;
    println!("Issued device certificate copied to the exchange.");
    Ok(())
}

fn accept(
    state: &Path,
    exchange: &Path,
    account: Id,
    head: Id,
    expected_designation: Id,
) -> io::Result<()> {
    separate(&[state, exchange])?;
    let (authority, head) = checked_authority(exchange, account, head)?;
    let exchange = StateDirectory::open(exchange)?;
    let designation = checked_designation(&exchange, head, expected_designation)?;
    let identity = LocalIdentity::load_or_create(state)?;
    let local = identity.certificate();
    let certificate = certificate(&exchange, &designation, &local)?;
    renewal::accept(state, &authority, &designation, &certificate, &local)?;
    println!("Device enrolled.");
    Ok(())
}

fn import_peer(state: &Path, exchange: &Path) -> io::Result<()> {
    separate(&[state, exchange])?;
    let directory = StateDirectory::open(state)?;
    let authority = AuthorityStore::open(state)?.load()?;
    let designation = designation(&directory, authority.head()?)?;
    let exchange = StateDirectory::open(exchange)?;
    let peer = peer(&exchange)?;
    let certificate = certificate(&exchange, &designation, &peer)?;
    renewal::import_peer(
        state,
        &directory,
        &authority,
        &designation,
        &certificate,
        &peer,
    )?;
    println!("Enrolled peer trusted.");
    Ok(())
}

fn checked_authority(
    exchange: &Path,
    account: Id,
    digest: Id,
) -> io::Result<(Authority, AuthorityHead)> {
    let authority = AuthorityStore::open(exchange)?.load()?;
    let head = authority.head()?;
    if head.account != account || head.digest != digest {
        return Err(invalid(
            "exchanged authority does not match the independently verified IDs",
        ));
    }
    Ok((authority, head))
}

fn designation(directory: &StateDirectory, head: AuthorityHead) -> io::Result<Designation> {
    let bytes = match profile_records(directory)? {
        Some((designation, _)) => designation,
        None => directory.read_bounded(DESIGNATION, 165_000)?,
    };
    Designation::verify(&bytes, head)
}

fn checked_designation(
    directory: &StateDirectory,
    head: AuthorityHead,
    expected: Id,
) -> io::Result<Designation> {
    let designation = designation(directory, head)?;
    if designation.digest() != expected {
        return Err(invalid(
            "exchanged designation does not match the independently verified ID",
        ));
    }
    Ok(designation)
}

fn peer(directory: &StateDirectory) -> io::Result<PeerCertificate> {
    let bytes = directory.read_bounded(PEER, CERTIFICATE_LEN as u64)?;
    PeerCertificate::from_bytes(
        bytes
            .try_into()
            .map_err(|_| invalid("invalid device identity length"))?,
    )
}

fn certificate(
    directory: &StateDirectory,
    designation: &Designation,
    peer: &PeerCertificate,
) -> io::Result<DeviceCertificate> {
    let certificate = DeviceCertificate::verify(
        &directory.read_bounded(CERTIFICATE, RECORD_LIMIT)?,
        designation,
    )?;
    if !certificate.matches(peer) {
        return Err(invalid("device certificate does not match the local keys"));
    }
    Ok(certificate)
}

fn secret_record(directory: &StateDirectory, name: &str) -> io::Result<Zeroizing<Id>> {
    let bytes = Zeroizing::new(directory.read_bounded(name, 32)?);
    let mut secret = Zeroizing::new([0; 32]);
    if bytes.len() != secret.len() {
        return Err(invalid("invalid secret record length"));
    }
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

fn initialize_key(directory: &StateDirectory, name: &str) -> io::Result<SigningKey> {
    let seed = directory.key(name)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn operator_signer(directory: &StateDirectory) -> io::Result<SigningKey> {
    load_key(directory, SIGNER)
}

fn load_key(directory: &StateDirectory, name: &str) -> io::Result<SigningKey> {
    let seed = secret_record(directory, name)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(super) fn write_exact(directory: &StateDirectory, name: &str, bytes: &[u8]) -> io::Result<()> {
    if directory.write(name, bytes)? {
        return Ok(());
    }
    let existing = Zeroizing::new(directory.read_bounded(name, bytes.len() as u64)?);
    if existing.as_slice() != bytes {
        return Err(invalid("a different enrollment record already exists"));
    }
    Ok(())
}

pub(super) fn separate(paths: &[&Path]) -> io::Result<()> {
    let mut canonical = Vec::with_capacity(paths.len());
    for path in paths {
        StateDirectory::open(path)?;
        let path = path.canonicalize()?;
        if canonical
            .iter()
            .any(|other: &std::path::PathBuf| path.starts_with(other) || other.starts_with(&path))
        {
            return Err(invalid("enrollment directories must be separate"));
        }
        canonical.push(path);
    }
    Ok(())
}

fn id(value: &OsStr) -> io::Result<Id> {
    let mut id = [0; 32];
    hex::decode_to_slice(value.as_encoded_bytes(), &mut id)
        .map_err(|_| invalid("invalid hexadecimal ID"))?;
    Ok(id)
}

fn show_authority(head: AuthorityHead, designation: &Designation) {
    println!("Account {}", hex::encode(head.account));
    println!("Authority {}", hex::encode(head.digest));
    println!("Designation {}", hex::encode(designation.digest()));
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
