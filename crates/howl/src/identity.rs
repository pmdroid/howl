use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh_base::{EndpointId, SecretKey};
use rustix::{
    fs::{AtFlags, Mode, OFlags, linkat, open, openat, unlinkat},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as EncryptionPublicKey, StaticSecret};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const DEVICE_RECORD: &str = "device-v1";
const KEY_RECORD_LEN: usize = 1 + 4 * 32;
const BODY_LEN: usize = 1 + 4 * 32;
pub const CERTIFICATE_LEN: usize = BODY_LEN + 2 * 64;
const CERTIFICATE_DOMAIN: &[u8] = b"howl/manual-peer/v1\0";

pub struct LocalIdentity {
    device_id: [u8; 32],
    signing: SigningKey,
    transport: SecretKey,
    encryption: StaticSecret,
}

impl LocalIdentity {
    pub fn load_or_create(directory: &Path) -> io::Result<Self> {
        let parent = StateDirectory::open(directory)?;
        let mut bytes = Zeroizing::new([0; KEY_RECORD_LEN]);
        match parent.read(DEVICE_RECORD, &mut bytes[..]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                bytes[0] = VERSION;
                getrandom::fill(&mut bytes[1..]).map_err(io::Error::other)?;
                if !parent.write(DEVICE_RECORD, &bytes[..])? {
                    parent.read(DEVICE_RECORD, &mut bytes[..])?;
                }
            }
            Err(error) => return Err(error),
        }
        if bytes[0] != VERSION {
            return Err(invalid_data("invalid local device record"));
        }

        Ok(Self {
            device_id: *field(&bytes[..], 1),
            signing: SigningKey::from_bytes(field(&bytes[..], 33)),
            transport: SecretKey::from_bytes(field(&bytes[..], 65)),
            encryption: StaticSecret::from(*field(&bytes[..], 97)),
        })
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub(crate) fn encryption_key(&self) -> &StaticSecret {
        &self.encryption
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    pub fn transport_key(&self) -> &SecretKey {
        &self.transport
    }

    pub fn certificate(&self) -> PeerCertificate {
        let mut bytes = [0; CERTIFICATE_LEN];
        bytes[0] = VERSION;
        bytes[1..33].copy_from_slice(&self.device_id);
        bytes[33..65].copy_from_slice(self.signing.verifying_key().as_bytes());
        let endpoint = self.transport.public();
        bytes[65..97].copy_from_slice(endpoint.as_bytes());
        bytes[97..BODY_LEN].copy_from_slice(EncryptionPublicKey::from(&self.encryption).as_bytes());
        let signed = signed_body(&bytes[..BODY_LEN]);
        bytes[BODY_LEN..BODY_LEN + 64].copy_from_slice(&self.signing.sign(&signed).to_bytes());
        bytes[BODY_LEN + 64..].copy_from_slice(&self.transport.sign(&signed).to_bytes());
        PeerCertificate { bytes, endpoint }
    }
}

#[derive(Clone)]
pub struct PeerCertificate {
    bytes: [u8; CERTIFICATE_LEN],
    endpoint: EndpointId,
}

impl PeerCertificate {
    pub fn from_bytes(bytes: [u8; CERTIFICATE_LEN]) -> io::Result<Self> {
        if bytes[0] != VERSION {
            return Err(invalid_data("unsupported peer certificate version"));
        }
        let signed = signed_body(&bytes[..BODY_LEN]);
        let signing_key = field(&bytes, 33);
        let endpoint_key = field(&bytes, 65);
        let encryption_key = field(&bytes, 97);
        if signing_key == endpoint_key
            || signing_key == encryption_key
            || endpoint_key == encryption_key
        {
            return Err(invalid_data("peer certificate reuses a public key"));
        }
        verify(signing_key, &signed, field(&bytes, BODY_LEN))?;
        verify(endpoint_key, &signed, field(&bytes, BODY_LEN + 64))?;
        let encryption = EncryptionPublicKey::from(*encryption_key);
        if !StaticSecret::from([1; 32])
            .diffie_hellman(&encryption)
            .was_contributory()
        {
            return Err(invalid_data("invalid peer encryption key"));
        }
        let endpoint = EndpointId::from_bytes(endpoint_key)
            .map_err(|_| invalid_data("invalid peer endpoint key"))?;
        Ok(Self { bytes, endpoint })
    }

    pub fn as_bytes(&self) -> &[u8; CERTIFICATE_LEN] {
        &self.bytes
    }

    pub fn device_id(&self) -> &[u8; 32] {
        field(&self.bytes, 1)
    }

    pub fn endpoint(&self) -> EndpointId {
        self.endpoint
    }

    pub(crate) fn manual_account_id(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"howl/manual-account/v1\0");
        digest.update(self.device_id());
        digest.finalize().into()
    }

    pub(crate) fn signing_public(&self) -> [u8; 32] {
        *field(&self.bytes, 33)
    }

    pub(crate) fn encryption_public(&self) -> [u8; 32] {
        *field(&self.bytes, 97)
    }

    pub(crate) fn verify_signature(&self, message: &[u8], signature: &[u8; 64]) -> io::Result<()> {
        verify(field(&self.bytes, 33), message, signature)
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes[..BODY_LEN]).into()
    }
}

pub struct PeerTrust {
    parent: StateDirectory,
}

impl PeerTrust {
    pub fn open(directory: &Path) -> io::Result<Self> {
        let parent = StateDirectory::open(directory)?;
        Ok(Self { parent })
    }

    pub fn pin(&self, certificate: &PeerCertificate, confirmed: &[u8; 32]) -> io::Result<()> {
        if certificate.fingerprint() != *confirmed {
            return Err(denied("peer fingerprint does not match"));
        }
        let filename = hex::encode(certificate.device_id());
        if self.parent.write(&filename, certificate.as_bytes())? {
            return Ok(());
        }
        let existing = self.pinned(certificate.device_id())?;
        if existing.as_bytes() != certificate.as_bytes() {
            return Err(denied("a different peer certificate is already pinned"));
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        device_id: &[u8; 32],
        endpoint: EndpointId,
    ) -> io::Result<PeerCertificate> {
        let certificate = self.pinned(device_id)?;
        if certificate.endpoint() != endpoint {
            return Err(denied(
                "peer endpoint does not match the pinned certificate",
            ));
        }
        Ok(certificate)
    }

    pub fn pinned(&self, device_id: &[u8; 32]) -> io::Result<PeerCertificate> {
        let filename = hex::encode(device_id);
        let mut bytes = [0; CERTIFICATE_LEN];
        self.parent.read(&filename, &mut bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                denied("peer is not pinned")
            } else {
                error
            }
        })?;
        let certificate = PeerCertificate::from_bytes(bytes)?;
        if certificate.device_id() != device_id {
            return Err(denied("peer pin does not match the requested device"));
        }
        Ok(certificate)
    }
}

pub(crate) fn verify(key: &[u8; 32], signed: &[u8], signature: &[u8; 64]) -> io::Result<()> {
    if !CompressedEdwardsY(*key)
        .decompress()
        .is_some_and(|point| point.is_torsion_free())
    {
        return Err(invalid_data("invalid peer signing key"));
    }
    let verifying =
        VerifyingKey::from_bytes(key).map_err(|_| invalid_data("invalid peer signing key"))?;
    verifying
        .verify_strict(signed, &Signature::from_bytes(signature))
        .map_err(|_| invalid_data("invalid peer certificate signature"))
}

fn signed_body(body: &[u8]) -> Vec<u8> {
    [CERTIFICATE_DOMAIN, body].concat()
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> &[u8; N] {
    bytes[offset..].first_chunk().expect("fixed record layout")
}

pub(crate) struct StateDirectory {
    path: PathBuf,
    handle: File,
}

impl StateDirectory {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let handle = File::from(open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        check_private(&handle, path, true)?;
        let containing = path.parent().filter(|value| !value.as_os_str().is_empty());
        File::open(containing.unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(Self {
            path: path.to_path_buf(),
            handle,
        })
    }

    fn read(&self, filename: &str, bytes: &mut [u8]) -> io::Result<()> {
        let mut file = self.open_private(filename)?;
        file.read_exact(bytes)?;
        if file.read(&mut [0; 1])? != 0 {
            return Err(invalid_data("unexpected state file length"));
        }
        self.handle.sync_all()
    }

    pub(crate) fn read_bounded(&self, filename: &str, maximum: u64) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.open_private(filename)?
            .take(maximum + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(invalid_data("state file is too large"));
        }
        self.handle.sync_all()?;
        Ok(bytes)
    }

    fn open_private(&self, filename: &str) -> io::Result<File> {
        let file = File::from(openat(
            &self.handle,
            filename,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        check_private(&file, &self.path.join(filename), false)?;
        Ok(file)
    }

    pub(crate) fn key(&self, filename: &str) -> io::Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0; 32]);
        match self.read(filename, &mut key[..]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                getrandom::fill(&mut key[..]).map_err(io::Error::other)?;
                if !self.write(filename, &key[..])? {
                    self.read(filename, &mut key[..])?;
                }
            }
            Err(error) => return Err(error),
        }
        Ok(key)
    }

    pub(crate) fn write(&self, filename: &str, bytes: &[u8]) -> io::Result<bool> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let staged_name = format!(".howl-{}", hex::encode(nonce));
        let mut staged = File::from(openat(
            &self.handle,
            staged_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);

        let published = (|| -> io::Result<bool> {
            check_private(&staged, &self.path.join(&staged_name), false)?;
            staged.write_all(bytes)?;
            staged.sync_all()?;
            match linkat(
                &self.handle,
                staged_name.as_str(),
                &self.handle,
                filename,
                AtFlags::empty(),
            ) {
                Ok(()) => Ok(true),
                Err(rustix::io::Errno::EXIST) => Ok(false),
                Err(error) => Err(error.into()),
            }
        })();
        let removed = unlinkat(&self.handle, staged_name.as_str(), AtFlags::empty());
        let published = published?;
        removed?;
        self.handle.sync_all()?;
        Ok(published)
    }
}

fn check_private(file: &File, path: &Path, directory: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    let expected_type = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if !expected_type || metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(denied(
            "state must be private and owned by the current user",
        ));
    }
    #[cfg(target_os = "macos")]
    if !exacl::getfacl(path, Some(exacl::AclOption::SYMLINK_ACL))?.is_empty() {
        return Err(denied(
            "state must not have an extended access control list",
        ));
    }
    let named = path.symlink_metadata()?;
    if named.dev() != metadata.dev() || named.ino() != metadata.ino() {
        return Err(denied("state path changed while opening"));
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
