use std::{io, path::Path};

use howl_envelope::MAX_RECIPIENTS as MAX_MEMBERS;
use sha2::{Digest, Sha256};

use crate::identity::{LocalIdentity, PeerCertificate, PeerTrust, StateDirectory};

const DOMAIN: &[u8] = b"howl/manual-channel/v1\0";
const MEMBER_LEN: usize = 64;
const SIGNATURE_LEN: usize = 64;
const HEADER_LEN: usize = DOMAIN.len() + 32 + 32 + 1;
pub const MAX_MANIFEST_LEN: usize = HEADER_LEN + MAX_MEMBERS * MEMBER_LEN + SIGNATURE_LEN;

pub struct Channel {
    id: [u8; 32],
    members: Vec<PeerCertificate>,
    manifest: Vec<u8>,
}

impl Channel {
    pub fn create(state: &Path, local: &LocalIdentity, peer_ids: &[[u8; 32]]) -> io::Result<Self> {
        if peer_ids.len() >= MAX_MEMBERS {
            return Err(invalid("too many channel members"));
        }
        let trust = PeerTrust::open(state)?;
        let local_certificate = local.certificate();
        let mut members = Vec::with_capacity(peer_ids.len() + 1);
        members.push(local_certificate.clone());
        for device in peer_ids {
            members.push(trust.pinned(device)?);
        }
        members.sort_unstable_by_key(|member| *member.device_id());
        if members
            .windows(2)
            .any(|pair| pair[0].device_id() == pair[1].device_id())
        {
            return Err(invalid("channel has a repeated device"));
        }

        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let mut manifest =
            Vec::with_capacity(HEADER_LEN + members.len() * MEMBER_LEN + SIGNATURE_LEN);
        manifest.extend_from_slice(DOMAIN);
        manifest.extend_from_slice(&nonce);
        manifest.extend_from_slice(local_certificate.device_id());
        manifest.push(members.len() as u8);
        for member in &members {
            manifest.extend_from_slice(member.device_id());
            manifest.extend_from_slice(&member.fingerprint());
        }
        let id = Sha256::digest(&manifest).into();
        manifest.extend_from_slice(&local.sign(&manifest));

        let channel = Self {
            id,
            members,
            manifest,
        };
        channel.persist(state)?;
        Ok(channel)
    }

    pub fn join(state: &Path, local: &LocalIdentity, manifest: &[u8]) -> io::Result<Self> {
        let channel = Self::verify(local, &PeerTrust::open(state)?, manifest)?;
        channel.persist(state)?;
        Ok(channel)
    }

    pub fn load(state: &Path, local: &LocalIdentity, id: &[u8; 32]) -> io::Result<Self> {
        let manifest =
            StateDirectory::open(state)?.read_bounded(&filename(id), MAX_MANIFEST_LEN as u64)?;
        let channel = Self::verify(local, &PeerTrust::open(state)?, &manifest)?;
        if channel.id() != id {
            return Err(invalid("stored channel ID does not match"));
        }
        Ok(channel)
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    pub fn members(&self) -> &[PeerCertificate] {
        &self.members
    }

    fn verify(local: &LocalIdentity, trust: &PeerTrust, manifest: &[u8]) -> io::Result<Self> {
        let header = manifest
            .get(..HEADER_LEN)
            .ok_or_else(|| invalid("invalid channel manifest"))?;
        if !header.starts_with(DOMAIN) {
            return Err(invalid("unsupported channel manifest"));
        }
        let owner_id = field(header, DOMAIN.len() + 32);
        let count = usize::from(header[HEADER_LEN - 1]);
        let signed_len = HEADER_LEN + count * MEMBER_LEN;
        if count == 0 || count > MAX_MEMBERS || manifest.len() != signed_len + SIGNATURE_LEN {
            return Err(invalid("invalid channel manifest length"));
        }

        let local = local.certificate();
        let (signed, signature) = manifest.split_at(signed_len);
        let id = Sha256::digest(signed).into();
        let owner = if owner_id == local.device_id() {
            local.clone()
        } else {
            trust.pinned(owner_id)?
        };
        owner.verify_signature(signed, field(signature, 0))?;

        let mut members = Vec::with_capacity(count);
        for entry in signed[HEADER_LEN..].as_chunks::<MEMBER_LEN>().0 {
            let device = field(entry, 0);
            if members
                .last()
                .is_some_and(|previous: &PeerCertificate| previous.device_id() >= device)
            {
                return Err(invalid("channel member order is invalid"));
            }
            let certificate = if device == local.device_id() {
                local.clone()
            } else {
                trust.pinned(device)?
            };
            if certificate.fingerprint() != *field(entry, 32) {
                return Err(denied(
                    "channel member does not match the pinned certificate",
                ));
            }
            members.push(certificate);
        }
        if !members
            .iter()
            .any(|member| member.device_id() == local.device_id())
        {
            return Err(denied("local device is outside the channel"));
        }
        if !members.iter().any(|member| member.device_id() == owner_id) {
            return Err(denied("channel owner is outside the channel"));
        }

        Ok(Self {
            id,
            members,
            manifest: manifest.to_vec(),
        })
    }

    fn persist(&self, state: &Path) -> io::Result<()> {
        let directory = StateDirectory::open(state)?;
        let record = filename(&self.id);
        if directory.write(&record, &self.manifest)? {
            return Ok(());
        }
        if directory.read_bounded(&record, MAX_MANIFEST_LEN as u64)? != self.manifest {
            return Err(denied(
                "a different manifest is already pinned for this channel",
            ));
        }
        Ok(())
    }
}

fn filename(id: &[u8; 32]) -> String {
    format!("channel-{}", hex::encode(id))
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> &[u8; N] {
    bytes[offset..]
        .first_chunk()
        .expect("fixed manifest layout")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
