use std::io;

use ed25519_dalek::{Signature, Signer, SigningKey};
use iroh_base::EndpointId;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::{PeerCertificate, verify};

use super::authority::{Authority, AuthorityHead, Id, check_signatures, invalid, sign, take};

const DESIGNATION: &[u8] = b"howl/identity/v1/membership-signer\0";
const DEVICE: &[u8] = b"howl/identity/v1/device\0";
const MAX_FLOORS: usize = 4096;
const DEVICE_FIELDS: usize = 32 * 6 + 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Floor {
    pub device: Id,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Designation {
    bytes: Vec<u8>,
    digest: Id,
    account: Id,
    signer: Id,
    root: Id,
    recovery: Id,
    sequence: u64,
    floors: Vec<Floor>,
}

impl Designation {
    pub fn issue(
        head: AuthorityHead,
        sequence: u64,
        root: &SigningKey,
        signer: &SigningKey,
        floors: &[Floor],
    ) -> io::Result<Self> {
        let count =
            u16::try_from(floors.len()).map_err(|_| invalid("too many revocation floors"))?;
        let mut body = [
            DESIGNATION,
            &head.account,
            &head.digest,
            &sequence.to_be_bytes(),
            signer.verifying_key().as_bytes(),
            &count.to_be_bytes(),
        ]
        .concat();
        for floor in floors {
            body.extend_from_slice(&floor.device);
            body.extend_from_slice(&floor.sequence.to_be_bytes());
        }
        Self::verify(&sign(body, &[root, signer]), head)
    }

    pub fn verify(bytes: &[u8], head: AuthorityHead) -> io::Result<Self> {
        let fields = bytes
            .strip_prefix(DESIGNATION)
            .filter(|fields| fields.len() >= 106 + 128)
            .ok_or_else(|| invalid("invalid membership signer record"))?;
        let account = take(fields, 0);
        let authority = take(fields, 32);
        let sequence = u64::from_be_bytes(take(fields, 64));
        let signer = take(fields, 72);
        let count = usize::from(u16::from_be_bytes(take(fields, 104)));
        let signed_len = 106 + count * 40;
        if count > MAX_FLOORS
            || fields.len() != signed_len + 128
            || account != head.account
            || authority != head.digest
            || sequence == 0
            || signer == head.root
            || signer == head.recovery
        {
            return Err(invalid("invalid membership signer fields"));
        }
        let mut floors: Vec<Floor> = Vec::with_capacity(count);
        for entry in fields[106..signed_len].as_chunks::<40>().0 {
            let device = take(entry, 0);
            let sequence = u64::from_be_bytes(take(entry, 32));
            if sequence == 0 || floors.last().is_some_and(|prior| prior.device >= device) {
                return Err(invalid("invalid membership revocation floor"));
            }
            floors.push(Floor { device, sequence });
        }
        let digest = check_signatures(bytes, DESIGNATION.len() + signed_len, &[head.root, signer])?;
        Ok(Self {
            bytes: bytes.to_vec(),
            digest,
            account,
            signer,
            root: head.root,
            recovery: head.recovery,
            sequence,
            floors,
        })
    }

    pub fn from_history(bytes: &[u8], authority: &Authority) -> io::Result<Self> {
        let fields = bytes
            .strip_prefix(DESIGNATION)
            .filter(|fields| fields.len() >= 64)
            .ok_or_else(|| invalid("invalid membership signer record"))?;
        Self::verify(bytes, authority.known_head(take(fields, 32))?)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> Id {
        self.digest
    }

    pub fn account(&self) -> Id {
        self.account
    }

    pub fn signer(&self) -> Id {
        self.signer
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn floors(&self) -> &[Floor] {
        &self.floors
    }

    pub fn revoked_through(&self, device: Id) -> u64 {
        self.floors
            .binary_search_by_key(&device, |floor| floor.device)
            .map_or(0, |i| self.floors[i].sequence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCertificate {
    bytes: Vec<u8>,
    pub digest: Id,
    pub account: Id,
    pub device: Id,
    pub sequence: u64,
    pub signing: Id,
    pub endpoint: EndpointId,
    pub encryption: Id,
}

impl DeviceCertificate {
    pub(super) fn body(
        designation: &Designation,
        peer: &PeerCertificate,
        sequence: u64,
    ) -> Vec<u8> {
        [
            DEVICE,
            &designation.account,
            &designation.digest,
            peer.device_id(),
            &sequence.to_be_bytes(),
            &peer.signing_public(),
            peer.endpoint().as_bytes(),
            &peer.encryption_public(),
        ]
        .concat()
    }

    pub(super) fn issue(
        designation: &Designation,
        signer: &SigningKey,
        device_body: Vec<u8>,
        device_proof: [u8; 64],
    ) -> io::Result<Self> {
        let mut bytes = sign(device_body, &[signer]);
        bytes.extend_from_slice(&device_proof);
        Self::verify(&bytes, designation)
    }

    pub fn verify(bytes: &[u8], designation: &Designation) -> io::Result<Self> {
        let fields = bytes
            .strip_prefix(DEVICE)
            .filter(|fields| fields.len() == DEVICE_FIELDS + 128)
            .ok_or_else(|| invalid("invalid device record"))?;
        let account = take(fields, 0);
        let owner_designation = take(fields, 32);
        let device = take(fields, 64);
        let sequence = u64::from_be_bytes(take(fields, 96));
        let signing = take(fields, 104);
        let endpoint_key = take(fields, 136);
        let encryption = take(fields, 168);
        if account != designation.account
            || owner_designation != designation.digest
            || sequence <= designation.revoked_through(device)
            || [signing, endpoint_key, encryption].into_iter().any(|key| {
                [designation.signer, designation.root, designation.recovery].contains(&key)
            })
            || signing == endpoint_key
            || signing == encryption
            || encryption == endpoint_key
            || !StaticSecret::from([1; 32])
                .diffie_hellman(&PublicKey::from(encryption))
                .was_contributory()
        {
            return Err(invalid("invalid device record fields"));
        }
        let endpoint = EndpointId::from_bytes(&endpoint_key)
            .map_err(|_| invalid("invalid device endpoint key"))?;
        let digest = check_signatures(
            bytes,
            DEVICE.len() + DEVICE_FIELDS,
            &[designation.signer, signing],
        )?;
        Ok(Self {
            bytes: bytes.to_vec(),
            digest,
            account,
            device,
            sequence,
            signing,
            endpoint,
            encryption,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn matches(&self, peer: &PeerCertificate) -> bool {
        self.device == *peer.device_id()
            && self.signing == peer.signing_public()
            && self.endpoint == peer.endpoint()
            && self.encryption == peer.encryption_public()
    }
}

const REVOKE: &[u8] = b"howl/identity/v1/device-revoke\0";

pub fn revoke(designation: &Designation, signer: &SigningKey, floor: Floor) -> io::Result<Vec<u8>> {
    let mut body = [
        REVOKE,
        &designation.account,
        &designation.digest,
        &floor.device,
        &floor.sequence.to_be_bytes(),
    ]
    .concat();
    let proof: Signature = signer.sign(&body);
    body.extend_from_slice(&proof.to_bytes());
    verify_revocation(designation, &body)?;
    Ok(body)
}

pub fn verify_revocation(designation: &Designation, bytes: &[u8]) -> io::Result<Floor> {
    let fields = bytes
        .strip_prefix(REVOKE)
        .filter(|fields| fields.len() == 168)
        .ok_or_else(|| invalid("invalid device revocation"))?;
    let sequence = u64::from_be_bytes(take(fields, 96));
    if take::<32>(fields, 0) != designation.account
        || take::<32>(fields, 32) != designation.digest
        || sequence == 0
    {
        return Err(invalid("revocation does not match current designation"));
    }
    verify(
        &designation.signer,
        &bytes[..REVOKE.len() + 104],
        &take(fields, 104),
    )?;
    Ok(Floor {
        device: take(fields, 64),
        sequence,
    })
}

pub(super) fn digest(bytes: &[u8]) -> Id {
    Sha256::digest(bytes).into()
}
