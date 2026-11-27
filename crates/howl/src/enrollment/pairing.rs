use std::{io, path::Path};

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::AesGcm128, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use sha2_10::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::identity::{LocalIdentity, PeerCertificate, StateDirectory, verify};

use super::{
    Designation, DeviceCertificate,
    authority::{Id, check_signatures, invalid, sign, take},
    membership::digest,
};

const OFFER: &[u8] = b"howl/enrollment/v1/offer\0";
const CHALLENGE: &[u8] = b"howl/enrollment/v1/encryption-challenge\0";
const PROOF: &[u8] = b"howl/enrollment/v1/proof\0";
const MAX_LIFETIME: u64 = 600;
const OFFER_FIELDS: usize = 128 + 24 + 32 + 48;
type HpkeKem = X25519HkdfSha256;

pub struct PairingTicket {
    nonce: Id,
    secret: Zeroizing<Id>,
    challenge: Zeroizing<Id>,
}

pub struct PairingOffer(Vec<u8>);

pub struct PairingResponse {
    pub mac: Id,
    pub endpoint_proof: [u8; 64],
    pub device_proof: [u8; 64],
}

struct CheckedOffer<'a> {
    nonce: Id,
    sequence: u64,
    wrapping: &'a [u8],
    proof_context: Id,
}

impl PairingTicket {
    pub fn create(
        designation: &Designation,
        signer: &SigningKey,
        peer: &PeerCertificate,
        fingerprint: Id,
        sequence: u64,
        now: u64,
    ) -> io::Result<(Self, PairingOffer)> {
        if peer.fingerprint() != fingerprint
            || sequence <= designation.revoked_through(*peer.device_id())
        {
            return Err(invalid(
                "pairing candidate does not match the approved device",
            ));
        }
        let nonce = random()?;
        let secret = Zeroizing::new(random()?);
        let challenge = Zeroizing::new(random()?);
        let expiry = now
            .checked_add(MAX_LIFETIME)
            .ok_or_else(|| invalid("pairing time overflow"))?;
        let mut body = [
            OFFER,
            &designation.account(),
            &designation.digest(),
            &fingerprint,
            &nonce,
            &sequence.to_be_bytes(),
            &now.to_be_bytes(),
            &expiry.to_be_bytes(),
        ]
        .concat();
        let encryption = <HpkeKem as Kem>::PublicKey::from_bytes(&peer.encryption_public())
            .map_err(|_| invalid("invalid pairing encryption key"))?;
        let mut rng = ChaCha20Rng::try_from_rng(&mut OsRng).map_err(io::Error::other)?;
        let (encapped, mut context) = hpke::setup_sender::<AesGcm128, HkdfSha256, HpkeKem, _>(
            &OpModeS::Base,
            &encryption,
            CHALLENGE,
            &mut rng,
        )
        .map_err(|_| invalid("invalid pairing encryption key"))?;
        let wrapped = context
            .seal(&*challenge, &body)
            .map_err(|_| invalid("pairing challenge encryption failed"))?;
        body.extend_from_slice(&encapped.to_bytes());
        body.extend_from_slice(&wrapped);
        let offer = PairingOffer(sign(body, &[signer]));
        offer.check(designation, peer, now)?;
        Ok((
            Self {
                nonce,
                secret,
                challenge,
            },
            offer,
        ))
    }

    pub fn invitation_secret(&self) -> &Id {
        &self.secret
    }

    pub fn save(&self, state: &Path) -> io::Result<()> {
        let mut bytes = Zeroizing::new([0; 64]);
        bytes[..32].copy_from_slice(&*self.secret);
        bytes[32..].copy_from_slice(&*self.challenge);
        let destination = StateDirectory::open(state)?;
        if !destination.write(&format!("pairing-{}", hex::encode(self.nonce)), &*bytes)? {
            return Err(invalid("pairing ticket already exists"));
        }
        Ok(())
    }

    pub fn load(state: &Path, offer: &PairingOffer) -> io::Result<Self> {
        let nonce = take(offer.as_bytes(), OFFER.len() + 96);
        let destination = StateDirectory::open(state)?;
        let bytes = Zeroizing::new(
            destination.read_bounded(&format!("pairing-{}", hex::encode(nonce)), 64)?,
        );
        if bytes.len() != 64 {
            return Err(invalid("invalid local pairing ticket"));
        }
        Ok(Self {
            nonce,
            secret: Zeroizing::new(take(&bytes, 0)),
            challenge: Zeroizing::new(take(&bytes, 32)),
        })
    }

    pub fn enroll(&self, input: Enroll<'_>) -> io::Result<DeviceCertificate> {
        let checked = input
            .offer
            .check(input.designation, input.peer, input.now)?;
        let response = input.response;
        if checked.nonce != self.nonce
            || !bool::from(
                proof_mac(&self.secret, &self.challenge, checked.proof_context)
                    .ct_eq(&response.mac),
            )
        {
            return Err(invalid("invalid pairing invitation proof"));
        }
        verify(
            input.peer.endpoint().as_bytes(),
            &proof_bytes(checked.proof_context, response.mac),
            &response.endpoint_proof,
        )?;
        let certificate = DeviceCertificate::issue(
            input.designation,
            input.signer,
            DeviceCertificate::body(input.designation, input.peer, checked.sequence),
            response.device_proof,
        )?;
        let state = StateDirectory::open(input.state)?;
        if !state.write(
            &format!("pairing-used-{}", hex::encode(self.nonce)),
            certificate.as_bytes(),
        )? {
            return Err(invalid("pairing invitation has already been used"));
        }
        Ok(certificate)
    }
}

pub struct Enroll<'a> {
    pub state: &'a Path,
    pub designation: &'a Designation,
    pub signer: &'a SigningKey,
    pub peer: &'a PeerCertificate,
    pub offer: &'a PairingOffer,
    pub response: &'a PairingResponse,
    pub now: u64,
}

impl PairingOffer {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if !bytes.starts_with(OFFER) || bytes.len() != OFFER.len() + OFFER_FIELDS + 64 {
            return Err(invalid("invalid pairing offer"));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn respond(
        &self,
        designation: &Designation,
        identity: &LocalIdentity,
        secret: &Id,
        now: u64,
    ) -> io::Result<PairingResponse> {
        let peer = identity.certificate();
        let checked = self.check(designation, &peer, now)?;
        let key = <HpkeKem as Kem>::PrivateKey::from_bytes(&identity.encryption_key().to_bytes())
            .map_err(|_| invalid("invalid pairing encryption key"))?;
        let encapped = <HpkeKem as Kem>::EncappedKey::from_bytes(&checked.wrapping[..32])
            .map_err(|_| invalid("invalid wrapped pairing challenge"))?;
        let mut context = hpke::setup_receiver::<AesGcm128, HkdfSha256, HpkeKem>(
            &OpModeR::Base,
            &key,
            &encapped,
            CHALLENGE,
        )
        .map_err(|_| invalid("invalid wrapped pairing challenge"))?;
        let challenge = Zeroizing::new(
            context
                .open(&checked.wrapping[32..], &self.0[..OFFER.len() + 152])
                .map_err(|_| invalid("invalid wrapped pairing challenge"))?,
        );
        let mac = proof_mac(secret, &take(&challenge, 0), checked.proof_context);
        let device_body = DeviceCertificate::body(designation, &peer, checked.sequence);
        Ok(PairingResponse {
            mac,
            endpoint_proof: identity
                .transport_key()
                .sign(&proof_bytes(checked.proof_context, mac))
                .to_bytes(),
            device_proof: identity.sign(&device_body),
        })
    }

    fn check(
        &self,
        designation: &Designation,
        peer: &PeerCertificate,
        now: u64,
    ) -> io::Result<CheckedOffer<'_>> {
        let fields = &self.0[OFFER.len()..OFFER.len() + OFFER_FIELDS];
        let sequence = u64::from_be_bytes(take(fields, 128));
        let created = u64::from_be_bytes(take(fields, 136));
        let expiry = u64::from_be_bytes(take(fields, 144));
        if take::<32>(fields, 0) != designation.account()
            || take::<32>(fields, 32) != designation.digest()
            || take::<32>(fields, 64) != peer.fingerprint()
            || sequence <= designation.revoked_through(*peer.device_id())
            || now < created
            || now >= expiry
            || expiry.saturating_sub(created) > MAX_LIFETIME
        {
            return Err(invalid(
                "pairing offer does not match the active invitation",
            ));
        }
        check_signatures(&self.0, OFFER.len() + OFFER_FIELDS, &[designation.signer()])?;
        Ok(CheckedOffer {
            nonce: take(fields, 96),
            sequence,
            wrapping: &fields[152..],
            proof_context: digest(&self.0),
        })
    }
}

fn proof_bytes(context: Id, mac: Id) -> Vec<u8> {
    [PROOF, &context, &mac].concat()
}

fn proof_mac(secret: &Id, challenge: &Id, context: Id) -> Id {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("fixed-size MAC key");
    mac.update(PROOF);
    mac.update(challenge);
    mac.update(&context);
    mac.finalize().into_bytes().into()
}

pub(super) fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}
