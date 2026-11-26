mod wire;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use curve25519_dalek::edwards::CompressedEdwardsY;
pub use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, AesGcm128},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng, TryRngCore};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const ALPN: &[u8] = b"howl/mesh/1";
pub const MAX_FRAME_SIZE: usize = 77_112;
pub const MAX_RECIPIENTS: usize = 64;

const PAYLOAD_DOMAIN: &[u8] = b"howl/payload/v1\0";
const WRAP_DOMAIN: &[u8] = b"howl/wrap/v1\0";
const SIGN_DOMAIN: &[u8] = b"howl/envelope/v1\0";
const PAYLOAD_NONCE: [u8; 12] = [0; 12];
const KEY_SIZE: usize = 32;
const TAG_SIZE: usize = 16;
const WRAP_SIZE: usize = KEY_SIZE * 2 + TAG_SIZE;

type HpkeKem = X25519HkdfSha256;

pub type Id = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeviceAddress {
    pub account: Id,
    pub device: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Intent {
    Chat = 1,
    Wake = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body<Text> {
    Chat(Text),
    Wake { session: Id, text: Text },
}

impl<Text> Body<Text> {
    fn intent(&self) -> Intent {
        match self {
            Self::Chat(_) => Intent::Chat,
            Self::Wake { .. } => Intent::Wake,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Routing {
    pub channel: Id,
    pub sender: DeviceAddress,
    pub epoch: u64,
    pub sequence: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub routing: Routing,
    pub intent: Intent,
    pub signing_key_id: Id,
    pub message_id: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recipient {
    pub address: DeviceAddress,
    pub encryption_key: [u8; 32],
}

pub struct RecipientSecret {
    address: DeviceAddress,
    key: <HpkeKem as Kem>::PrivateKey,
}

impl RecipientSecret {
    pub fn from_bytes(address: DeviceAddress, secret: &[u8; 32]) -> Result<Self, Error> {
        let key = <HpkeKem as Kem>::PrivateKey::from_bytes(secret).map_err(|_| Error::Key)?;
        Ok(Self { address, key })
    }

    pub fn public_recipient(&self) -> Recipient {
        Recipient {
            address: self.address,
            encryption_key: HpkeKem::sk_to_pk(&self.key).to_bytes().into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedSender {
    pub address: DeviceAddress,
    pub signing_key: [u8; 32],
    pub chat: bool,
    pub wake: bool,
}

pub struct ReceivePolicy<'a> {
    pub channel: Id,
    pub epoch: u64,
    pub now: u64,
    pub sender: AuthorizedSender,
    pub authorized_recipients: &'a [Recipient],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedEnvelope {
    pub metadata: Metadata,
    pub body: Body<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Encoding,
    Context,
    Unauthorized,
    Stale,
    Key,
    Signature,
    Commitment,
    Ciphertext,
    Randomness,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "invalid envelope encoding",
            Self::Context => "unexpected channel or membership epoch",
            Self::Unauthorized => "sender or recipient lacks authorization",
            Self::Stale => "wake is outside its validity window",
            Self::Key => "invalid public or private key",
            Self::Signature => "invalid envelope signature",
            Self::Commitment => "invalid content key commitment",
            Self::Ciphertext => "invalid encrypted envelope data",
            Self::Randomness => "system entropy unavailable",
        })
    }
}

impl std::error::Error for Error {}

pub fn seal(
    routing: Routing,
    body: Body<&str>,
    signer: &SigningKey,
    recipients: &[Recipient],
) -> Result<Vec<u8>, Error> {
    let intent = body.intent();
    wire::validate_routing(routing, intent)?;
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(Error::Encoding);
    }
    let mut recipients = recipients.to_vec();
    recipients.sort_unstable_by_key(|recipient| recipient.address);
    if recipients
        .windows(2)
        .any(|pair| pair[0].address == pair[1].address)
    {
        return Err(Error::Encoding);
    }

    let mut padded = wire::pad(body)?;
    let mut rng = ChaCha20Rng::try_from_rng(&mut OsRng).map_err(|_| Error::Randomness)?;
    let mut secret = Zeroizing::new([0; KEY_SIZE]);
    let mut message_id = [0; KEY_SIZE];
    OsRng
        .try_fill_bytes(&mut *secret)
        .map_err(|_| Error::Randomness)?;
    OsRng
        .try_fill_bytes(&mut message_id)
        .map_err(|_| Error::Randomness)?;
    let (key, commitment) = derive(&secret, &message_id);

    let metadata = Metadata {
        routing,
        intent,
        signing_key_id: key_id(b"device-signing", signer.verifying_key().as_bytes()),
        message_id,
    };
    let header = wire::encode_header(metadata, &commitment, &recipients);
    let header_digest = Sha256::digest(&header);
    let mut frame = header.clone();
    for recipient in recipients {
        let public = <HpkeKem as Kem>::PublicKey::from_bytes(&recipient.encryption_key)
            .map_err(|_| Error::Key)?;
        let (encapsulation, mut context) = hpke::setup_sender::<AesGcm128, HkdfSha256, HpkeKem, _>(
            &OpModeS::Base,
            &public,
            WRAP_DOMAIN,
            &mut rng,
        )
        .map_err(|_| Error::Key)?;
        let aad = joined(&header_digest, &wire::encode_recipient(recipient));
        let mut wrapped = Zeroizing::new(*secret);
        let tag = context
            .seal_in_place_detached(&mut *wrapped, &aad)
            .map_err(|_| Error::Ciphertext)?;
        frame.extend_from_slice(&encapsulation.to_bytes());
        frame.extend_from_slice(&*wrapped);
        frame.extend_from_slice(&tag.to_bytes());
    }

    let cipher = Aes256Gcm::new((&*key).into());
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&PAYLOAD_NONCE),
            &joined(PAYLOAD_DOMAIN, &header),
            &mut padded,
        )
        .map_err(|_| Error::Ciphertext)?;
    let ciphertext_len = (padded.len() + TAG_SIZE) as u32;
    frame.extend_from_slice(&ciphertext_len.to_be_bytes());
    frame.extend_from_slice(&padded);
    frame.extend_from_slice(&tag);
    let signature = signer.sign(&joined(SIGN_DOMAIN, &frame));
    frame.extend_from_slice(&signature.to_bytes());
    Ok(frame)
}

pub fn inspect_unverified(frame: &[u8]) -> Result<Metadata, Error> {
    Ok(wire::parse(frame)?.metadata)
}

pub fn open(
    frame: &[u8],
    policy: &ReceivePolicy<'_>,
    receiver: &RecipientSecret,
) -> Result<OpenedEnvelope, Error> {
    let decoded = wire::parse(frame)?;
    let metadata = decoded.metadata;
    let routing = metadata.routing;
    if routing.channel != policy.channel || routing.epoch != policy.epoch {
        return Err(Error::Context);
    }
    if routing.sender != policy.sender.address
        || metadata.signing_key_id != key_id(b"device-signing", &policy.sender.signing_key)
        || !match metadata.intent {
            Intent::Chat => policy.sender.chat,
            Intent::Wake => policy.sender.wake,
        }
    {
        return Err(Error::Unauthorized);
    }
    if metadata.intent == Intent::Wake
        && (policy.now < routing.created_at.saturating_sub(30) || policy.now >= routing.expires_at)
    {
        return Err(Error::Stale);
    }

    let signing_key = &policy.sender.signing_key;
    if !is_canonical_point(signing_key, true) {
        return Err(Error::Key);
    }
    let verify_key = VerifyingKey::from_bytes(signing_key).map_err(|_| Error::Key)?;
    let signature = Signature::from_bytes(decoded.signature);
    if !is_canonical_point(signature.r_bytes(), false) {
        return Err(Error::Signature);
    }
    verify_key
        .verify_strict(&joined(SIGN_DOMAIN, decoded.signed), &signature)
        .map_err(|_| Error::Signature)?;

    let local = receiver.public_recipient();
    let local_id = key_id(b"device-encryption", &local.encryption_key);
    let mut local_wrap = None;
    for (index, (triple, address, id)) in decoded.recipients().enumerate() {
        let recipient_valid = policy.authorized_recipients.iter().any(|recipient| {
            recipient.address == address
                && key_id(b"device-encryption", &recipient.encryption_key) == id
        });
        if !recipient_valid {
            return Err(Error::Unauthorized);
        }
        if address == local.address && id == local_id {
            local_wrap = Some((triple, &decoded.wraps[index * WRAP_SIZE..][..WRAP_SIZE]));
        }
    }
    let (triple, wrap) = local_wrap.ok_or(Error::Unauthorized)?;
    let encapsulation = <HpkeKem as Kem>::EncappedKey::from_bytes(&wrap[..KEY_SIZE])
        .map_err(|_| Error::Ciphertext)?;
    let tag =
        AeadTag::<AesGcm128>::from_bytes(&wrap[2 * KEY_SIZE..]).map_err(|_| Error::Ciphertext)?;
    let mut secret = Zeroizing::new([0; KEY_SIZE]);
    secret.copy_from_slice(&wrap[KEY_SIZE..2 * KEY_SIZE]);
    let mut context = hpke::setup_receiver::<AesGcm128, HkdfSha256, HpkeKem>(
        &OpModeR::Base,
        &receiver.key,
        &encapsulation,
        WRAP_DOMAIN,
    )
    .map_err(|_| Error::Ciphertext)?;
    let aad = joined(&Sha256::digest(decoded.header), triple);
    context
        .open_in_place_detached(&mut *secret, &aad, &tag)
        .map_err(|_| Error::Ciphertext)?;

    let (key, commitment) = derive(&secret, &metadata.message_id);
    if !bool::from(commitment.ct_eq(decoded.commitment)) {
        return Err(Error::Commitment);
    }
    let cipher = Aes256Gcm::new((&*key).into());
    let (ciphertext, tag) = decoded
        .ciphertext
        .split_at(decoded.ciphertext.len() - TAG_SIZE);
    let mut padded = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&PAYLOAD_NONCE),
            &joined(PAYLOAD_DOMAIN, decoded.header),
            &mut padded,
            tag.into(),
        )
        .map_err(|_| Error::Ciphertext)?;
    let body = wire::unpad(metadata.intent, &padded)?;
    Ok(OpenedEnvelope { metadata, body })
}

fn derive(secret: &[u8; KEY_SIZE], message_id: &Id) -> (Zeroizing<[u8; KEY_SIZE]>, Id) {
    let kdf = Hkdf::<Sha512>::new(Some(message_id), secret);
    let mut key = Zeroizing::new([0; KEY_SIZE]);
    let mut commitment = [0; KEY_SIZE];
    kdf.expand(b"\x04\x78DERIVEKEY", &mut *key)
        .expect("32-byte HKDF output");
    kdf.expand(b"COMMITKEY", &mut commitment)
        .expect("32-byte HKDF output");
    (key, commitment)
}

fn key_id(role: &[u8], key: &[u8; 32]) -> Id {
    let mut digest = Sha256::new();
    digest.update(b"howl/key/v1/");
    digest.update(role);
    digest.update([0]);
    digest.update(key);
    digest.finalize().into()
}

fn is_canonical_point(bytes: &[u8; 32], require_prime_order: bool) -> bool {
    CompressedEdwardsY(*bytes)
        .decompress()
        .is_some_and(|point| {
            point.compress().as_bytes() == bytes
                && (!require_prime_order || (point.is_torsion_free() && !point.is_small_order()))
        })
}

fn joined(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(first.len() + second.len());
    result.extend_from_slice(first);
    result.extend_from_slice(second);
    result
}
