use std::io;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use super::{
    AuthorityHead, Id,
    authority::{invalid, take},
    pairing::random,
};

const PACKAGE: &[u8] = b"howl/enrollment/v1/recovery-package\0";
const HEADER_FIELDS: usize = 32 + 32 + 8 + 12;

pub struct RecoveryPackage(Vec<u8>);

impl RecoveryPackage {
    pub fn export(head: AuthorityHead, recovery: &SigningKey) -> io::Result<(Self, Zeroizing<Id>)> {
        if recovery.verifying_key().to_bytes() != head.recovery {
            return Err(invalid("recovery key does not match the authority"));
        }
        let unlock = Zeroizing::new(random()?);
        let nonce: [u8; 12] = random()?;
        let mut record = [
            PACKAGE,
            &head.account,
            &head.recovery,
            &head.generation.to_be_bytes(),
            &nonce,
        ]
        .concat();
        let mut sealed = Zeroizing::new(recovery.to_bytes());
        let tag = Aes256Gcm::new((&*unlock).into())
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &record, &mut *sealed)
            .map_err(|_| invalid("recovery package encryption failed"))?;
        record.extend_from_slice(&*sealed);
        record.extend_from_slice(&tag);
        Ok((Self(record), unlock))
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if !bytes.starts_with(PACKAGE) || bytes.len() != PACKAGE.len() + HEADER_FIELDS + 48 {
            return Err(invalid("invalid recovery package"));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn unlock(&self, head: AuthorityHead, unlock: &Id) -> io::Result<SigningKey> {
        let fields = &self.0[PACKAGE.len()..];
        if take::<32>(fields, 0) != head.account
            || take::<32>(fields, 32) != head.recovery
            || u64::from_be_bytes(take(fields, 64)) != head.generation
        {
            return Err(invalid("recovery package does not match the authority"));
        }
        let mut seed = Zeroizing::new(take(fields, HEADER_FIELDS));
        let tag: [u8; 16] = take(fields, HEADER_FIELDS + 32);
        Aes256Gcm::new(unlock.into())
            .decrypt_in_place_detached(
                Nonce::from_slice(&fields[72..HEADER_FIELDS]),
                &self.0[..PACKAGE.len() + HEADER_FIELDS],
                &mut *seed,
                (&tag).into(),
            )
            .map_err(|_| invalid("invalid recovery unlock key or package"))?;
        let recovery = SigningKey::from_bytes(&seed);
        if recovery.verifying_key().to_bytes() != head.recovery {
            return Err(invalid("recovery package key does not match the authority"));
        }
        Ok(recovery)
    }
}
