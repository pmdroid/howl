use std::{collections::BTreeMap, io};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::identity::verify;

pub type Id = [u8; 32];

const GENESIS: &[u8] = b"howl/identity/v1/genesis\0";
const ROTATE: &[u8] = b"howl/identity/v1/rotate\0";
const RECOVER: &[u8] = b"howl/identity/v1/recover\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityHead {
    pub account: Id,
    pub digest: Id,
    pub generation: u64,
    pub sequence: u64,
    pub root: Id,
    pub recovery: Id,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRecord(Vec<u8>);

struct AuthorityEntry {
    head: AuthorityHead,
    successor: Option<Id>,
}

pub struct Authority {
    head: AuthorityHead,
    entries: BTreeMap<Id, AuthorityEntry>,
    records: Vec<AuthorityRecord>,
    forked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Import {
    Applied,
    Repeated,
    Fork,
}

impl AuthorityRecord {
    pub fn genesis(root: &SigningKey, recovery: &SigningKey) -> Self {
        let root_public = root.verifying_key().to_bytes();
        let recovery_public = recovery.verifying_key().to_bytes();
        let body = [GENESIS, &root_public, &recovery_public].concat();
        Self(sign(body, &[root, recovery]))
    }

    pub fn rotate(head: AuthorityHead, root: &SigningKey, next: &SigningKey) -> io::Result<Self> {
        let sequence = next_counter(head.sequence)?;
        let mut body = successor(ROTATE, head, head.generation, sequence);
        body.extend_from_slice(next.verifying_key().as_bytes());
        Ok(Self(sign(body, &[root, next])))
    }

    pub fn recover(
        head: AuthorityHead,
        recovery: &SigningKey,
        next_root: &SigningKey,
        next_recovery: &SigningKey,
    ) -> io::Result<Self> {
        let mut body = successor(RECOVER, head, next_counter(head.generation)?, 0);
        body.extend_from_slice(next_root.verifying_key().as_bytes());
        body.extend_from_slice(next_recovery.verifying_key().as_bytes());
        Ok(Self(sign(body, &[recovery, next_root, next_recovery])))
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (prefix, body, proofs) = if bytes.starts_with(GENESIS) {
            (GENESIS, 64, 2)
        } else if bytes.starts_with(ROTATE) {
            (ROTATE, 112, 2)
        } else if bytes.starts_with(RECOVER) {
            (RECOVER, 144, 3)
        } else {
            return Err(invalid("unknown authority record"));
        };
        if bytes.len() != prefix.len() + body + 64 * proofs {
            return Err(invalid("invalid authority record length"));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn digest(&self) -> Id {
        let proofs = if self.0.starts_with(RECOVER) { 3 } else { 2 };
        Sha256::digest(&self.0[..self.0.len() - 64 * proofs]).into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn checked_genesis(&self) -> io::Result<AuthorityHead> {
        let body = self
            .0
            .strip_prefix(GENESIS)
            .ok_or_else(|| invalid("authority must start at genesis"))?;
        let root = take(body, 0);
        let recovery = take(body, 32);
        if root == recovery {
            return Err(invalid("authority keys must be independent"));
        }
        let digest = check_signatures(&self.0, GENESIS.len() + 64, &[root, recovery])?;
        Ok(AuthorityHead {
            account: digest,
            digest,
            generation: 0,
            sequence: 0,
            root,
            recovery,
        })
    }

    fn predecessor(&self) -> io::Result<Id> {
        let body = self
            .0
            .strip_prefix(ROTATE)
            .or_else(|| self.0.strip_prefix(RECOVER))
            .ok_or_else(|| invalid("unexpected authority genesis"))?;
        Ok(take(body, 32))
    }

    fn checked_successor(&self, old: AuthorityHead) -> io::Result<AuthorityHead> {
        let (body, prefix, is_recovery) = match self.0.strip_prefix(ROTATE) {
            Some(body) => (body, ROTATE, false),
            None => (
                self.0
                    .strip_prefix(RECOVER)
                    .ok_or_else(|| invalid("unknown authority successor"))?,
                RECOVER,
                true,
            ),
        };
        if take::<32>(body, 0) != old.account || take::<32>(body, 32) != old.digest {
            return Err(invalid("authority successor does not match predecessor"));
        }
        let generation = u64::from_be_bytes(take(body, 64));
        let sequence = u64::from_be_bytes(take(body, 72));
        let root = take(body, 80);
        let (digest, recovery) = if is_recovery {
            let recovery = take(body, 112);
            if generation != next_counter(old.generation)? || sequence != 0 || recovery == old.root
            {
                return Err(invalid("invalid recovery succession"));
            }
            let digest =
                check_signatures(&self.0, prefix.len() + 144, &[old.recovery, root, recovery])?;
            (digest, recovery)
        } else {
            if generation != old.generation || sequence != next_counter(old.sequence)? {
                return Err(invalid("invalid root rotation"));
            }
            let digest = check_signatures(&self.0, prefix.len() + 112, &[old.root, root])?;
            (digest, old.recovery)
        };
        if root == old.root || root == recovery || root == old.recovery {
            return Err(invalid("root key was reused"));
        }
        Ok(AuthorityHead {
            account: old.account,
            digest,
            generation,
            sequence,
            root,
            recovery,
        })
    }
}

impl Authority {
    pub fn import(
        records: impl IntoIterator<Item = AuthorityRecord>,
        pinned_account: Id,
        pinned_head: Id,
    ) -> io::Result<Self> {
        let mut records = records.into_iter();
        let genesis = records
            .next()
            .ok_or_else(|| invalid("missing authority genesis"))?;
        let head = genesis.checked_genesis()?;
        if head.account != pinned_account {
            return Err(invalid("authority account does not match the pairing pin"));
        }
        let mut authority = Self {
            head,
            entries: BTreeMap::from([(
                head.digest,
                AuthorityEntry {
                    head,
                    successor: None,
                },
            )]),
            records: vec![genesis],
            forked: false,
        };
        for record in records {
            authority.apply(record)?;
        }
        if authority.head.digest != pinned_head {
            return Err(invalid("authority head does not match the pairing pin"));
        }
        Ok(authority)
    }

    pub fn account(&self) -> Id {
        self.head.account
    }

    pub fn head(&self) -> io::Result<AuthorityHead> {
        if self.forked {
            return Err(invalid("authority has a verified fork"));
        }
        Ok(self.head)
    }

    pub fn known_head(&self, digest: Id) -> io::Result<AuthorityHead> {
        self.head()?;
        self.entries
            .get(&digest)
            .map(|entry| entry.head)
            .ok_or_else(|| invalid("authority head is outside the pinned history"))
    }

    pub fn records(&self) -> &[AuthorityRecord] {
        &self.records
    }

    pub fn apply(&mut self, record: AuthorityRecord) -> io::Result<Import> {
        if self.records.contains(&record) {
            return Ok(Import::Repeated);
        }
        let previous = record.predecessor()?;
        let entry = self
            .entries
            .get(&previous)
            .ok_or_else(|| invalid("unknown predecessor authority head"))?;
        let next = record.checked_successor(entry.head)?;
        for ancestor in self.ancestors(previous) {
            if next.root == ancestor.root
                || next.root == ancestor.recovery
                || next.recovery == ancestor.root
                || (next.recovery != entry.head.recovery && next.recovery == ancestor.recovery)
            {
                return Err(invalid("historical authority key was reused"));
            }
        }
        if let Some(existing) = entry.successor {
            if existing != next.digest {
                self.forked = true;
                self.records.push(record);
                return Ok(Import::Fork);
            }
            return Err(invalid("authority record has conflicting proof bytes"));
        }
        self.entries.get_mut(&previous).unwrap().successor = Some(next.digest);
        self.entries.insert(
            next.digest,
            AuthorityEntry {
                head: next,
                successor: None,
            },
        );
        self.records.push(record);
        self.head = next;
        Ok(Import::Applied)
    }

    fn ancestors(&self, from: Id) -> impl Iterator<Item = AuthorityHead> {
        self.entries
            .values()
            .map(|entry| entry.head)
            .filter(move |head| {
                let current = self.entries[&from].head;
                (head.generation, head.sequence) <= (current.generation, current.sequence)
            })
    }
}

pub(super) fn take<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    *bytes[offset..]
        .first_chunk()
        .expect("validated record length")
}

pub(super) fn sign(mut body: Vec<u8>, keys: &[&SigningKey]) -> Vec<u8> {
    let prefix = body.len();
    for key in keys {
        let proof: ed25519_dalek::Signature = key.sign(&body[..prefix]);
        body.extend_from_slice(&proof.to_bytes());
    }
    body
}

pub(super) fn check_signatures(bytes: &[u8], body: usize, keys: &[Id]) -> io::Result<Id> {
    for (slot, key) in keys.iter().enumerate() {
        verify(key, &bytes[..body], &take(bytes, body + slot * 64))?;
    }
    Ok(Sha256::digest(&bytes[..body]).into())
}

fn successor(prefix: &[u8], head: AuthorityHead, generation: u64, sequence: u64) -> Vec<u8> {
    [
        prefix,
        &head.account,
        &head.digest,
        &generation.to_be_bytes(),
        &sequence.to_be_bytes(),
    ]
    .concat()
}

fn next_counter(n: u64) -> io::Result<u64> {
    n.checked_add(1)
        .ok_or_else(|| invalid("authority counter overflow"))
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    #[test]
    fn accepts_pinned_rotation_and_recovery_chain_and_rejects_rollback() {
        let genesis = AuthorityRecord::genesis(&key(1), &key(2));
        let account = genesis.digest();
        let mut authority = Authority::import([genesis.clone()], account, account).unwrap();
        let rotate = AuthorityRecord::rotate(authority.head().unwrap(), &key(1), &key(3)).unwrap();
        assert_eq!(authority.apply(rotate.clone()).unwrap(), Import::Applied);
        let recover =
            AuthorityRecord::recover(authority.head().unwrap(), &key(2), &key(4), &key(5)).unwrap();
        assert_eq!(authority.apply(recover.clone()).unwrap(), Import::Applied);
        let head = authority.head().unwrap();
        assert_eq!((head.generation, head.sequence), (1, 0));
        assert_eq!(head.account, account);
        assert_eq!(authority.apply(recover.clone()).unwrap(), Import::Repeated);
        assert!(
            Authority::import([genesis.clone(), rotate.clone()], account, head.digest).is_err()
        );
        let uploaded = authority
            .records()
            .iter()
            .map(|record| AuthorityRecord::from_bytes(record.as_bytes()).unwrap())
            .collect::<Vec<_>>();
        assert!(Authority::import(uploaded.clone(), [0; 32], head.digest).is_err());
        assert_eq!(
            Authority::import(uploaded, account, head.digest)
                .unwrap()
                .head()
                .unwrap(),
            head
        );
        let repeated_root = AuthorityRecord::rotate(head, &key(4), &key(1)).unwrap();
        assert!(authority.apply(repeated_root).is_err());
        let mut invalid_proof = recover.as_bytes().to_vec();
        let last = invalid_proof.last_mut().unwrap();
        *last ^= 1;
        assert!(
            authority
                .apply(AuthorityRecord::from_bytes(&invalid_proof).unwrap())
                .is_err()
        );
        invalid_proof.push(0);
        assert!(AuthorityRecord::from_bytes(&invalid_proof).is_err());
    }

    #[test]
    fn retains_competing_root_proofs_and_suspends_a_fork() {
        let genesis = AuthorityRecord::genesis(&key(1), &key(2));
        let account = genesis.digest();
        let mut authority = Authority::import([genesis], account, account).unwrap();
        let previous = authority.head().unwrap();
        let rotate = AuthorityRecord::rotate(previous, &key(1), &key(3)).unwrap();
        let mut invalid = rotate.as_bytes().to_vec();
        invalid[ROTATE.len() + 15] ^= 1;
        assert!(
            authority
                .apply(AuthorityRecord::from_bytes(&invalid).unwrap())
                .is_err()
        );
        assert_eq!(authority.head().unwrap(), previous);
        assert_eq!(authority.apply(rotate).unwrap(), Import::Applied);
        let recover = AuthorityRecord::recover(previous, &key(2), &key(4), &key(2)).unwrap();
        assert_eq!(authority.apply(recover).unwrap(), Import::Fork);
        assert!(authority.head().is_err());
        assert_eq!(authority.records().len(), 3);
    }
}
