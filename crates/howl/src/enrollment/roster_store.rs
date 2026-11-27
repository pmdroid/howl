use std::{collections::BTreeSet, io, path::Path};

use crate::identity::StateDirectory;

use super::{
    Authority, Designation, RosterChain,
    authority::{Id, Import, invalid},
    membership::digest,
};

const MAX_EVENTS: usize = 4096;
const MAX_DESIGNATION: usize = 165_000;
const MAX_ENTRY: usize = MAX_DESIGNATION + 7000;
const ROSTER: u8 = 1;
const REVOKE: u8 = 2;

pub struct RosterStore {
    state: StateDirectory,
    channel: Id,
    prefix: String,
}

struct History {
    chain: RosterChain,
    seen: BTreeSet<Id>,
    count: usize,
}

impl RosterStore {
    pub fn open(path: &Path, channel: Id) -> io::Result<Self> {
        Ok(Self {
            state: StateDirectory::open(path)?,
            channel,
            prefix: format!("roster-{}", hex::encode(channel)),
        })
    }

    pub(crate) fn account_revocations(path: &Path, account: Id) -> io::Result<Self> {
        Ok(Self {
            state: StateDirectory::open(path)?,
            channel: [0; 32],
            prefix: format!("enrollment-revocations-{}", hex::encode(account)),
        })
    }

    pub fn has_history(&self) -> io::Result<bool> {
        match self.state.read_bounded(&self.name(0), MAX_ENTRY as u64) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn load(&self, authority: &Authority) -> io::Result<RosterChain> {
        Ok(self.history(authority)?.chain)
    }

    pub fn apply(
        &self,
        authority: &Authority,
        designation: &Designation,
        record: &[u8],
    ) -> io::Result<Import> {
        self.append(authority, designation, ROSTER, record)
    }

    pub fn revoke(
        &self,
        authority: &Authority,
        designation: &Designation,
        record: &[u8],
    ) -> io::Result<Import> {
        self.append(authority, designation, REVOKE, record)
    }

    fn append(
        &self,
        authority: &Authority,
        designation: &Designation,
        kind: u8,
        record: &[u8],
    ) -> io::Result<Import> {
        designation.verify_current(authority)?;
        let mut history = self.history(authority)?;
        let length = (designation.as_bytes().len() as u32).to_be_bytes();
        let entry = [&[kind], length.as_slice(), designation.as_bytes(), record].concat();
        if history.seen.contains(&digest(&entry)) {
            return Ok(Import::Repeated);
        }
        if history.count >= MAX_EVENTS || entry.len() > MAX_ENTRY {
            return Err(invalid("channel roster history is too large"));
        }
        let outcome = apply(&mut history.chain, designation, kind, record)?;
        if outcome == Import::Repeated {
            return Ok(outcome);
        }
        if !self.state.write(&self.name(history.count), &entry)? {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "channel roster changed during append",
            ));
        }
        Ok(outcome)
    }

    fn history(&self, authority: &Authority) -> io::Result<History> {
        let mut history = History {
            chain: RosterChain::new(authority.head()?.account, self.channel),
            seen: BTreeSet::new(),
            count: 0,
        };
        for index in 0..MAX_EVENTS {
            let entry = match self.state.read_bounded(&self.name(index), MAX_ENTRY as u64) {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            };
            if !history.seen.insert(digest(&entry)) {
                return Err(invalid("duplicate entry in persisted roster history"));
            }
            let (kind, rest) = entry
                .split_first()
                .ok_or_else(|| invalid("invalid persisted roster"))?;
            let (size, rest) = rest
                .split_first_chunk::<4>()
                .ok_or_else(|| invalid("invalid persisted roster size"))?;
            let size = u32::from_be_bytes(*size) as usize;
            let (designation, bytes) = rest
                .split_at_checked(size)
                .ok_or_else(|| invalid("truncated persisted roster"))?;
            let designation = Designation::from_history(designation, authority)?;
            if apply(&mut history.chain, &designation, *kind, bytes)? == Import::Repeated {
                return Err(invalid("duplicate persisted roster proof"));
            }
            history.count = index + 1;
        }
        Ok(history)
    }

    fn name(&self, index: usize) -> String {
        format!("{}-{index:04x}", self.prefix)
    }
}

fn apply(
    chain: &mut RosterChain,
    designation: &Designation,
    kind: u8,
    bytes: &[u8],
) -> io::Result<Import> {
    chain.learn_designation(designation);
    match kind {
        ROSTER => chain.apply(bytes, designation),
        REVOKE => {
            chain.learn_revocation(designation, bytes)?;
            Ok(Import::Applied)
        }
        _ => Err(invalid("invalid roster history entry kind")),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::enrollment::{AuthorityRecord, Roster};

    use super::*;

    #[test]
    fn reload_retains_active_epoch_and_fork() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("rosters");
        let root = SigningKey::from_bytes(&[1; 32]);
        let recovery = SigningKey::from_bytes(&[2; 32]);
        let signer = SigningKey::from_bytes(&[3; 32]);
        let genesis = AuthorityRecord::genesis(&root, &recovery);
        let account = genesis.digest();
        let authority = Authority::import([genesis], account, account).unwrap();
        let designation =
            Designation::issue(authority.head().unwrap(), 1, &root, &signer, &[]).unwrap();
        let channel = [9; 32];
        let first = Roster::issue(&designation, &signer, channel, None, false, &[]).unwrap();
        let pause = Roster::issue(&designation, &signer, channel, Some(&first), true, &[]).unwrap();
        let active =
            Roster::issue(&designation, &signer, channel, Some(&first), false, &[]).unwrap();
        let store = RosterStore::open(&state, channel).unwrap();
        assert_eq!(
            store
                .apply(&authority, &designation, first.as_bytes())
                .unwrap(),
            Import::Applied
        );
        assert_eq!(
            store
                .apply(&authority, &designation, first.as_bytes())
                .unwrap(),
            Import::Repeated
        );
        assert_eq!(
            store
                .apply(&authority, &designation, active.as_bytes())
                .unwrap(),
            Import::Applied
        );
        assert_eq!(
            RosterStore::open(&state, channel)
                .unwrap()
                .load(&authority)
                .unwrap()
                .active(&designation)
                .unwrap()
                .epoch(),
            2
        );
        assert_eq!(
            store
                .apply(&authority, &designation, pause.as_bytes())
                .unwrap(),
            Import::Fork
        );
        assert!(
            RosterStore::open(&state, channel)
                .unwrap()
                .load(&authority)
                .unwrap()
                .active(&designation)
                .is_err()
        );
    }
}
