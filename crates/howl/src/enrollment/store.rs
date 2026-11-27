use std::{io, path::Path};

use crate::identity::StateDirectory;

use super::{
    Authority, AuthorityHead, AuthorityRecord, Id, Import,
    authority::{invalid, take},
};

const PIN_FILE: &str = "authority-pin";
const PIN_HEADER: &[u8] = b"howl/enrollment/v1/authority-pin\0";
const MAX_HISTORY: usize = 4096;
const MAX_RECORD: usize = 512;
const MAX_PIN_BYTES: usize = PIN_HEADER.len() + 64 + MAX_HISTORY * (2 + MAX_RECORD);

pub struct AuthorityStore {
    state: StateDirectory,
}

impl AuthorityStore {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            state: StateDirectory::open(path)?,
        })
    }

    pub fn initialize(&self, records: &[AuthorityRecord], account: Id, head: Id) -> io::Result<()> {
        Authority::import(records.iter().cloned(), account, head)?.head()?;
        if records.len() > MAX_HISTORY {
            return Err(invalid("authority history is too large"));
        }
        let mut bytes = [PIN_HEADER, &account, &head].concat();
        for record in records {
            let bytes_record = record.as_bytes();
            let length = u16::try_from(bytes_record.len())
                .map_err(|_| invalid("authority record is too large"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(bytes_record);
        }
        if self.state.write(PIN_FILE, &bytes)? {
            return Ok(());
        }
        if self.state.read_bounded(PIN_FILE, MAX_PIN_BYTES as u64)? == bytes {
            return Ok(());
        }
        Err(invalid("a different authority is already pinned"))
    }

    pub fn current(&self) -> io::Result<AuthorityHead> {
        self.load()?.head()
    }

    pub fn load(&self) -> io::Result<Authority> {
        let pin = self.state.read_bounded(PIN_FILE, MAX_PIN_BYTES as u64)?;
        let pin = pin
            .strip_prefix(PIN_HEADER)
            .filter(|pin| pin.len() >= 64)
            .ok_or_else(|| invalid("invalid local authority pin"))?;
        let mut records = Vec::new();
        let mut source = &pin[64..];
        while !source.is_empty() {
            let (size, rest) = source
                .split_first_chunk::<2>()
                .ok_or_else(|| invalid("invalid authority history length"))?;
            let (record, after) = rest
                .split_at_checked(usize::from(u16::from_be_bytes(*size)))
                .ok_or_else(|| invalid("truncated authority history"))?;
            records.push(AuthorityRecord::from_bytes(record)?);
            if records.len() > MAX_HISTORY {
                return Err(invalid("authority history is too large"));
            }
            source = after;
        }
        let mut authority = Authority::import(records, take(pin, 0), take(pin, 32))?;
        for index in authority.records().len()..MAX_HISTORY {
            let bytes = match self
                .state
                .read_bounded(&record_name(index), MAX_RECORD as u64)
            {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(authority),
                Err(error) => return Err(error),
            };
            if authority.apply(AuthorityRecord::from_bytes(&bytes)?)? == Import::Repeated {
                return Err(invalid("duplicate in local authority history"));
            }
        }
        Ok(authority)
    }

    pub fn append(&self, record: AuthorityRecord) -> io::Result<Import> {
        let mut authority = self.load()?;
        let index = authority.records().len();
        let outcome = authority.apply(record.clone())?;
        if outcome == Import::Repeated {
            return Ok(outcome);
        }
        if index >= MAX_HISTORY {
            return Err(invalid("authority history is too large"));
        }
        if self.state.write(&record_name(index), record.as_bytes())? {
            return Ok(outcome);
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "authority changed during append",
        ))
    }
}

fn record_name(index: usize) -> String {
    format!("authority-{index:04x}")
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn persists_the_exact_pin_and_verified_fork_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("authority");
        let store = AuthorityStore::open(&path).unwrap();
        let root = SigningKey::from_bytes(&[1; 32]);
        let recovery = SigningKey::from_bytes(&[2; 32]);
        let next = SigningKey::from_bytes(&[3; 32]);
        let recovered = SigningKey::from_bytes(&[4; 32]);
        let genesis = AuthorityRecord::genesis(&root, &recovery);
        let account = genesis.digest();
        store
            .initialize(std::slice::from_ref(&genesis), account, account)
            .unwrap();
        let prior = store.current().unwrap();
        let rotate = AuthorityRecord::rotate(prior, &root, &next).unwrap();
        let rotated = rotate.digest();
        assert_eq!(store.append(rotate).unwrap(), Import::Applied);
        assert_eq!(
            AuthorityStore::open(&path)
                .unwrap()
                .current()
                .unwrap()
                .digest,
            rotated
        );
        let competing = AuthorityRecord::recover(prior, &recovery, &recovered, &recovery).unwrap();
        assert_eq!(store.append(competing).unwrap(), Import::Fork);
        assert!(AuthorityStore::open(&path).unwrap().current().is_err());
        assert!(store.initialize(&[genesis], account, rotated).is_err());
    }
}
