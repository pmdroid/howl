use std::{fs::File, io, path::Path};

use rustix::fs::{FlockOperation, flock};
use zeroize::Zeroizing;

use super::{
    AuthorityRecord, AuthorityStore, DESIGNATION, Designation, Id, RECORD_LIMIT, RECOVERY, ROOT,
    SIGNER, StateDirectory, checked_authority, initialize_key, invalid, load_key, secret_record,
    separate, show_authority, write_exact,
};
use crate::enrollment::{Import, RecoveryPackage};

const PACKAGE: &str = "recovery-package";
const UNLOCK: &str = "recovery-unlock";

pub(super) fn export(
    state: &Path,
    offline: &Path,
    package: &Path,
    unlock: &Path,
) -> io::Result<()> {
    separate(&[state, offline, package, unlock])?;
    let authority = AuthorityStore::open(state)?.load()?;
    let head = authority.head()?;
    let offline = StateDirectory::open(offline)?;
    let seed = load_key(&offline, RECOVERY)?;
    if seed.verifying_key().to_bytes() != head.recovery {
        return Err(invalid(
            "offline recovery key does not match the pinned authority",
        ));
    }
    let export = format!("recovery-export-{}", hex::encode(head.digest));
    let staged = match offline.read_bounded(&export, RECORD_LIMIT) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (package, key) = RecoveryPackage::export(head, &seed)?;
            let staged = Zeroizing::new([key.as_slice(), package.as_bytes()].concat());
            if offline.write(&export, &staged)? {
                staged
            } else {
                Zeroizing::new(offline.read_bounded(&export, RECORD_LIMIT)?)
            }
        }
        Err(error) => return Err(error),
    };
    let (key, bytes) = staged
        .split_first_chunk::<32>()
        .ok_or_else(|| invalid("invalid staged recovery export"))?;
    RecoveryPackage::from_bytes(bytes)?.unlock(head, key)?;
    AuthorityStore::open(package)?.initialize(authority.records(), head.account, head.digest)?;
    write_exact(&StateDirectory::open(package)?, PACKAGE, bytes)?;
    write_exact(&StateDirectory::open(unlock)?, UNLOCK, key)?;
    println!("Recovery export ready. Store the package and unlock directories separately.");
    Ok(())
}

pub(super) fn recover(
    state: &Path,
    package: &Path,
    unlock: &Path,
    offline: &Path,
    account: Id,
    digest: Id,
) -> io::Result<()> {
    separate(&[state, package, unlock, offline])?;
    let (authority, previous) = checked_authority(package, account, digest)?;
    let package = StateDirectory::open(package)?;
    let unlock = secret_record(&StateDirectory::open(unlock)?, UNLOCK)?;
    let recovery = RecoveryPackage::from_bytes(&package.read_bounded(PACKAGE, RECORD_LIMIT)?)?
        .unlock(previous, &unlock)?;

    let directory = StateDirectory::open(state)?;
    let lock = File::open(state)?;
    flock(&lock, FlockOperation::LockExclusive)?;
    let local = AuthorityStore::open(state)?;
    local.initialize(authority.records(), account, digest)?;
    let root = initialize_key(&directory, ROOT)?;
    let signer = initialize_key(&directory, SIGNER)?;
    let next_recovery = initialize_key(&StateDirectory::open(offline)?, RECOVERY)?;
    let successor = AuthorityRecord::recover(previous, &recovery, &root, &next_recovery)?;
    let next_digest = successor.digest();
    let current = local.current()?.digest;
    if current != digest && current != next_digest {
        return Err(invalid("local authority already has a different successor"));
    }
    let mut authority = authority;
    if authority.apply(successor.clone())? != Import::Applied {
        return Err(invalid("invalid authority recovery succession"));
    }
    let head = authority.head()?;
    let designation = Designation::issue(head, 1, &root, &signer, &[])?;
    match directory.read_bounded(DESIGNATION, RECORD_LIMIT) {
        Ok(bytes) if bytes != designation.as_bytes() => {
            return Err(invalid(
                "a different designation already exists in the destination",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if local.append(successor)? == Import::Fork {
        return Err(invalid("authority recovery fork detected"));
    }
    write_exact(&directory, DESIGNATION, designation.as_bytes())?;
    show_authority(head, &designation);
    Ok(())
}
