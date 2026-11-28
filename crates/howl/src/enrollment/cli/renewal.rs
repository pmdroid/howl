use std::{fs::File, io, path::Path};

use rustix::fs::{FlockOperation, flock};

use super::{
    Authority, AuthorityStore, CERTIFICATE, DESIGNATION, Designation, DeviceCertificate, Id,
    PeerCertificate, StateDirectory, invalid, write_exact,
};
use crate::{enrollment::Import, identity::PeerTrust};

const PROFILE: &str = "enrollment-profile";
const MAX_DESIGNATION: u64 = 165_000;
const MAX_CERTIFICATE: u64 = 512;
const MAX_PROFILE: u64 = 4 + MAX_DESIGNATION + MAX_CERTIFICATE;

type Records = (Vec<u8>, Vec<u8>);

pub(crate) fn profile_records(directory: &StateDirectory) -> io::Result<Option<Records>> {
    if let Some(records) = revised(directory, PROFILE)? {
        return Ok(Some(records));
    }
    let Some(certificate) = optional(directory, CERTIFICATE, MAX_CERTIFICATE)? else {
        return Ok(None);
    };
    Ok(Some((
        directory.read_bounded(DESIGNATION, MAX_DESIGNATION)?,
        certificate,
    )))
}

pub(crate) fn peer_records(directory: &StateDirectory, device: Id) -> io::Result<Option<Records>> {
    if let Some(records) = revised(directory, &peer_profile(device))? {
        return Ok(Some(records));
    }
    let Some(certificate) = optional(directory, &peer_legacy(device), MAX_CERTIFICATE)? else {
        return Ok(None);
    };
    Ok(Some((
        directory.read_bounded(DESIGNATION, MAX_DESIGNATION)?,
        certificate,
    )))
}

pub(in crate::enrollment) fn accept(
    state: &Path,
    authority: &Authority,
    designation: &Designation,
    certificate: &DeviceCertificate,
    peer: &PeerCertificate,
) -> io::Result<()> {
    let directory = StateDirectory::open(state)?;
    let lock = File::open(state)?;
    flock(&lock, FlockOperation::LockExclusive)?;
    let store = AuthorityStore::open(state)?;
    let head = authority.head()?;
    let active = profile_records(&directory)?;
    let previous = match store.load() {
        Ok(previous) => Some(previous),
        Err(error) if error.kind() == io::ErrorKind::NotFound && active.is_none() => None,
        Err(error) => return Err(error),
    };
    if let Some((old_designation, old_certificate)) = &active {
        let previous = previous
            .as_ref()
            .ok_or_else(|| invalid("enrollment authority is missing"))?;
        let old_designation = Designation::from_history(old_designation, previous)?;
        let old_certificate = DeviceCertificate::verify(old_certificate, &old_designation)?;
        check_device(&old_certificate, certificate, peer)?;
        if designation.digest() != old_designation.digest() {
            let same_head = Designation::verify(old_designation.as_bytes(), head).is_ok();
            let next = if same_head {
                old_designation.sequence().checked_add(1)
            } else {
                Some(1)
            };
            if Some(designation.sequence()) != next
                || old_designation
                    .floors()
                    .iter()
                    .any(|floor| designation.revoked_through(floor.device) < floor.sequence)
            {
                return Err(invalid(
                    "designation does not advance the pinned enrollment",
                ));
            }
        }
    } else if let Some(existing) = optional(&directory, DESIGNATION, MAX_DESIGNATION)?
        && existing != designation.as_bytes()
    {
        return Err(invalid(
            "enrollment designation does not match the existing owner state",
        ));
    }
    match previous {
        Some(previous) => advance(&store, &previous, authority)?,
        None => store.initialize(authority.records(), head.account, head.digest)?,
    }
    if store.current()? != head {
        return Err(invalid(
            "local authority head differs from the approved head",
        ));
    }
    match active {
        Some((old_designation, old_certificate))
            if old_designation == designation.as_bytes()
                && old_certificate == certificate.as_bytes() =>
        {
            Ok(())
        }
        Some(_) => publish(&directory, PROFILE, designation, certificate),
        None => {
            write_exact(&directory, DESIGNATION, designation.as_bytes())?;
            write_exact(&directory, CERTIFICATE, certificate.as_bytes())
        }
    }
}

pub(in crate::enrollment) fn import_peer(
    state: &Path,
    directory: &StateDirectory,
    authority: &Authority,
    designation: &Designation,
    certificate: &DeviceCertificate,
    peer: &PeerCertificate,
) -> io::Result<()> {
    let lock = File::open(state)?;
    flock(&lock, FlockOperation::LockExclusive)?;
    let active = super::designation(directory, AuthorityStore::open(state)?.current()?)?;
    if active.digest() != designation.digest() {
        return Err(invalid("enrollment changed while importing the peer"));
    }
    let device = *peer.device_id();
    let profile = peer_profile(device);
    let previous = super::peer_records(directory, device)?;
    if previous.is_none()
        && optional(directory, DESIGNATION, MAX_DESIGNATION)?.as_deref()
            == Some(designation.as_bytes())
    {
        PeerTrust::open(state)?.pin(peer, &peer.fingerprint())?;
        return write_exact(directory, &peer_legacy(device), certificate.as_bytes());
    }
    if let Some((old_designation, old_certificate)) = previous {
        let old_designation = Designation::from_history(&old_designation, authority)?;
        let old = DeviceCertificate::verify(&old_certificate, &old_designation)?;
        check_device(&old, certificate, peer)?;
        if old.as_bytes() == certificate.as_bytes() {
            return PeerTrust::open(state)?.pin(peer, &peer.fingerprint());
        }
    }
    PeerTrust::open(state)?.pin(peer, &peer.fingerprint())?;
    publish(directory, &profile, designation, certificate)
}

fn advance(store: &AuthorityStore, local: &Authority, incoming: &Authority) -> io::Result<()> {
    local.head()?;
    let local_records = local.records();
    let records = incoming.records();
    if records.starts_with(local_records) {
        for record in &records[local_records.len()..] {
            if store.append(record.clone())? == Import::Fork {
                return Err(invalid("verified authority fork recorded"));
            }
        }
        return Ok(());
    }
    let shared = local_records
        .iter()
        .zip(records)
        .take_while(|(left, right)| left == right)
        .count();
    if let Some(competing) = records.get(shared)
        && shared > 0
        && shared < local_records.len()
        && store.append(competing.clone())? == Import::Fork
    {
        return Err(invalid("verified authority fork recorded"));
    }
    Err(invalid(
        "exchanged authority does not extend the existing pin",
    ))
}

fn check_device(
    old: &DeviceCertificate,
    next: &DeviceCertificate,
    peer: &PeerCertificate,
) -> io::Result<()> {
    if old.account != next.account
        || !old.matches(peer)
        || (old.as_bytes() != next.as_bytes() && next.sequence <= old.sequence)
    {
        return Err(invalid(
            "certificate does not advance the existing device enrollment",
        ));
    }
    Ok(())
}

fn revised(directory: &StateDirectory, name: &str) -> io::Result<Option<Records>> {
    let Some(bytes) = optional(directory, name, MAX_PROFILE)? else {
        return Ok(None);
    };
    let (length, records) = bytes
        .split_first_chunk::<4>()
        .ok_or_else(|| invalid("invalid enrollment profile"))?;
    let size = u32::from_be_bytes(*length) as usize;
    let (designation, certificate) = records
        .split_at_checked(size)
        .ok_or_else(|| invalid("invalid enrollment profile"))?;
    if designation.len() as u64 > MAX_DESIGNATION || certificate.len() as u64 > MAX_CERTIFICATE {
        return Err(invalid("invalid enrollment profile"));
    }
    Ok(Some((designation.to_vec(), certificate.to_vec())))
}

fn publish(
    directory: &StateDirectory,
    filename: &str,
    designation: &Designation,
    certificate: &DeviceCertificate,
) -> io::Result<()> {
    let length = (designation.as_bytes().len() as u32).to_be_bytes();
    let record = [&length, designation.as_bytes(), certificate.as_bytes()].concat();
    directory.replace(filename, &record)
}

fn optional(directory: &StateDirectory, name: &str, limit: u64) -> io::Result<Option<Vec<u8>>> {
    match directory.read_bounded(name, limit) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn peer_legacy(device: Id) -> String {
    format!("enrollment-peer-{}", hex::encode(device))
}
fn peer_profile(device: Id) -> String {
    format!("enrollment-peer-profile-{}", hex::encode(device))
}
