use std::{collections::BTreeMap, io};

use ed25519_dalek::SigningKey;
use howl_envelope::{DeviceAddress, MAX_RECIPIENTS};

use super::{
    Designation, DeviceCertificate, Floor,
    authority::{Id, Import, check_signatures, invalid, sign, take},
    verify_revocation,
};

const ROSTER: &[u8] = b"howl/identity/v1/roster\0";
const HEADER: usize = 139;
const MEMBER: usize = 97;
const ZERO: Id = [0; 32];
pub(crate) const MAX_ROSTER_LEN: usize = ROSTER.len() + HEADER + MAX_RECIPIENTS * MEMBER + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelPermission {
    Receive = 1,
    Send = 2,
    Wake = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterMember {
    pub address: DeviceAddress,
    pub certificate: Id,
    pub permissions: u8,
}

impl RosterMember {
    pub fn allows(self, permission: ChannelPermission) -> bool {
        self.permissions & permission as u8 != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Roster {
    bytes: Vec<u8>,
    digest: Id,
    owner: Id,
    designation: Id,
    channel: Id,
    previous: Id,
    epoch: u64,
    paused: bool,
    members: Vec<RosterMember>,
}

impl Roster {
    pub fn issue(
        designation: &Designation,
        signer: &SigningKey,
        channel: Id,
        previous: Option<&Roster>,
        paused: bool,
        members: &[RosterMember],
    ) -> io::Result<Self> {
        if members.len() > MAX_RECIPIENTS {
            return Err(invalid("too many channel members"));
        }
        let (prior, epoch) = match previous {
            Some(previous)
                if previous.owner == designation.account() && previous.channel == channel =>
            {
                (
                    previous.digest,
                    previous
                        .epoch
                        .checked_add(1)
                        .ok_or_else(|| invalid("roster epoch overflow"))?,
                )
            }
            Some(_) => return Err(invalid("roster predecessor belongs to a different channel")),
            None => (ZERO, 1),
        };
        let mut body = [
            ROSTER,
            &designation.account(),
            &designation.digest(),
            &channel,
            &prior,
            &epoch.to_be_bytes(),
            &[u8::from(paused)],
            &(members.len() as u16).to_be_bytes(),
        ]
        .concat();
        for member in members {
            body.extend_from_slice(&member.address.account);
            body.extend_from_slice(&member.address.device);
            body.extend_from_slice(&member.certificate);
            body.push(member.permissions);
        }
        Self::verify(&sign(body, &[signer]), designation)
    }

    pub fn verify(bytes: &[u8], designation: &Designation) -> io::Result<Self> {
        let fields = bytes
            .strip_prefix(ROSTER)
            .filter(|fields| fields.len() >= HEADER + 64)
            .ok_or_else(|| invalid("invalid channel roster"))?;
        let owner = take(fields, 0);
        let signer = take(fields, 32);
        let previous = take(fields, 96);
        let epoch = u64::from_be_bytes(take(fields, 128));
        let count = usize::from(u16::from_be_bytes(take(fields, 137)));
        let signed = HEADER + count * MEMBER;
        if fields.len() != signed + 64
            || count > MAX_RECIPIENTS
            || owner != designation.account()
            || signer != designation.digest()
            || epoch == 0
            || (epoch == 1) != (previous == ZERO)
            || fields[136] > 1
        {
            return Err(invalid("invalid channel roster fields"));
        }
        let mut members: Vec<RosterMember> = Vec::with_capacity(count);
        for entry in fields[HEADER..signed].as_chunks::<MEMBER>().0 {
            let address = DeviceAddress {
                account: take(entry, 0),
                device: take(entry, 32),
            };
            if entry[96] == 0
                || entry[96] & !7 != 0
                || members.last().is_some_and(|prior| prior.address >= address)
            {
                return Err(invalid("invalid channel roster member"));
            }
            members.push(RosterMember {
                address,
                certificate: take(entry, 64),
                permissions: entry[96],
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            digest: check_signatures(bytes, ROSTER.len() + signed, &[designation.signer()])?,
            owner,
            designation: signer,
            channel: take(fields, 64),
            previous,
            epoch,
            paused: fields[136] == 1,
            members,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> Id {
        self.digest
    }

    pub fn channel(&self) -> Id {
        self.channel
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    pub fn members(&self) -> &[RosterMember] {
        &self.members
    }
}

pub struct RosterChain {
    owner: Id,
    channel: Id,
    head: Option<Id>,
    accepted: BTreeMap<Id, Roster>,
    successors: BTreeMap<Id, Id>,
    conflicts: Vec<Roster>,
    floors: BTreeMap<DeviceAddress, u64>,
}

impl RosterChain {
    pub fn new(owner: Id, channel: Id) -> Self {
        Self {
            owner,
            channel,
            head: None,
            accepted: BTreeMap::new(),
            successors: BTreeMap::new(),
            conflicts: Vec::new(),
            floors: BTreeMap::new(),
        }
    }

    pub fn apply(&mut self, bytes: &[u8], current: &Designation) -> io::Result<Import> {
        if self
            .accepted
            .values()
            .chain(&self.conflicts)
            .any(|prior| prior.as_bytes() == bytes)
        {
            return Ok(Import::Repeated);
        }
        let roster = Roster::verify(bytes, current)?;
        if roster.owner != self.owner || roster.channel != self.channel {
            return Err(invalid("roster does not match the pinned channel owner"));
        }
        let prior_epoch = if roster.previous == ZERO {
            0
        } else {
            self.accepted
                .get(&roster.previous)
                .ok_or_else(|| invalid("unknown roster predecessor"))?
                .epoch
        };
        if prior_epoch.checked_add(1) != Some(roster.epoch) {
            return Err(invalid("roster does not advance the preceding epoch"));
        }
        if let Some(previous) = self.successors.get(&roster.previous) {
            if *previous != roster.digest {
                self.conflicts.push(roster);
                return Ok(Import::Fork);
            }
            return Err(invalid("roster record has conflicting proof bytes"));
        }
        if roster.previous != self.head.unwrap_or(ZERO) {
            return Err(invalid("roster does not advance the pinned head"));
        }
        self.successors.insert(roster.previous, roster.digest);
        self.head = Some(roster.digest);
        self.accepted.insert(roster.digest, roster);
        Ok(Import::Applied)
    }

    pub fn learn_revocation(&mut self, designation: &Designation, bytes: &[u8]) -> io::Result<()> {
        let floor = verify_revocation(designation, bytes)?;
        self.raise_floor(designation.account(), floor);
        Ok(())
    }

    pub fn learn_designation(&mut self, designation: &Designation) {
        for floor in designation.floors() {
            self.raise_floor(designation.account(), *floor);
        }
    }

    fn raise_floor(&mut self, account: Id, floor: Floor) {
        self.floors
            .entry(DeviceAddress {
                account,
                device: floor.device,
            })
            .and_modify(|known| *known = (*known).max(floor.sequence))
            .or_insert(floor.sequence);
    }

    pub fn latest(&self) -> io::Result<Option<&Roster>> {
        if !self.conflicts.is_empty() {
            return Err(invalid("roster has a verified fork"));
        }
        Ok(self.head.and_then(|head| self.accepted.get(&head)))
    }

    pub fn active(&self, current: &Designation) -> io::Result<&Roster> {
        self.latest()?
            .filter(|roster| roster.designation == current.digest() && !roster.paused)
            .ok_or_else(|| invalid("no active roster matches the current designation"))
    }

    pub fn authorize(
        &self,
        current: &Designation,
        certificate: &DeviceCertificate,
        permission: ChannelPermission,
    ) -> io::Result<()> {
        let active = self.active(current)?;
        let address = DeviceAddress {
            account: certificate.account,
            device: certificate.device,
        };
        if !active.members.iter().any(|member| {
            member.address == address
                && member.certificate == certificate.digest
                && member.allows(permission)
        }) || self
            .floors
            .get(&address)
            .is_some_and(|floor| certificate.sequence <= *floor)
        {
            return Err(invalid("device is outside the active roster permissions"));
        }
        Ok(())
    }

    pub fn conflicts(&self) -> &[Roster] {
        &self.conflicts
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::LocalIdentity;

    use super::super::{Authority, AuthorityRecord, revoke};
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    #[test]
    fn pinned_successor_rejects_a_partitioned_fork_and_pauses() {
        let root = key(1);
        let signer = key(3);
        let genesis = AuthorityRecord::genesis(&root, &key(2));
        let account = genesis.digest();
        let authority = Authority::import([genesis], account, account)
            .unwrap()
            .head()
            .unwrap();
        let current = Designation::issue(authority, 1, &root, &signer, &[]).unwrap();
        let channel = [9; 32];
        let first = Roster::issue(&current, &signer, channel, None, false, &[]).unwrap();
        let next = Roster::issue(&current, &signer, channel, Some(&first), true, &[]).unwrap();
        let competitor =
            Roster::issue(&current, &signer, channel, Some(&first), false, &[]).unwrap();
        let other = Roster::issue(&current, &signer, [8; 32], None, false, &[]).unwrap();
        let mut left = RosterChain::new(account, channel);
        let mut right = RosterChain::new(account, channel);
        assert!(left.apply(other.as_bytes(), &current).is_err());
        assert!(left.apply(next.as_bytes(), &current).is_err());
        assert!(Roster::issue(&current, &key(4), channel, None, false, &[]).is_err());
        for book in [&mut left, &mut right] {
            assert_eq!(
                book.apply(first.as_bytes(), &current).unwrap(),
                Import::Applied
            );
            assert_eq!(
                book.apply(first.as_bytes(), &current).unwrap(),
                Import::Repeated
            );
        }
        assert_eq!(
            left.apply(next.as_bytes(), &current).unwrap(),
            Import::Applied
        );
        assert!(left.active(&current).is_err());
        assert_eq!(
            right.apply(competitor.as_bytes(), &current).unwrap(),
            Import::Applied
        );
        assert_eq!(right.active(&current).unwrap().epoch(), 2);
        assert_eq!(
            left.apply(competitor.as_bytes(), &current).unwrap(),
            Import::Fork
        );
        assert_eq!(
            right.apply(next.as_bytes(), &current).unwrap(),
            Import::Fork
        );
        assert_eq!(right.conflicts(), &[next]);
        assert!(right.active(&current).is_err());
    }

    #[test]
    fn rejects_retired_or_revoked_devices_without_removing_historical_evidence() {
        let root = key(1);
        let signer = key(3);
        let genesis = AuthorityRecord::genesis(&root, &key(2));
        let account = genesis.digest();
        let authority = Authority::import([genesis], account, account)
            .unwrap()
            .head()
            .unwrap();
        let current = Designation::issue(authority, 1, &root, &signer, &[]).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let id = LocalIdentity::load_or_create(&temp.path().join("device")).unwrap();
        let device_body = DeviceCertificate::body(&current, &id.certificate(), 1);
        let proof = id.sign(&device_body);
        let certificate = DeviceCertificate::issue(&current, &signer, device_body, proof).unwrap();
        let channel = [9; 32];
        let member = RosterMember {
            address: DeviceAddress {
                account,
                device: certificate.device,
            },
            certificate: certificate.digest,
            permissions: 3,
        };
        let first = Roster::issue(&current, &signer, channel, None, false, &[member]).unwrap();
        let mut book = RosterChain::new(account, channel);
        book.apply(first.as_bytes(), &current).unwrap();
        assert!(
            book.authorize(&current, &certificate, ChannelPermission::Receive)
                .is_ok()
        );
        assert!(
            book.authorize(&current, &certificate, ChannelPermission::Wake)
                .is_err()
        );
        let floor = Floor {
            device: certificate.device,
            sequence: 1,
        };
        book.learn_revocation(&current, &revoke(&current, &signer, floor).unwrap())
            .unwrap();
        assert!(
            book.authorize(&current, &certificate, ChannelPermission::Receive)
                .is_err()
        );
        let next_signer = key(4);
        let replacement = Designation::issue(authority, 2, &root, &next_signer, &[floor]).unwrap();
        assert!(book.active(&replacement).is_err());
        book.learn_designation(&replacement);
        let next = Roster::issue(
            &replacement,
            &next_signer,
            channel,
            Some(&first),
            false,
            &[],
        )
        .unwrap();
        book.apply(next.as_bytes(), &replacement).unwrap();
        assert!(book.active(&replacement).unwrap().members().is_empty());
        assert!(
            book.authorize(&replacement, &certificate, ChannelPermission::Receive)
                .is_err()
        );
        assert_eq!(book.accepted[&first.digest()].members(), &[member]);
    }
}
