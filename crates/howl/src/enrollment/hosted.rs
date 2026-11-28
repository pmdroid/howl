use std::{io, path::Path};

use ed25519_dalek::SigningKey;
use howl_envelope::{DeviceAddress, MAX_RECIPIENTS};
use serde::{Deserialize, Serialize};

use crate::identity::{LocalIdentity, PeerCertificate, StateDirectory};

use super::{
    Authority, AuthorityRecord, AuthorityStore, Designation, DeviceCertificate, Id, Import, Roster,
    RosterChain, RosterMember, RosterStore, authority::invalid, cli,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub authority: Vec<String>,
    pub designation: String,
    pub devices: Vec<Device>,
    pub rosters: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub peer: String,
    pub certificate: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub peer: String,
    pub proof: String,
}

fn decode(text: &str) -> io::Result<Vec<u8>> {
    hex::decode(text).map_err(|_| invalid("invalid hexadecimal enrollment record"))
}

fn identity(text: &str) -> io::Result<PeerCertificate> {
    let mut record = [0; crate::identity::CERTIFICATE_LEN];
    hex::decode_to_slice(text, &mut record).map_err(|_| invalid("invalid peer identity length"))?;
    PeerCertificate::from_bytes(record)
}

fn authority(records: &[String], designation: &str) -> io::Result<(Authority, Designation)> {
    let [genesis] = records else {
        return Err(invalid("expected a founding authority record"));
    };
    let genesis = AuthorityRecord::from_bytes(&decode(genesis)?)?;
    let account = genesis.digest();
    let authority = Authority::import([genesis], account, account)?;
    let designation = Designation::verify(&decode(designation)?, authority.head()?)?;
    Ok((authority, designation))
}

impl Device {
    pub fn identity(&self) -> io::Result<PeerCertificate> {
        identity(&self.peer)
    }

    fn records(
        &self,
        designation: &Designation,
    ) -> io::Result<(PeerCertificate, DeviceCertificate)> {
        let peer = self.identity()?;
        let certificate = DeviceCertificate::verify(&decode(&self.certificate)?, designation)?;
        if !certificate.matches(&peer) || certificate.sequence != 1 {
            return Err(invalid(
                "network enrollment does not match the device identity",
            ));
        }
        Ok((peer, certificate))
    }
}

impl Candidate {
    pub fn identity(&self) -> io::Result<PeerCertificate> {
        identity(&self.peer)
    }

    pub fn verify(&self, records: &[String], designation: &str) -> io::Result<PeerCertificate> {
        let (_, designation) = authority(records, designation)?;
        let peer = self.identity()?;
        let body = DeviceCertificate::body(&designation, &peer, 1);
        peer.verify_signature(&body, &self.signature()?)?;
        Ok(peer)
    }

    fn signature(&self) -> io::Result<[u8; 64]> {
        let mut signature = [0; 64];
        hex::decode_to_slice(&self.proof, &mut signature)
            .map_err(|_| invalid("invalid enrollment signature"))?;
        Ok(signature)
    }

    fn issue(&self, designation: &Designation, signer: &SigningKey) -> io::Result<Device> {
        let peer = self.identity()?;
        let body = DeviceCertificate::body(designation, &peer, 1);
        let certificate = DeviceCertificate::issue(designation, signer, body, self.signature()?)?;
        Ok(Device {
            peer: self.peer.clone(),
            certificate: hex::encode(certificate.as_bytes()),
        })
    }
}

fn member(certificate: &DeviceCertificate) -> RosterMember {
    RosterMember {
        address: DeviceAddress {
            account: certificate.account,
            device: certificate.device,
        },
        certificate: certificate.digest,
        permissions: 3,
    }
}

struct Verified {
    authority: Authority,
    designation: Designation,
    devices: Vec<(PeerCertificate, DeviceCertificate)>,
    chain: RosterChain,
}

impl Network {
    pub fn account_owned(
        root: &SigningKey,
        recovery: &SigningKey,
        signer: &SigningKey,
    ) -> io::Result<Self> {
        let genesis = AuthorityRecord::genesis(root, recovery);
        let account = genesis.digest();
        let authority = Authority::import([genesis.clone()], account, account)?;
        let designation = Designation::issue(authority.head()?, 1, root, signer, &[])?;
        Ok(Self {
            authority: vec![hex::encode(genesis.as_bytes())],
            designation: hex::encode(designation.as_bytes()),
            devices: Vec::new(),
            rosters: Vec::new(),
        })
    }

    pub fn signer(&self) -> io::Result<Id> {
        Ok(authority(&self.authority, &self.designation)?.1.signer())
    }

    pub fn admit(
        &self,
        channel: Id,
        signer: &SigningKey,
        candidate: &Candidate,
    ) -> io::Result<Self> {
        if self.devices.len() >= MAX_RECIPIENTS || channel == [0; 32] {
            return Err(invalid("invalid channel or network membership size"));
        }
        if self.devices.is_empty() && self.rosters.is_empty() {
            let (_, designation) = authority(&self.authority, &self.designation)?;
            return self.add(channel, None, Vec::new(), candidate, &designation, signer);
        }
        let verified = self.verified(channel)?;
        let previous = verified
            .chain
            .latest()?
            .ok_or_else(|| invalid("missing roster"))?;
        let next = self.add(
            channel,
            Some(previous),
            previous.members().to_vec(),
            candidate,
            &verified.designation,
            signer,
        )?;
        self.verify_successor(channel, &next, candidate)?;
        Ok(next)
    }

    fn verified(&self, channel: Id) -> io::Result<Verified> {
        if channel == [0; 32]
            || self.devices.is_empty()
            || self.devices.len() > MAX_RECIPIENTS
            || self.devices.len() != self.rosters.len()
        {
            return Err(invalid("invalid network membership size or channel"));
        }
        let (authority, designation) = authority(&self.authority, &self.designation)?;
        let mut chain = RosterChain::new(authority.account(), channel);
        let mut devices = Vec::new();
        let mut members = Vec::new();
        for (device, roster) in self.devices.iter().zip(&self.rosters) {
            let records = device.records(&designation)?;
            let member = member(&records.1);
            let Err(index) =
                members.binary_search_by_key(&member.address, |m: &RosterMember| m.address)
            else {
                return Err(invalid("duplicate device in network"));
            };
            members.insert(index, member);
            if chain.apply(&decode(roster)?, &designation)? != Import::Applied
                || !chain
                    .latest()?
                    .is_some_and(|r| !r.is_paused() && r.members() == members)
            {
                return Err(invalid(
                    "network roster does not authorize the enrolled devices",
                ));
            }
            devices.push(records);
        }
        Ok(Verified {
            authority,
            designation,
            devices,
            chain,
        })
    }

    pub fn verify(&self, channel: Id) -> io::Result<()> {
        self.verified(channel).map(|_| ())
    }

    pub fn pin(&self) -> io::Result<(Id, Id, Id)> {
        let (authority, designation) = authority(&self.authority, &self.designation)?;
        let head = authority.head()?;
        Ok((head.account, head.digest, designation.digest()))
    }

    pub fn verify_successor(
        &self,
        channel: Id,
        next: &Network,
        candidate: &Candidate,
    ) -> io::Result<()> {
        if self.authority != next.authority
            || self.designation != next.designation
            || next.rosters.len() != self.rosters.len() + 1
            || !next.rosters.starts_with(&self.rosters)
            || next.devices.len() != self.devices.len() + 1
            || !next.devices.starts_with(&self.devices)
            || next
                .devices
                .last()
                .is_none_or(|device| device.peer != candidate.peer)
        {
            return Err(invalid(
                "approval must append the requested device to the current network",
            ));
        }
        candidate.verify(&self.authority, &self.designation)?;
        next.verify(channel)
    }

    fn add(
        &self,
        channel: Id,
        prior: Option<&Roster>,
        mut members: Vec<RosterMember>,
        candidate: &Candidate,
        designation: &Designation,
        signer: &SigningKey,
    ) -> io::Result<Network> {
        let device = candidate.issue(designation, signer)?;
        let (_, certificate) = device.records(designation)?;
        members.push(member(&certificate));
        members.sort_unstable_by_key(|m| m.address);
        let roster = Roster::issue(designation, signer, channel, prior, false, &members)?;
        let mut next = self.clone();
        next.devices.push(device);
        next.rosters.push(hex::encode(roster.as_bytes()));
        Ok(next)
    }
}

fn identity_only(state: &Path) -> io::Result<bool> {
    for entry in std::fs::read_dir(state)? {
        if !matches!(
            entry?.file_name().as_encoded_bytes(),
            b"device-v1"
                | b"control-auth.lock"
                | b"credentials"
                | b"hosted-network.lock"
                | b"hosted-designation"
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn can_join(state: &Path) -> io::Result<bool> {
    let directory = StateDirectory::open(state)?;
    match directory.read_bounded("hosted-network", 32) {
        Ok(channel) if channel.len() == 32 && channel != [0; 32] => Ok(true),
        Ok(_) => Err(invalid("invalid hosted network reservation")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => identity_only(state),
        Err(error) => Err(error),
    }
}

fn bind(state: &Path, directory: &StateDirectory, channel: Id) -> io::Result<()> {
    if channel == [0; 32] {
        return Err(invalid("invalid network id"));
    }
    let key = "hosted-network";
    match directory.read_bounded(key, 32) {
        Ok(existing) if existing == channel => return Ok(()),
        Ok(_) => return Err(invalid("device state belongs to another network")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if !identity_only(state)? {
        return Err(invalid(
            "existing mesh profile requires a separate device state for a new network",
        ));
    }
    if !directory.write(key, &channel)? && directory.read_bounded(key, 32)? != channel {
        return Err(invalid("device state belongs to another network"));
    }
    Ok(())
}

pub fn reserve(state: &Path, channel: Id) -> io::Result<()> {
    let directory = StateDirectory::open(state)?;
    let _lock = directory.lock("hosted-network.lock")?;
    bind(state, &directory, channel)
}

pub fn candidate(state: &Path, records: &[String], designation: &str) -> io::Result<Candidate> {
    let (authority, designation) = authority(records, designation)?;
    let directory = StateDirectory::open(state)?;
    match AuthorityStore::open(state)?.current() {
        Ok(head) if head != authority.head()? => {
            return Err(invalid("device state belongs to another authority"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if !directory.write("hosted-designation", &designation.digest())?
        && directory.read_bounded("hosted-designation", 32)? != designation.digest()
    {
        return Err(invalid(
            "network designation changed after device registration",
        ));
    }
    let identity = LocalIdentity::load_or_create(state)?;
    let peer = identity.certificate();
    let body = DeviceCertificate::body(&designation, &peer, 1);
    Ok(Candidate {
        peer: hex::encode(peer.as_bytes()),
        proof: hex::encode(identity.sign(&body)),
    })
}

pub fn bootstrap(state: &Path, channel: Id) -> io::Result<Network> {
    let directory = StateDirectory::open(state)?;
    let _lock = directory.lock("hosted-network.lock")?;
    bind(state, &directory, channel)?;
    match directory.read_bounded("hosted-genesis", 8192) {
        Ok(bytes) => {
            let network: Network = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            network.verify(channel)?;
            if network.devices.len() != 1
                || network.devices[0].identity()?.as_bytes()
                    != LocalIdentity::load_or_create(state)?
                        .certificate()
                        .as_bytes()
            {
                return Err(invalid(
                    "cached genesis does not belong to the founding device",
                ));
            }
            return Ok(network);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let state = state.canonicalize()?;
    let mut name = state
        .file_name()
        .ok_or_else(|| invalid("invalid founder state path"))?
        .to_os_string();
    name.push(".recovery");
    let offline = std::env::var_os("HOWL_NETWORK_RECOVERY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| state.with_file_name(name));
    cli::separate(&[&state, &offline])?;
    let root = SigningKey::from_bytes(&*directory.key(cli::ROOT)?);
    let signer = SigningKey::from_bytes(&*directory.key(cli::SIGNER)?);
    let recovery_dir = StateDirectory::open(&offline)?;
    let recovery = SigningKey::from_bytes(&*recovery_dir.key(cli::RECOVERY)?);
    let network = Network::account_owned(&root, &recovery, &signer)?;
    let candidate = candidate(&state, &network.authority, &network.designation)?;
    let genesis = network.admit(channel, &signer, &candidate)?;
    cli::write_exact(
        &directory,
        "hosted-genesis",
        &serde_json::to_vec(&genesis).map_err(io::Error::other)?,
    )?;
    Ok(genesis)
}

pub fn approve(
    state: &Path,
    channel: Id,
    network: &Network,
    candidate: &Candidate,
) -> io::Result<Network> {
    let directory = StateDirectory::open(state)?;
    if directory.read_bounded("hosted-network", 32)? != channel {
        return Err(invalid("device state belongs to another network"));
    }
    let verified = network.verified(channel)?;
    let local = LocalIdentity::load_or_create(state)?.certificate();
    if local.as_bytes() != verified.devices[0].0.as_bytes() {
        return Err(invalid("approval requires the network's founding device"));
    }
    let signer = cli::operator_signer(&directory)?;
    let prior = verified.chain.latest()?.unwrap();
    network.add(
        channel,
        Some(prior),
        prior.members().to_vec(),
        candidate,
        &verified.designation,
        &signer,
    )
}

pub fn apply(state: &Path, channel: Id, network: &Network) -> io::Result<()> {
    let verified = network.verified(channel)?;
    let local = LocalIdentity::load_or_create(state)?.certificate();
    let (_, certificate) = verified
        .devices
        .iter()
        .find(|(p, _)| p.as_bytes() == local.as_bytes())
        .ok_or_else(|| invalid("device has not joined this network"))?;
    let directory = StateDirectory::open(state)?;
    let _lock = directory.lock("hosted-network.lock")?;
    bind(state, &directory, channel)?;
    if directory.read_bounded("hosted-designation", 32)? != verified.designation.digest() {
        return Err(invalid(
            "enrollment does not match the signed device request",
        ));
    }
    let store = RosterStore::open(state, channel)?;
    let history = store.load(&verified.authority)?;
    if let Some(current) = history.latest()?
        && network.rosters.get(current.epoch() as usize - 1)
            != Some(&hex::encode(current.as_bytes()))
    {
        return Err(invalid(
            "network snapshot does not extend the pinned channel",
        ));
    }
    cli::accept_records(
        state,
        &verified.authority,
        &verified.designation,
        certificate,
        &local,
    )?;
    for (peer, certificate) in &verified.devices {
        if peer.as_bytes() != local.as_bytes() {
            cli::import_records(
                state,
                &directory,
                &verified.authority,
                &verified.designation,
                certificate,
                peer,
            )?;
        }
    }
    for record in network.rosters.iter().skip(
        history
            .latest()?
            .map_or(0, |roster| roster.epoch() as usize),
    ) {
        if store.apply(&verified.authority, &verified.designation, &decode(record)?)?
            == Import::Fork
        {
            return Err(invalid("verified roster fork"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{channel::Channel, enrollment::ChannelPermission, identity::PeerTrust};

    #[test]
    fn account_authority_admits_devices_with_no_founder_identity() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let recovery = SigningKey::from_bytes(&[2; 32]);
        let signer = SigningKey::from_bytes(&[3; 32]);
        let network = Network::account_owned(&root, &recovery, &signer).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let channel = [5; 32];
        assert!(network.devices.is_empty() && network.rosters.is_empty());
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let a = candidate(&first, &network.authority, &network.designation).unwrap();
        assert!(network.admit(channel, &root, &a).is_err());
        let current = network.admit(channel, &signer, &a).unwrap();
        network.verify_successor(channel, &current, &a).unwrap();
        std::fs::remove_dir_all(&first).unwrap();
        let b = candidate(&second, &network.authority, &network.designation).unwrap();
        let next = current.admit(channel, &signer, &b).unwrap();
        current.verify_successor(channel, &next, &b).unwrap();
        assert!(next.admit(channel, &signer, &b).is_err());
        apply(&second, channel, &next).unwrap();
    }

    #[test]
    fn only_fresh_identities_and_reserved_profiles_join_during_login() {
        let temp = tempfile::tempdir().unwrap();
        let peer = LocalIdentity::load_or_create(&temp.path().join("peer"))
            .unwrap()
            .certificate();
        let fresh = temp.path().join("fresh");
        assert!(can_join(&fresh).unwrap());
        LocalIdentity::load_or_create(&fresh).unwrap();
        let directory = StateDirectory::open(&fresh).unwrap();
        let _login = directory.lock("control-auth.lock").unwrap();
        directory.write("credentials", b"session").unwrap();
        assert!(can_join(&fresh).unwrap());
        PeerTrust::open(&fresh)
            .unwrap()
            .pin(&peer, &peer.fingerprint())
            .unwrap();
        assert!(!can_join(&fresh).unwrap());
        assert!(reserve(&fresh, [1; 32]).is_err());

        for artifact in ["channel-manifest", "delivery.db", "authority-pin"] {
            let state = temp.path().join(artifact);
            StateDirectory::open(&state)
                .unwrap()
                .write(artifact, b"existing state")
                .unwrap();
            assert!(!can_join(&state).unwrap());
        }
        let hosted = temp.path().join("hosted");
        reserve(&hosted, [2; 32]).unwrap();
        PeerTrust::open(&hosted)
            .unwrap()
            .pin(&peer, &peer.fingerprint())
            .unwrap();
        assert!(can_join(&hosted).unwrap());
    }

    #[test]
    fn synchronizes_only_committed_members_and_preserves_pinned_history() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let third = temp.path().join("third");
        let channel = [42; 32];
        let genesis = bootstrap(&first, channel).unwrap();
        apply(&first, channel, &genesis).unwrap();
        std::fs::rename(
            temp.path().join("first.recovery"),
            temp.path().join("offline"),
        )
        .unwrap();
        assert_eq!(bootstrap(&first, channel).unwrap(), genesis);
        assert!(!temp.path().join("first.recovery").exists());
        let join = candidate(&second, &genesis.authority, &genesis.designation).unwrap();
        let other = candidate(&third, &genesis.authority, &genesis.designation).unwrap();
        let peer = join.identity().unwrap();
        let updated = approve(&first, channel, &genesis, &join).unwrap();
        let competing = approve(&first, channel, &genesis, &other).unwrap();
        assert!(
            PeerTrust::open(&first)
                .unwrap()
                .pinned(peer.device_id())
                .is_err()
        );
        assert!(apply(&second, channel, &genesis).is_err());
        assert!(genesis.verify_successor(channel, &updated, &other).is_err());
        genesis.verify_successor(channel, &updated, &join).unwrap();
        for state in [&first, &second] {
            apply(state, channel, &updated).unwrap();
            apply(state, channel, &updated).unwrap();
            let identity = LocalIdentity::load_or_create(state).unwrap();
            let roster = Channel::load(state, &identity, &channel).unwrap();
            assert_eq!(roster.members().len(), 2);
            assert!(roster.allows(peer.device_id(), ChannelPermission::Send));
            assert!(!roster.allows(peer.device_id(), ChannelPermission::Wake));
        }
        assert!(apply(&first, channel, &genesis).is_err());
        assert!(apply(&first, channel, &competing).is_err());
        assert!(approve(&second, channel, &updated, &other).is_err());
        assert!(reserve(&second, [43; 32]).is_err());
        assert!(!second.join(cli::SIGNER).exists());
        assert!(!second.join(cli::ROOT).exists());
    }

    #[test]
    fn registration_rejects_key_substitution_and_unrelated_profiles() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let unrelated = temp.path().join("unrelated");
        let channel = [42; 32];
        let network = bootstrap(&first, channel).unwrap();
        let foreign = bootstrap(&unrelated, [5; 32]).unwrap();
        let mut join = candidate(&second, &network.authority, &network.designation).unwrap();
        assert!(candidate(&second, &foreign.authority, &foreign.designation).is_err());
        join.peer.clone_from(&network.devices[0].peer);
        assert!(
            join.verify(&network.authority, &network.designation)
                .is_err()
        );
        assert!(approve(&first, channel, &network, &join).is_err());
        let legacy = temp.path().join("legacy");
        let file = StateDirectory::open(&legacy).unwrap();
        file.write("authority-pin", b"existing").unwrap();
        assert!(bootstrap(&legacy, channel).is_err());
        assert_eq!(file.read_bounded("authority-pin", 32).unwrap(), b"existing");
        assert!(!legacy.join("hosted-network").exists());
        assert!(!legacy.join(cli::SIGNER).exists());
    }
}
