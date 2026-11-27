use std::{io, path::Path};

use howl_envelope::DeviceAddress;

use crate::identity::{PeerCertificate, PeerTrust, StateDirectory};

use super::{
    Authority, AuthorityStore, Designation, DeviceCertificate, Id, Roster, RosterMember,
    RosterStore, cli::operator_signer,
};

const DESIGNATION_FILE: &str = "enrollment-designation";
const CERTIFICATE_FILE: &str = "enrollment-certificate";

pub(crate) struct Profile {
    pub authority: Authority,
    pub designation: Designation,
    pub local: DeviceCertificate,
    state: StateDirectory,
    path: std::path::PathBuf,
    trust: PeerTrust,
}

impl Profile {
    pub(crate) fn load(path: &Path, local: &PeerCertificate) -> io::Result<Option<Self>> {
        let state = StateDirectory::open(path)?;
        let Some(certificate) = local_certificate(&state)? else {
            return Ok(None);
        };
        let authority = AuthorityStore::open(path)?.load()?;
        let designation = Designation::verify(
            &state.read_bounded(DESIGNATION_FILE, 165_000)?,
            authority.head()?,
        )?;
        let local = verify_device(&certificate, &designation, local)?;
        let trust = PeerTrust::open(path)?;
        Ok(Some(Self {
            authority,
            designation,
            local,
            state,
            path: path.to_owned(),
            trust,
        }))
    }

    pub(crate) fn account(path: &Path) -> io::Result<Option<Id>> {
        let state = StateDirectory::open(path)?;
        if local_certificate(&state)?.is_none() {
            return Ok(None);
        }
        Ok(Some(AuthorityStore::open(path)?.load()?.account()))
    }

    pub(crate) fn revocations(&self) -> io::Result<RosterStore> {
        RosterStore::account_revocations(&self.path, self.local.account)
    }

    pub(crate) fn member(&self, device: Id, permissions: u8) -> io::Result<RosterMember> {
        let certificate = if device == self.local.device {
            self.local.clone()
        } else {
            self.peer(device)?.0
        };
        let address = DeviceAddress {
            account: certificate.account,
            device,
        };
        if certificate.sequence
            <= self
                .revocations()?
                .load(&self.authority)?
                .revoked_through(address)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the device certificate has been revoked",
            ));
        }
        Ok(RosterMember {
            address,
            certificate: certificate.digest,
            permissions,
        })
    }

    pub(crate) fn issue(
        &self,
        store: &RosterStore,
        channel: Id,
        paused: bool,
        mut members: Vec<RosterMember>,
    ) -> io::Result<Roster> {
        members.sort_unstable_by_key(|member| member.address);
        let signer = operator_signer(&self.state)?;
        let history = store.load(&self.authority)?;
        let roster = Roster::issue(
            &self.designation,
            &signer,
            channel,
            history.latest()?,
            paused,
            &members,
        )?;
        store.apply(&self.authority, &self.designation, roster.as_bytes())?;
        Ok(roster)
    }

    pub(crate) fn peer(&self, device: Id) -> io::Result<(DeviceCertificate, PeerCertificate)> {
        let peer = self.trust.pinned(&device)?;
        let contents = self
            .state
            .read_bounded(&format!("enrollment-peer-{}", hex::encode(device)), 512)?;
        Ok((verify_device(&contents, &self.designation, &peer)?, peer))
    }
}

fn local_certificate(state: &StateDirectory) -> io::Result<Option<Vec<u8>>> {
    match state.read_bounded(CERTIFICATE_FILE, 512) {
        Ok(certificate) => Ok(Some(certificate)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn verify_device(
    contents: &[u8],
    designation: &Designation,
    peer: &PeerCertificate,
) -> io::Result<DeviceCertificate> {
    let certificate = DeviceCertificate::verify(contents, designation)?;
    if !certificate.matches(peer) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "enrollment certificate does not match the device keys",
        ));
    }
    Ok(certificate)
}
