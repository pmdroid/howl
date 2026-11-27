use std::{ffi::OsString, io, path::Path};

use howl_envelope::DeviceAddress;

use crate::identity::{LocalIdentity, StateDirectory};

use super::{
    Floor, Id, Import, Roster, RosterMember, RosterStore, authority::invalid, cli::operator_signer,
    pairing::random, profile::Profile, revoke,
};

pub fn run(args: &[OsString]) -> io::Result<()> {
    let [action, state, channel, rest @ ..] = args else {
        return Err(invalid(
            "expected roster action, state directory and channel",
        ));
    };
    let state = Path::new(state);
    let identity = LocalIdentity::load_or_create(state)?;
    let profile = Profile::load(state, &identity.certificate())?
        .ok_or_else(|| invalid("this device needs a signed enrollment certificate"))?;
    let channel = if action == "issue" && channel == "-" {
        random()?
    } else {
        id(channel.as_encoded_bytes())?
    };
    let store = RosterStore::open(state, channel)?;
    let proof = match (action.to_str(), rest) {
        (Some("issue"), [status, named @ ..]) => {
            let paused = match status.to_str() {
                Some("active") => false,
                Some("paused") => true,
                _ => return Err(invalid("expected active or paused roster")),
            };
            let mut members = named
                .iter()
                .map(|member| {
                    let (device, permissions) = member
                        .to_str()
                        .and_then(|member| member.split_once(':'))
                        .ok_or_else(|| invalid("expected a device ID and permission mask"))?;
                    let device = id(device.as_bytes())?;
                    let permissions = permissions.parse::<u8>().map_err(io::Error::other)?;
                    let certificate = if device == profile.local.device {
                        profile.local.clone()
                    } else {
                        profile.peer(device)?.0
                    };
                    Ok(RosterMember {
                        address: DeviceAddress {
                            account: certificate.account,
                            device,
                        },
                        certificate: certificate.digest,
                        permissions,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?;
            members.sort_unstable_by_key(|member| member.address);
            let signer = operator_signer(&StateDirectory::open(state)?)?;
            let history = store.load(&profile.authority)?;
            let roster = Roster::issue(
                &profile.designation,
                &signer,
                channel,
                history.latest()?,
                paused,
                &members,
            )?;
            store.apply(&profile.authority, &profile.designation, roster.as_bytes())?;
            Some(roster.as_bytes().to_vec())
        }
        (Some("apply"), [record]) => {
            let record = decode_record(record)?;
            if store.apply(&profile.authority, &profile.designation, &record)? == Import::Fork {
                return Err(invalid("verified roster fork recorded"));
            }
            None
        }
        (Some("revoke"), [device, sequence]) => {
            let device = id(device.as_encoded_bytes())?;
            let sequence = sequence
                .to_str()
                .ok_or_else(|| invalid("invalid device sequence"))?
                .parse::<u64>()
                .map_err(io::Error::other)?;
            let signer = operator_signer(&StateDirectory::open(state)?)?;
            let record = revoke(&profile.designation, &signer, Floor { device, sequence })?;
            store.revoke(&profile.authority, &profile.designation, &record)?;
            Some(record)
        }
        (Some("apply-revocation"), [record]) => {
            let record = decode_record(record)?;
            store.revoke(&profile.authority, &profile.designation, &record)?;
            None
        }
        (Some("show"), []) => {
            let history = store.load(&profile.authority)?;
            let current = history
                .latest()?
                .ok_or_else(|| invalid("channel has no signed roster"))?;
            Some(current.as_bytes().to_vec())
        }
        _ => return Err(invalid("invalid roster command")),
    };
    println!("Channel {}", hex::encode(channel));
    if let Some(proof) = proof {
        println!("Proof {}", hex::encode(proof));
    }
    Ok(())
}

fn id(bytes: &[u8]) -> io::Result<Id> {
    let mut id = [0; 32];
    hex::decode_to_slice(bytes, &mut id).map_err(io::Error::other)?;
    Ok(id)
}

fn decode_record(record: &OsString) -> io::Result<Vec<u8>> {
    if record.as_encoded_bytes().len() > 14_000 {
        return Err(invalid("roster proof is too large"));
    }
    hex::decode(record.as_encoded_bytes()).map_err(io::Error::other)
}
