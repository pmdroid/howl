use std::{io, path::Path};

use howl_envelope::DeviceAddress;
use sha2::{Digest, Sha256};

use crate::{
    delivery::{Acknowledgment, Id},
    identity::{LocalIdentity, StateDirectory},
    node::{self, EnvelopeSource},
};

pub struct MailboxEnvelope<'a> {
    pub channel: Id,
    pub epoch: u64,
    pub sender: DeviceAddress,
    pub sequence: u64,
    pub message: Id,
    pub sent_at: u64,
    pub digest: Id,
    pub ciphertext: &'a [u8],
}

pub struct MailboxReceipt {
    message: Id,
    digest: Id,
    inserted: bool,
    acknowledgment: Acknowledgment,
}

impl MailboxReceipt {
    pub fn message(&self) -> Id {
        self.message
    }

    pub fn digest(&self) -> Id {
        self.digest
    }

    pub fn inserted(&self) -> bool {
        self.inserted
    }

    pub fn acknowledgment(&self) -> &Acknowledgment {
        &self.acknowledgment
    }
}

pub fn ingest(state: &Path, envelope: MailboxEnvelope<'_>) -> io::Result<MailboxReceipt> {
    let metadata =
        howl_envelope::inspect_unverified(envelope.ciphertext).map_err(io::Error::other)?;
    let routing = metadata.routing;
    let digest: Id = Sha256::digest(envelope.ciphertext).into();
    if metadata.message_id != envelope.message
        || routing.channel != envelope.channel
        || routing.epoch != envelope.epoch
        || routing.sender != envelope.sender
        || routing.sequence != envelope.sequence
        || routing.created_at != envelope.sent_at
        || digest != envelope.digest
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mailbox metadata does not match the envelope",
        ));
    }
    let identity = LocalIdentity::load_or_create(state)?;
    let directory = StateDirectory::open(state)?;
    let mut delivery = node::open_delivery(state, &directory, &identity.certificate())?;
    let receipt = node::accept_envelope(
        state,
        &identity,
        &mut delivery,
        envelope.ciphertext,
        metadata,
        EnvelopeSource::Mailbox,
    )?;
    Ok(MailboxReceipt {
        message: metadata.message_id,
        digest,
        inserted: receipt.inserted,
        acknowledgment: receipt.acknowledgment,
    })
}

#[cfg(test)]
mod tests;
