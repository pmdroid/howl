use std::{io, path::Path};

use howl_envelope::{DeviceAddress, inspect_unverified};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::{
    channel::Channel,
    control_client::{ControlClient, read_response},
    delivery::{Device, Id, MAILBOX_OUTBOX_BATCH},
    enrollment::{ChannelPermission, profile::Profile},
    identity::{LocalIdentity, StateDirectory},
    node,
    transport::MAX_FRAME_BYTES,
};

use super::{MailboxEnvelope, MailboxReceipt, ingest};

const PAGE_SIZE: usize = 16;
const MAX_PAGES: usize = 16;
const RESPONSE_LIMIT: usize = PAGE_SIZE * (2 * MAX_FRAME_BYTES + 1024) + 1024;

#[derive(Default)]
pub struct PullReport {
    pub stored: usize,
    pub acknowledged: usize,
    pub unacknowledged: usize,
}

#[derive(Default)]
pub struct DepositReport {
    pub stored: usize,
    pub already_stored: usize,
    pub skipped: usize,
    pub next: Option<i64>,
}

pub async fn deposit(state: &Path, recipient: Id, mut after: i64) -> io::Result<DepositReport> {
    if after < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid mailbox cursor",
        ));
    }
    let account = Profile::account(state)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "hosted mailbox requires an enrolled device",
        )
    })?;
    let control = ControlClient::open(state).await?;
    let identity = control.identity();
    let local = identity.certificate();
    let sender = Device {
        account,
        device: *local.device_id(),
    };
    if recipient == sender.device {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mailbox recipient is the local device",
        ));
    }
    let delivery = node::open_delivery(state, &StateDirectory::open(state)?, &local)?;
    let recipient = Device {
        account,
        device: recipient,
    };
    let mut report = DepositReport::default();
    for _ in 0..MAX_PAGES {
        let page = delivery
            .mailbox_outbox(recipient, after, node::unix_time()?)
            .map_err(io::Error::other)?;
        let more = page.len() > MAILBOX_OUTBOX_BATCH;
        for item in page.into_iter().take(MAILBOX_OUTBOX_BATCH) {
            after = item.cursor;
            if !may_deposit(state, identity, sender, recipient, &item.frame)? {
                report.skipped += 1;
                continue;
            }
            let request = serde_json::json!({
                "recipient": hex::encode(recipient.device),
                "ciphertext": hex::encode(item.frame),
            })
            .to_string();
            let response = control
                .post_json("/v1/mailbox/deposit", "mailbox-deposit", request.as_bytes())
                .await?;
            match response.status() {
                StatusCode::CREATED => report.stored += 1,
                StatusCode::NO_CONTENT => report.already_stored += 1,
                StatusCode::GONE => report.skipped += 1,
                _ => return Err(io::Error::other("hosted mailbox deposit failed")),
            }
        }
        if !more {
            return Ok(report);
        }
    }
    report.next = Some(after);
    Ok(report)
}

fn may_deposit(
    state: &Path,
    identity: &LocalIdentity,
    sender: Device,
    recipient: Device,
    bytes: &[u8],
) -> io::Result<bool> {
    let metadata = inspect_unverified(bytes).map_err(io::Error::other)?;
    let routing = metadata.routing;
    if routing.sender.account != sender.account || routing.sender.device != sender.device {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbox envelope has an unexpected sender",
        ));
    }
    let roster = Channel::load(state, identity, &routing.channel)?;
    let permission = if metadata.intent.requires_wake_permission() {
        ChannelPermission::Wake
    } else {
        ChannelPermission::Send
    };
    Ok(roster.epoch() == routing.epoch
        && roster.allows(&sender.device, permission)
        && roster.allows(&recipient.device, ChannelPermission::Receive))
}

#[derive(Deserialize)]
struct Page {
    envelopes: Vec<HostedEnvelope>,
    next: Option<i64>,
}

#[derive(Deserialize)]
struct HostedEnvelope {
    cursor: i64,
    channel: String,
    epoch: u64,
    sender_account: String,
    sender_device: String,
    sequence: u64,
    message: String,
    sent_at: u64,
    digest: String,
    ciphertext: String,
}

pub async fn pull(state: &Path) -> io::Result<PullReport> {
    let control = ControlClient::open(state).await?;
    let mut report = PullReport::default();
    let mut after = 0;
    for _ in 0..MAX_PAGES {
        let page = fetch(&control, after).await?;
        for row in page.envelopes {
            let Ok(receipt) = row.persist(state) else {
                report.unacknowledged += 1;
                continue;
            };
            report.stored += usize::from(receipt.inserted());
            acknowledge(&control, &receipt).await?;
            report.acknowledged += 1;
        }
        match page.next {
            Some(cursor) => after = cursor,
            None => break,
        }
    }
    Ok(report)
}

async fn fetch(control: &ControlClient, after: i64) -> io::Result<Page> {
    let request = serde_json::json!({ "after": after, "limit": PAGE_SIZE }).to_string();
    let response = control
        .post_json("/v1/mailbox/fetch", "mailbox-fetch", request.as_bytes())
        .await?;
    let body = read_response(response, RESPONSE_LIMIT).await?;
    let page: Page = serde_json::from_slice(&body).map_err(|_| invalid())?;
    if page.envelopes.len() > PAGE_SIZE {
        return Err(invalid());
    }
    let mut last = after;
    for row in &page.envelopes {
        if row.cursor <= last {
            return Err(invalid());
        }
        last = row.cursor;
    }
    if let Some(next) = page.next
        && (next != last || next == after || page.envelopes.len() != PAGE_SIZE)
    {
        return Err(invalid());
    }
    Ok(page)
}

async fn acknowledge(control: &ControlClient, receipt: &MailboxReceipt) -> io::Result<()> {
    let request = serde_json::json!({
        "message": hex::encode(receipt.message()),
        "digest": hex::encode(receipt.digest()),
    })
    .to_string();
    let response = control
        .post_json("/v1/mailbox/ack", "mailbox-ack", request.as_bytes())
        .await?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(io::Error::other("hosted mailbox acknowledgment failed"));
    }
    Ok(())
}

impl HostedEnvelope {
    fn persist(self, state: &Path) -> io::Result<MailboxReceipt> {
        if self.ciphertext.is_empty() || self.ciphertext.len() > 2 * MAX_FRAME_BYTES {
            return Err(invalid());
        }
        let ciphertext = hex::decode(self.ciphertext).map_err(|_| invalid())?;
        ingest(
            state,
            MailboxEnvelope {
                channel: decode_id(&self.channel)?,
                epoch: self.epoch,
                sender: DeviceAddress {
                    account: decode_id(&self.sender_account)?,
                    device: decode_id(&self.sender_device)?,
                },
                sequence: self.sequence,
                message: decode_id(&self.message)?,
                sent_at: self.sent_at,
                digest: decode_id(&self.digest)?,
                ciphertext: &ciphertext,
            },
        )
    }
}

fn decode_id(encoded: &str) -> io::Result<Id> {
    let mut decoded = [0; 32];
    hex::decode_to_slice(encoded, &mut decoded).map_err(|_| invalid())?;
    Ok(decoded)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid hosted mailbox response",
    )
}
