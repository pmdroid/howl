use std::{io, path::Path};

use howl_envelope::DeviceAddress;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::{
    control_client::{ControlClient, read_response},
    delivery::Id,
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
