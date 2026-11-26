use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use howl::{
    delivery::{DeliveryStore, Device},
    identity::{LocalIdentity, PeerTrust},
    transport::{EndpointAddr, Network, Transport},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let [state, channel, route] = args.as_slice() else {
        return Err("use STATE CHANNEL ADDRESS".into());
    };
    let state = Path::new(state).canonicalize()?;
    if !state
        .to_string_lossy()
        .starts_with("/private/tmp/hwl-2506.")
    {
        return Err("expected disposable PAS-2506 fixture state".into());
    }
    let mut channel_id = [0; 32];
    hex::decode_to_slice(channel, &mut channel_id)?;
    let identity = LocalIdentity::load_or_create(&state)?;
    let certificate = identity.certificate();
    let mut account = Sha256::new();
    account.update(b"howl/manual-account/v1\0");
    account.update(certificate.device_id());
    let device = Device {
        account: account.finalize().into(),
        device: *certificate.device_id(),
    };
    let mut key = Zeroizing::new([0; 32]);
    File::open(state.join("delivery.key"))?.read_exact(&mut key[..])?;
    let mut store = DeliveryStore::open(&state.join("delivery.db"), &key, device)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut attempt = store
        .claim_due(Some(channel_id), now + 300, 1)?
        .pop()
        .ok_or_else(|| io::Error::other("no queued fixture envelope"))?;
    if attempt.route.as_deref() != Some("127.0.0.1:9") {
        return Err("queued envelope was not the disposable mutation fixture".into());
    }
    let index = attempt
        .frame
        .len()
        .checked_sub(81)
        .ok_or("short envelope")?;
    attempt.frame[index] ^= 0x80;
    let trust = PeerTrust::open(&state)?;
    let recipient = trust.pinned(&attempt.recipient.device)?;
    let endpoint = Transport::bind(&identity, trust, Network::Direct, None).await?;
    let address = EndpointAddr::new(recipient.endpoint()).with_ip_addr(route.parse()?);
    endpoint
        .send(recipient.device_id(), address, &attempt.frame)
        .await?;
    if let Ok(response) = tokio::time::timeout(Duration::from_secs(2), endpoint.receive()).await
        && response.is_some()
    {
        return Err("received an application response to a corrupted envelope".into());
    }
    println!("sent a mutated ciphertext byte over authenticated transport; no ACK");
    endpoint.close().await;
    Ok(())
}
