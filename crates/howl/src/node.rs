use std::{
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::VerifyingKey;
use howl_envelope::{
    AuthorizedSender, Body, DeviceAddress, Id, Intent, Metadata, ReceivePolicy, Recipient,
    RecipientSecret, Routing,
};
use sha2::{Digest, Sha256};
use tokio::{
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};

use crate::{
    channel::Channel,
    delivery::{
        ACK_LENGTH, ACK_TAG, Acknowledgment, DeliveryStore, Device, Frame, Payload, Stream,
    },
    identity::{LocalIdentity, PeerCertificate, PeerTrust, StateDirectory},
    local_control::{self, ControlServer},
    transport::{EndpointAddr, Network, ReceivedFrame, RelayUrl, Transport},
};

const EPOCH: u64 = 1;
pub const CHAT_LIMIT: usize = 65_532;
const CONTROL_WORKERS: usize = 16;
const DELIVERY_WORKERS: usize = 8;
const DELIVERY_KEY: &str = "delivery.key";
const DELIVERY_DB: &str = "delivery.db";

pub async fn run(state: &Path, listen: &str, relay: Option<&str>) -> io::Result<()> {
    let identity = LocalIdentity::load_or_create(state)?;
    let local = identity.certificate();
    let directory = StateDirectory::open(state)?;
    let control = ControlServer::bind(state)?;
    let relay = relay.map(parse_relay).transpose()?;
    let bind = if listen == "-" {
        None
    } else {
        Some(listen.parse::<SocketAddr>().map_err(io::Error::other)?)
    };
    let network = match (&relay, bind) {
        (Some(relay), None) => Network::RelayOnly(relay.clone()),
        (Some(relay), Some(_)) => Network::Automatic(relay.clone()),
        (None, _) => Network::Direct,
    };
    let transport =
        Arc::new(Transport::bind(&identity, PeerTrust::open(state)?, network, bind).await?);
    let mut delivery = open_delivery(state, &directory, &local)?;
    let address = transport.address();
    for ip in address.ip_addrs() {
        println!("Listening {ip}");
    }
    if let Some(url) = &relay {
        println!("Relay {url}");
    }
    println!("Ready {}", hex::encode(local.device_id()));

    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut controls = JoinSet::new();
    let mut replies = JoinSet::new();
    let mut deliveries = JoinSet::new();
    let stop_link = loop {
        tokio::select! {
            result = control.listener.accept(), if controls.len() + replies.len() < CONTROL_WORKERS => {
                let (mut link, _) = result?;
                controls.spawn(async move {
                    let request = local_control::read_request(&mut link).await;
                    (link, request)
                });
            }
            completed = controls.join_next(), if !controls.is_empty() => {
                let Some(Ok((mut link, request))) = completed else { continue; };
                if matches!(&request, Ok(bytes) if bytes == b"X") {
                    break Some(link);
                }
                let queued = request.and_then(|bytes| {
                    queue(state, &identity, &mut delivery, relay.is_some(), &bytes)
                });
                replies.spawn(async move { local_control::reply(&mut link, queued).await });
            }
            reply = replies.join_next(), if !replies.is_empty() => {
                if let Some(Ok(Err(error))) = reply {
                    eprintln!("Mesh control reply failed. {error}");
                }
            }
            incoming = transport.receive(), if deliveries.len() < DELIVERY_WORKERS => {
                let Some(incoming) = incoming else { break None; };
                match accept(state, &identity, &mut delivery, &incoming) {
                    Ok(Some(ack)) => {
                        deliveries.spawn(async move { incoming.reply(ack.as_bytes()).await });
                    }
                    Ok(None) => {}
                    Err(error) => eprintln!("Rejected mesh frame. {error}"),
                }
            }
            _ = tick.tick(), if deliveries.len() < DELIVERY_WORKERS => {
                let slots = DELIVERY_WORKERS - deliveries.len();
                let attempts = delivery.claim_due(None, unix_time()?, slots).map_err(io::Error::other)?;
                for attempt in attempts {
                    match target_address(state, relay.as_ref(), &attempt) {
                        Ok(destination) => {
                            let transport = Arc::clone(&transport);
                            deliveries.spawn(async move {
                                transport.send(&attempt.recipient.device, destination, &attempt.frame).await
                            });
                        }
                        Err(error) => eprintln!("Delivery queued for retry. {error}"),
                    }
                }
            }
            result = deliveries.join_next(), if !deliveries.is_empty() => {
                if let Some(Ok(Err(error))) = result {
                    eprintln!("Delivery will retry. {error}");
                }
            }
        }
    };
    controls.shutdown().await;
    replies.shutdown().await;
    deliveries.shutdown().await;
    let transport = Arc::into_inner(transport).expect("mesh owns the transport after workers stop");
    transport.close().await;
    drop(control);
    if let Some(mut link) = stop_link {
        local_control::reply(&mut link, Ok("stopped".to_owned())).await?;
    }
    Ok(())
}

pub async fn send(
    state: &Path,
    channel: Id,
    recipient: Id,
    route: &str,
    message: &str,
) -> io::Result<String> {
    StateDirectory::open(state)?;
    if message.is_empty() || message.len() > CHAT_LIMIT {
        return Err(invalid("invalid chat length"));
    }
    let route = parse_route(route.as_bytes())?;
    let text = route.map_or("-".to_owned(), |address| address.to_string());
    let mut request = Vec::with_capacity(66 + text.len() + message.len());
    request.push(b'S');
    request.extend_from_slice(&channel);
    request.extend_from_slice(&recipient);
    request.push(text.len() as u8);
    request.extend_from_slice(text.as_bytes());
    request.extend_from_slice(message.as_bytes());
    local_control::request(state, &request).await
}

pub async fn stop(state: &Path) -> io::Result<()> {
    StateDirectory::open(state)?;
    local_control::request(state, b"X").await?;
    Ok(())
}

pub fn read(state: &Path, id: Id) -> io::Result<()> {
    let identity = LocalIdentity::load_or_create(state)?;
    Channel::load(state, &identity, &id)?;
    let delivery = open_delivery(
        state,
        &StateDirectory::open(state)?,
        &identity.certificate(),
    )?;
    for item in delivery.chat_history(id, 100).map_err(io::Error::other)? {
        println!(
            "{} {} {:?}",
            hex::encode(item.sender.device),
            item.received_at,
            item.body
        );
    }
    Ok(())
}

pub fn status(state: &Path, channel: Id, message: Id) -> io::Result<()> {
    let identity = LocalIdentity::load_or_create(state)?;
    Channel::load(state, &identity, &channel)?;
    let local = identity.certificate();
    let delivery = open_delivery(state, &StateDirectory::open(state)?, &local)?;
    let results = delivery
        .delivery_status(local_stream(channel, &local), message)
        .map_err(io::Error::other)?;
    if results.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "unknown outgoing message",
        ));
    }
    for result in results {
        let state = if result.acknowledged {
            "delivered"
        } else {
            "queued"
        };
        println!(
            "{} {state} attempts={}",
            hex::encode(result.recipient.device),
            result.attempts
        );
    }
    Ok(())
}

fn queue(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    has_relay: bool,
    request: &[u8],
) -> io::Result<String> {
    let ([command], request) = request
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid mesh command"))?;
    if *command != b'S' {
        return Err(invalid("invalid mesh command"));
    }
    let (channel, rest) = request
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid chat channel"))?;
    let (peer, rest) = rest
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid chat recipient"))?;
    let ([route_length], rest) = rest
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid peer route"))?;
    let (route, text) = rest
        .split_at_checked(usize::from(*route_length))
        .ok_or_else(|| invalid("invalid peer route"))?;
    let route = parse_route(route)?;
    if route.is_none() && !has_relay {
        return Err(invalid("peer address or relay is required"));
    }
    let text = std::str::from_utf8(text).map_err(io::Error::other)?;
    let roster = Channel::load(state, identity, channel)?;
    let local = identity.certificate();
    let target = roster
        .members()
        .iter()
        .find(|member| member.device_id() == peer)
        .filter(|member| member.device_id() != local.device_id())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "recipient is outside the channel or is the local device",
            )
        })?;
    let stream = local_stream(*channel, &local);
    delivery
        .set_epoch(*channel, EPOCH)
        .map_err(io::Error::other)?;
    let sequence = delivery
        .reserve_sequence(stream)
        .map_err(io::Error::other)?;
    let now = unix_time()?;
    let key_seed = zeroize::Zeroizing::new(identity.signing_key().to_bytes());
    let signer = howl_envelope::SigningKey::from_bytes(&key_seed);
    let sealed = howl_envelope::seal(
        Routing {
            channel: *channel,
            sender: address(&local),
            epoch: EPOCH,
            sequence,
            created_at: now,
            expires_at: 0,
        },
        Body::Chat(text),
        &signer,
        &[recipient(target)],
    )
    .map_err(io::Error::other)?;
    let metadata = howl_envelope::inspect_unverified(&sealed).map_err(io::Error::other)?;
    let route = route.map_or("-".to_owned(), |address| address.to_string());
    delivery
        .enqueue_routed(frame(metadata), &sealed, device(target), &route, now)
        .map_err(io::Error::other)?;
    Ok(format!("queued {}", hex::encode(metadata.message_id)))
}

fn target_address(
    state: &Path,
    relay: Option<&RelayUrl>,
    attempt: &crate::delivery::Attempt,
) -> io::Result<EndpointAddr> {
    let peer = PeerTrust::open(state)?.pinned(&attempt.recipient.device)?;
    if device(&peer) != attempt.recipient {
        return Err(invalid(
            "stored peer route does not match the pinned device",
        ));
    }
    let route = attempt
        .route
        .as_deref()
        .ok_or_else(|| invalid("peer route is missing"))?;
    let mut destination = EndpointAddr::new(peer.endpoint());
    if let Some(address) = parse_route(route.as_bytes())? {
        destination = destination.with_ip_addr(address);
    } else if relay.is_none() {
        return Err(invalid("peer address or relay is required"));
    }
    if let Some(url) = relay {
        destination = destination.with_relay_url(url.clone());
    }
    Ok(destination)
}

fn accept(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    incoming: &ReceivedFrame,
) -> io::Result<Option<Acknowledgment>> {
    let bytes = &incoming.bytes;
    let peer = &incoming.peer;
    if bytes.first() == Some(&ACK_TAG) {
        let bytes: [u8; ACK_LENGTH] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid delivery acknowledgment length"))?;
        let ack = Acknowledgment::from_bytes(bytes);
        let key = VerifyingKey::from_bytes(&peer.signing_public()).map_err(io::Error::other)?;
        delivery
            .apply_ack(&ack, device(peer), &key)
            .map_err(io::Error::other)?;
        return Ok(None);
    }

    let unverified = howl_envelope::inspect_unverified(bytes).map_err(io::Error::other)?;
    if unverified.intent != Intent::Chat {
        return Err(invalid("unsupported message intent"));
    }
    let roster = Channel::load(state, identity, &unverified.routing.channel)?;
    if !roster
        .members()
        .iter()
        .any(|member| member.device_id() == peer.device_id())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sender is outside the channel",
        ));
    }
    let allowed: Vec<_> = roster.members().iter().map(recipient).collect();
    let key = zeroize::Zeroizing::new(identity.encryption_key().to_bytes());
    let local = identity.certificate();
    let secret = RecipientSecret::from_bytes(address(&local), &key).map_err(io::Error::other)?;
    let now = unix_time()?;
    let policy = ReceivePolicy {
        channel: *roster.id(),
        epoch: EPOCH,
        now,
        sender: AuthorizedSender {
            address: address(peer),
            signing_key: peer.signing_public(),
            chat: true,
            wake: false,
        },
        authorized_recipients: &allowed,
    };
    let message = howl_envelope::open(bytes, &policy, &secret).map_err(io::Error::other)?;
    let Body::Chat(text) = message.body else {
        return Err(invalid("unsupported message intent"));
    };
    delivery
        .set_epoch(*roster.id(), EPOCH)
        .map_err(io::Error::other)?;
    let accepted = delivery
        .accept_authenticated(
            frame(message.metadata),
            bytes,
            Payload::Chat(&text),
            now,
            identity.signing_key(),
        )
        .map_err(io::Error::other)?;
    Ok(Some(accepted.acknowledgment))
}

fn open_delivery(
    state: &Path,
    directory: &StateDirectory,
    local: &PeerCertificate,
) -> io::Result<DeliveryStore> {
    let key = directory.key(DELIVERY_KEY)?;
    DeliveryStore::open(&state.join(DELIVERY_DB), &key, device(local)).map_err(io::Error::other)
}

fn address(cert: &PeerCertificate) -> DeviceAddress {
    DeviceAddress {
        account: cert.manual_account_id(),
        device: *cert.device_id(),
    }
}

fn device(cert: &PeerCertificate) -> Device {
    let address = address(cert);
    Device {
        account: address.account,
        device: address.device,
    }
}

fn recipient(cert: &PeerCertificate) -> Recipient {
    Recipient {
        address: address(cert),
        encryption_key: cert.encryption_public(),
    }
}

fn local_stream(channel: Id, certificate: &PeerCertificate) -> Stream {
    let mut hash = Sha256::new();
    hash.update(b"howl/key/v1/device-signing\0");
    hash.update(certificate.signing_public());
    Stream {
        channel,
        sender: device(certificate),
        signing_key: hash.finalize().into(),
    }
}

fn frame(metadata: Metadata) -> Frame {
    let routing = metadata.routing;
    Frame {
        stream: Stream {
            channel: routing.channel,
            sender: Device {
                account: routing.sender.account,
                device: routing.sender.device,
            },
            signing_key: metadata.signing_key_id,
        },
        message: metadata.message_id,
        sequence: routing.sequence,
        epoch: routing.epoch,
        created_at: routing.created_at,
        expires_at: routing.expires_at,
    }
}

fn parse_route(route: &[u8]) -> io::Result<Option<SocketAddr>> {
    if route == b"-" {
        return Ok(None);
    }
    let value = std::str::from_utf8(route).map_err(io::Error::other)?;
    value
        .parse::<SocketAddr>()
        .map(Some)
        .map_err(io::Error::other)
}

fn parse_relay(value: &str) -> io::Result<RelayUrl> {
    value.parse().map_err(io::Error::other)
}

fn unix_time() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(io::Error::other)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
