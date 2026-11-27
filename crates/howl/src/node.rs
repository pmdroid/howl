use std::{
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::VerifyingKey;
use howl_envelope::{
    AgentReply, AuthorizedSender, Body, DeviceAddress, Id, Metadata, ReceivePolicy, Recipient,
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
        ACK_LENGTH, ACK_TAG, Acknowledgment, AdmissionTime, ApprovedAgentReply, DeliveryStore,
        Device, Frame, IntegrationDelivery, IntegrationDispatch, IntegrationRun, NewIntegrationRun,
        Payload, Receipt, Stream, run_fingerprint, valid_integration_owner,
    },
    discovery::{self, HINT_LEN, RouteHint},
    enrollment::{ChannelPermission, profile::Profile},
    identity::{LocalIdentity, PeerCertificate, PeerTrust, StateDirectory},
    interaction::LocalInteraction,
    local_control::{self, ControlServer},
    transport::{EndpointAddr, Network, ReceivedFrame, RelayUrl, Transport},
};

pub const CHAT_LIMIT: usize = 65_532;
pub const WAKE_LIMIT: usize = CHAT_LIMIT - 32;
const INTEGRATION_CHAT_LIMIT: usize = CHAT_LIMIT - 32;
pub(crate) const INTEGRATION_WAKE_LIMIT: usize = WAKE_LIMIT - 32;
const CONTROL_WORKERS: usize = 16;
const DELIVERY_WORKERS: usize = 8;
pub(crate) const DELIVERY_KEY: &str = "delivery.key";
const DELIVERY_DB: &str = "delivery.db";

pub async fn run(state: &Path, listen: &str, relay: Option<&str>) -> io::Result<()> {
    run_node(state, listen, relay, true).await
}

pub async fn run_client(state: &Path, listen: &str, relay: Option<&str>) -> io::Result<()> {
    LocalInteraction::new(state).require_enrolled()?;
    run_node(state, listen, relay, false).await
}

async fn run_node(
    state: &Path,
    listen: &str,
    relay: Option<&str>,
    accepts_wakes: bool,
) -> io::Result<()> {
    let identity = Arc::new(LocalIdentity::load_or_create(state)?);
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
    if accepts_wakes {
        delivery.recover_wakes().map_err(io::Error::other)?;
    }
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
                    if !accepts_wakes && bytes.first() == Some(&b'G') {
                        return Err(forbidden("client-only device cannot grant inbound wake"));
                    }
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
                match accept(state, &identity, &mut delivery, &incoming, accepts_wakes) {
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
                    match target_address(state, &identity, &delivery, relay.as_ref(), &attempt) {
                        Ok(destination) => {
                            let transport = Arc::clone(&transport);
                            let identity = Arc::clone(&identity);
                            let state = state.to_owned();
                            deliveries.spawn(async move {
                                transport.send_authorized(
                                    &attempt.recipient.device,
                                    destination,
                                    &attempt.frame,
                                    || check_outbound(&state, &identity, &attempt),
                                ).await
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

pub fn export_hint(state: &Path, address: SocketAddr) -> io::Result<String> {
    let identity = LocalIdentity::load_or_create(state)?;
    let hint = RouteHint::issue(&identity, address, discovery::now()?)?;
    Ok(hex::encode(hint.as_bytes()))
}

pub fn import_hint(state: &Path, encoded: &str) -> io::Result<()> {
    let mut bytes = [0; HINT_LEN];
    hex::decode_to_slice(encoded, &mut bytes)
        .map_err(|_| invalid("invalid address hint encoding"))?;
    let hint = RouteHint::from_bytes(bytes);
    let peer = PeerTrust::open(state)?.pinned(hint.device())?;
    if hint.address(&peer, discovery::now()?)?.is_none() {
        return Err(invalid("address hint expired"));
    }
    let identity = LocalIdentity::load_or_create(state)?;
    let directory = StateDirectory::open(state)?;
    let delivery = open_delivery(state, &directory, &identity.certificate())?;
    if !delivery.import_hint(&hint).map_err(io::Error::other)? {
        return Err(invalid(
            "address hint is older than or conflicts with the saved hint",
        ));
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
    request_message(state, channel, recipient, route, b'S', message.as_bytes()).await
}

pub(crate) async fn send_channel(state: &Path, channel: Id, text: &str) -> io::Result<String> {
    StateDirectory::open(state)?;
    if text.is_empty() || text.len() > CHAT_LIMIT {
        return Err(invalid("invalid chat length"));
    }
    request_message(state, channel, [0; 32], "-", b'C', text.as_bytes()).await
}

pub(crate) async fn request_peer_cancel(
    state: &Path,
    channel: Id,
    peer: Id,
    route: &str,
    wake: Id,
) -> io::Result<String> {
    StateDirectory::open(state)?;
    request_message(state, channel, peer, route, b'K', &wake).await
}

pub(crate) async fn send_integration_chat(
    state: &Path,
    channel: Id,
    peer: Option<Id>,
    owner: &str,
    text: &str,
) -> io::Result<String> {
    StateDirectory::open(state)?;
    if !valid_integration_owner(owner) || text.is_empty() || text.len() > INTEGRATION_CHAT_LIMIT {
        return Err(invalid("invalid integration chat"));
    }
    let mut body = Vec::with_capacity(1 + owner.len() + text.len());
    body.push(owner.len() as u8);
    body.extend_from_slice(owner.as_bytes());
    body.extend_from_slice(text.as_bytes());
    let (command, peer) = match peer {
        Some(peer) => (b'I', peer),
        None => (b'P', [0; 32]),
    };
    request_message(state, channel, peer, "-", command, &body).await
}

pub async fn send_wake(
    state: &Path,
    channel: Id,
    recipient: Id,
    route: &str,
    target: Id,
    lifetime_secs: u16,
    message: &str,
) -> io::Result<String> {
    StateDirectory::open(state)?;
    let body = encode_wake(target, lifetime_secs, message)?;
    request_message(state, channel, recipient, route, b'W', &body).await
}

pub(crate) fn prepare_integration_run(
    state: &Path,
    request: NewIntegrationRun<'_>,
) -> io::Result<IntegrationRun> {
    LocalInteraction::new(state).authorize(request.channel, ChannelPermission::Wake)?;
    run_delivery(state)?
        .prepare_integration_run(&request, unix_time()?)
        .map_err(integration_error)
}

pub(crate) fn integration_run(
    state: &Path,
    owner: &str,
    id: Id,
) -> io::Result<Option<IntegrationRun>> {
    run_delivery(state)?
        .integration_run(owner, id, unix_time()?)
        .map_err(integration_error)
}

pub(crate) fn cancel_integration_run(
    state: &Path,
    owner: &str,
    id: Id,
) -> io::Result<Option<IntegrationRun>> {
    run_delivery(state)?
        .cancel_integration_run(owner, id, unix_time()?)
        .map_err(integration_error)
}

pub(crate) async fn send_integration_wake(
    state: &Path,
    id: Id,
    request: NewIntegrationRun<'_>,
) -> io::Result<String> {
    if request.text.len() > INTEGRATION_WAKE_LIMIT {
        return Err(invalid("integration wake text is too large"));
    }
    let mut body = id.to_vec();
    body.extend(encode_wake(request.target, request.lifetime, request.text)?);
    request_message(state, request.channel, request.peer, "-", b'T', &body).await
}

fn run_delivery(state: &Path) -> io::Result<DeliveryStore> {
    let identity = LocalIdentity::load_or_create(state)?;
    open_delivery(
        state,
        &StateDirectory::open(state)?,
        &identity.certificate(),
    )
}

fn integration_error(error: crate::delivery::Error) -> io::Error {
    match error {
        crate::delivery::Error::Conflict => invalid("idempotency key is already in use"),
        crate::delivery::Error::InvalidFrame => invalid("invalid integration run"),
        _ => io::Error::other(error),
    }
}

fn encode_wake(target: Id, lifetime_secs: u16, message: &str) -> io::Result<Vec<u8>> {
    if message.is_empty() || message.len() > WAKE_LIMIT || !(1..=300).contains(&lifetime_secs) {
        return Err(invalid("invalid wake text or lifetime"));
    }
    let mut body = Vec::with_capacity(34 + message.len());
    body.extend_from_slice(&target);
    body.extend_from_slice(&lifetime_secs.to_be_bytes());
    body.extend_from_slice(message.as_bytes());
    Ok(body)
}

pub async fn grant_wake(
    state: &Path,
    channel: Id,
    sender: Id,
    target: Id,
    generation: u64,
) -> io::Result<()> {
    StateDirectory::open(state)?;
    let mut request = Vec::with_capacity(105);
    request.push(b'G');
    request.extend_from_slice(&channel);
    request.extend_from_slice(&sender);
    request.extend_from_slice(&target);
    request.extend_from_slice(&generation.to_be_bytes());
    local_control::request(state, &request).await?;
    Ok(())
}

async fn request_message(
    state: &Path,
    channel: Id,
    recipient: Id,
    route: &str,
    command: u8,
    body: &[u8],
) -> io::Result<String> {
    let route = parse_route(route.as_bytes())?;
    let text = route.map_or("-".to_owned(), |address| address.to_string());
    let mut request = Vec::with_capacity(66 + text.len() + body.len());
    request.push(command);
    request.extend_from_slice(&channel);
    request.extend_from_slice(&recipient);
    request.push(text.len() as u8);
    request.extend_from_slice(text.as_bytes());
    request.extend_from_slice(body);
    local_control::request(state, &request).await
}

pub async fn stop(state: &Path) -> io::Result<()> {
    StateDirectory::open(state)?;
    local_control::request(state, b"X").await?;
    Ok(())
}

pub fn read(state: &Path, id: Id) -> io::Result<()> {
    for item in LocalInteraction::new(state).history_messages(id, 100)? {
        let device = hex::encode(item.sender.device);
        let sender = match item.integration {
            Some(actor) => format!("integration {} {device}", hex::encode(actor)),
            None => device,
        };
        match item.body {
            Body::Chat(text) => println!("{sender} {} {text:?}", item.received_at),
            Body::AgentReply(reply) => println!(
                "agent {sender} {} message={} reply-to={} context={} {} {:?}",
                hex::encode(reply.agent),
                hex::encode(item.message),
                hex::encode(reply.in_reply_to),
                hex::encode(reply.context_digest),
                item.received_at,
                reply.text,
            ),
            Body::Wake { session, text } => println!(
                "wake-history {sender} target={} message={} {} {text:?}",
                hex::encode(session),
                hex::encode(item.message),
                item.received_at,
            ),
            Body::CancelWake { wake } => println!("wake-cancel {sender} {}", hex::encode(wake)),
        }
    }
    Ok(())
}

pub fn status(state: &Path, channel: Id, message: Id) -> io::Result<()> {
    let results = LocalInteraction::new(state).delivery_status(channel, message)?;
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
    let (channel, rest) = request
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid mesh channel"))?;
    let (peer, rest) = rest
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid mesh peer"))?;
    if *command == b'G' {
        return enable_grant(state, identity, delivery, *channel, peer, rest);
    }

    let ([route_length], rest) = rest
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid peer route"))?;
    let (route, body) = rest
        .split_at_checked(usize::from(*route_length))
        .ok_or_else(|| invalid("invalid peer route"))?;
    let route = parse_route(route)?;
    if matches!(*command, b'I' | b'P' | b'T') && route.is_some() {
        return Err(invalid("integration operations require a signed route"));
    }
    let post = matches!(*command, b'C' | b'P');
    if post && (*peer != [0; 32] || route.is_some()) {
        return Err(invalid(
            "channel posts use the current signed recipients and routes",
        ));
    }
    if !post && route.is_none() && !has_relay {
        let peer = PeerTrust::open(state)?.pinned(peer)?;
        if cached_address(delivery, &peer)?.is_none() {
            return Err(invalid(
                "peer address, signed address hint, or relay is required",
            ));
        }
    }
    let address = Destination {
        channel: *channel,
        peer: (!post).then_some(*peer),
        route,
        integration: None,
    };
    match command {
        b'S' | b'I' | b'C' | b'P' => {
            let (integration, body) = if matches!(*command, b'I' | b'P') {
                let ([length], body) = body
                    .split_first_chunk()
                    .ok_or_else(|| invalid("missing integration owner"))?;
                let (owner, body) = body
                    .split_at_checked(usize::from(*length))
                    .ok_or_else(|| invalid("invalid integration owner length"))?;
                let owner = std::str::from_utf8(owner).map_err(io::Error::other)?;
                if !valid_integration_owner(owner) {
                    return Err(invalid("invalid integration owner"));
                }
                let actor = integration_actor(identity.certificate().device_id(), owner);
                (Some(IntegrationSource::Chat(actor)), body)
            } else {
                (None, body)
            };
            let text = std::str::from_utf8(body).map_err(io::Error::other)?;
            let text_limit = if integration.is_some() {
                INTEGRATION_CHAT_LIMIT
            } else {
                CHAT_LIMIT
            };
            if text.is_empty() || text.len() > text_limit {
                return Err(invalid("invalid chat length"));
            }
            queue_frame(
                state,
                identity,
                delivery,
                Destination {
                    integration,
                    ..address
                },
                Body::Chat(text),
                0,
                None,
            )
        }
        b'W' | b'T' => {
            let (integration, body) = if *command == b'T' {
                let (id, body) = body
                    .split_first_chunk::<32>()
                    .ok_or_else(|| invalid("invalid integration run"))?;
                (Some(*id), body)
            } else {
                (None, body)
            };
            let (target, rest) = body
                .split_first_chunk()
                .ok_or_else(|| invalid("invalid wake target"))?;
            let (lifetime, bytes) = rest
                .split_first_chunk()
                .ok_or_else(|| invalid("invalid wake lifetime"))?;
            let lifetime = u16::from_be_bytes(*lifetime);
            let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
            let text_limit = if integration.is_some() {
                INTEGRATION_WAKE_LIMIT
            } else {
                WAKE_LIMIT
            };
            if text.is_empty() || text.len() > text_limit || !(1..=300).contains(&lifetime) {
                return Err(invalid("invalid wake text or lifetime"));
            }
            let address = Destination {
                integration: integration.map(|id| {
                    IntegrationSource::Wake(IntegrationDispatch {
                        id,
                        fingerprint: run_fingerprint(*channel, *peer, *target, lifetime, text),
                    })
                }),
                ..address
            };
            queue_frame(
                state,
                identity,
                delivery,
                address,
                Body::Wake {
                    session: *target,
                    text,
                },
                lifetime,
                None,
            )
        }
        b'K' => {
            let wake = body
                .try_into()
                .map_err(|_| invalid("invalid wake cancellation"))?;
            queue_frame(
                state,
                identity,
                delivery,
                address,
                Body::CancelWake { wake },
                0,
                None,
            )
        }
        _ => Err(invalid("invalid mesh command")),
    }
}

fn enable_grant(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    channel: Id,
    peer: &Id,
    bytes: &[u8],
) -> io::Result<String> {
    let (target, generation) = bytes
        .split_first_chunk()
        .ok_or_else(|| invalid("invalid wake grant target"))?;
    let generation = u64::from_be_bytes(
        generation
            .try_into()
            .map_err(|_| invalid("invalid wake grant generation"))?,
    );
    let roster = Channel::load(state, identity, &channel)?;
    let sender = channel_peer(
        &roster,
        &identity.certificate(),
        peer,
        ChannelPermission::Wake,
    )?;
    delivery
        .set_epoch(channel, roster.epoch())
        .map_err(io::Error::other)?;
    delivery
        .establish_wake_time(unix_time()?)
        .map_err(io::Error::other)?;
    delivery
        .enable_network_wake_target(channel, device_for(state, sender)?, *target, generation)
        .map_err(io::Error::other)?;
    Ok("granted".to_owned())
}

struct Destination {
    channel: Id,
    peer: Option<Id>,
    route: Option<SocketAddr>,
    integration: Option<IntegrationSource>,
}

enum IntegrationSource {
    Chat(Id),
    Wake(IntegrationDispatch),
}

enum ReplyDispatch<'a> {
    Wake(ApprovedAgentReply<&'a str>),
    Conversation(i64),
}

fn integration_actor(gateway: &Id, owner: &str) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"howl/integration-actor/v1\0");
    hash.update(gateway);
    hash.update(owner.as_bytes());
    hash.finalize().into()
}

pub fn queue_agent_reply(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    channel: Id,
    recipient: Id,
    route: &str,
    approved: ApprovedAgentReply<&str>,
) -> io::Result<String> {
    queue_frame(
        state,
        identity,
        delivery,
        Destination {
            channel,
            peer: Some(recipient),
            route: parse_route(route.as_bytes())?,
            integration: None,
        },
        Body::AgentReply(approved.reply),
        0,
        Some(ReplyDispatch::Wake(approved)),
    )
}

pub(crate) fn queue_ongoing_reply(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    thread: crate::delivery::OngoingThread,
    route: &str,
    publication: &crate::delivery::OngoingPublication,
) -> io::Result<String> {
    let role = howl_envelope::AgentRole::default();
    let agent = role.agent_id(identity.certificate().device_id());
    queue_frame(
        state,
        identity,
        delivery,
        Destination {
            channel: thread.channel,
            peer: Some(thread.peer.device),
            route: parse_route(route.as_bytes())?,
            integration: None,
        },
        Body::AgentReply(howl_envelope::AgentReply {
            agent,
            role,
            in_reply_to: publication.source,
            context_digest: Sha256::digest([thread.scope, publication.source].as_flattened())
                .into(),
            text: &publication.result,
        }),
        0,
        Some(ReplyDispatch::Conversation(publication.id)),
    )
}

fn queue_frame(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    destination: Destination,
    body: Body<&str>,
    lifetime: u16,
    approved: Option<ReplyDispatch<'_>>,
) -> io::Result<String> {
    let Destination {
        channel,
        peer,
        route,
        integration,
    } = destination;
    let roster = Channel::load(state, identity, &channel)?;
    let local = identity.certificate();
    let permission = match &body {
        Body::Wake { .. } | Body::CancelWake { .. } => ChannelPermission::Wake,
        Body::Chat(_) | Body::AgentReply(_) => ChannelPermission::Send,
    };
    if !roster.allows(local.device_id(), permission) {
        return Err(forbidden(
            "local device lacks the required signed channel permission",
        ));
    }
    let peers = match peer {
        Some(peer) => vec![channel_peer(
            &roster,
            &local,
            &peer,
            ChannelPermission::Receive,
        )?],
        None => roster
            .members()
            .iter()
            .filter(|peer| {
                peer.device_id() != local.device_id()
                    && roster.allows(peer.device_id(), ChannelPermission::Receive)
            })
            .collect(),
    };
    if peers.is_empty() {
        return Err(forbidden("channel has no other signed recipients"));
    }
    let integration = match integration {
        None => None,
        Some(IntegrationSource::Chat(actor)) => Some(IntegrationDelivery {
            actor,
            dispatch: None,
        }),
        Some(IntegrationSource::Wake(dispatch)) => {
            let (owner, message) = delivery
                .integration_dispatch(dispatch, unix_time()?)
                .map_err(integration_error)?;
            if let Some(message) = message {
                return Ok(format!("queued {}", hex::encode(message)));
            }
            Some(IntegrationDelivery {
                actor: integration_actor(local.device_id(), &owner),
                dispatch: Some(dispatch),
            })
        }
    };
    let stream = local_stream(state, channel, &local)?;
    delivery
        .set_epoch(channel, roster.epoch())
        .map_err(io::Error::other)?;
    let sequence = delivery
        .reserve_sequence(stream)
        .map_err(io::Error::other)?;
    let now = unix_time()?;
    let expires_at = if lifetime == 0 {
        0
    } else {
        now.checked_add(u64::from(lifetime))
            .ok_or_else(|| invalid("invalid wake deadline"))?
    };
    let key_seed = zeroize::Zeroizing::new(identity.signing_key().to_bytes());
    let signer = howl_envelope::SigningKey::from_bytes(&key_seed);
    if matches!(&body, Body::AgentReply(_)) != approved.is_some() {
        return Err(invalid("invalid reply approval"));
    }
    let routing = Routing {
        channel,
        sender: address(stream.sender),
        epoch: roster.epoch(),
        sequence,
        created_at: now,
        expires_at,
    };
    let devices = peers
        .iter()
        .map(|peer| device_for(state, peer))
        .collect::<io::Result<Vec<_>>>()?;
    let recipients = devices
        .iter()
        .copied()
        .zip(peers)
        .map(|(device, peer)| recipient(device, peer))
        .collect::<Vec<_>>();
    let sealed = match integration {
        Some(attribution) => howl_envelope::seal_integration(
            routing,
            body.clone(),
            &signer,
            &recipients,
            attribution.actor,
        ),
        None => howl_envelope::seal(routing, body.clone(), &signer, &recipients),
    }
    .map_err(io::Error::other)?;
    let metadata = howl_envelope::inspect_unverified(&sealed).map_err(io::Error::other)?;
    let outbound = frame(metadata);
    if let Some(attribution) = integration {
        let message = delivery
            .enqueue_integration(outbound, &sealed, &devices, body, now, attribution)
            .map_err(integration_error)?;
        return Ok(format!("queued {}", hex::encode(message)));
    }
    if peer.is_none() {
        delivery
            .enqueue_channel_message(outbound, &sealed, &devices, body, now)
            .map_err(io::Error::other)?;
        return Ok(format!("queued {}", hex::encode(metadata.message_id)));
    }
    let route = route.map_or("-".to_owned(), |address| address.to_string());
    let target = devices[0];
    match approved {
        Some(ReplyDispatch::Wake(approved)) => {
            delivery.enqueue_agent_reply(outbound, &sealed, target, &route, unix_time, approved)
        }
        Some(ReplyDispatch::Conversation(turn)) => {
            let Body::AgentReply(reply) = body else {
                return Err(invalid("invalid conversation reply"));
            };
            let message = delivery
                .enqueue_ongoing_reply(outbound, &sealed, target, &route, turn, reply)
                .map_err(io::Error::other)?;
            return Ok(format!("queued {}", hex::encode(message)));
        }
        None => {
            let visible = (!matches!(&body, Body::CancelWake { .. })).then_some(body);
            delivery.enqueue_routed_message(outbound, &sealed, target, &route, now, visible)
        }
    }
    .map_err(io::Error::other)?;
    Ok(format!("queued {}", hex::encode(metadata.message_id)))
}

fn channel_peer<'a>(
    roster: &'a Channel,
    local: &PeerCertificate,
    id: &Id,
    permission: ChannelPermission,
) -> io::Result<&'a PeerCertificate> {
    roster
        .members()
        .iter()
        .find(|member| member.device_id() == id)
        .filter(|member| member.device_id() != local.device_id() && roster.allows(id, permission))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer is outside the channel or is the local device",
            )
        })
}

fn target_address(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &DeliveryStore,
    relay: Option<&RelayUrl>,
    attempt: &crate::delivery::Attempt,
) -> io::Result<EndpointAddr> {
    check_outbound(state, identity, attempt)?;
    let peer = PeerTrust::open(state)?.pinned(&attempt.recipient.device)?;
    if device_for(state, &peer)? != attempt.recipient {
        return Err(invalid(
            "stored peer route does not match the pinned device",
        ));
    }
    let explicit = parse_route(attempt.route.as_deref().unwrap_or("-").as_bytes())?;
    let address = match explicit {
        Some(address) => Some(address),
        None => match cached_address(delivery, &peer) {
            Ok(address) => address,
            Err(_) if relay.is_some() => None,
            Err(error) => return Err(error),
        },
    };
    let mut destination = EndpointAddr::new(peer.endpoint());
    if let Some(address) = address {
        destination = destination.with_ip_addr(address);
    } else if relay.is_none() {
        return Err(invalid(
            "peer address, signed address hint, or relay is required",
        ));
    }
    if let Some(url) = relay {
        destination = destination.with_relay_url(url.clone());
    }
    Ok(destination)
}

fn check_outbound(
    state: &Path,
    identity: &LocalIdentity,
    attempt: &crate::delivery::Attempt,
) -> io::Result<()> {
    let metadata = howl_envelope::inspect_unverified(&attempt.frame).map_err(io::Error::other)?;
    let roster = Channel::load(state, identity, &metadata.routing.channel)?;
    let permission = if metadata.intent.requires_wake_permission() {
        ChannelPermission::Wake
    } else {
        ChannelPermission::Send
    };
    if roster.epoch() != metadata.routing.epoch
        || !roster.allows(identity.certificate().device_id(), permission)
        || !roster.allows(&attempt.recipient.device, ChannelPermission::Receive)
    {
        return Err(forbidden(
            "outbox frame no longer has current signed channel authority",
        ));
    }
    Ok(())
}

fn cached_address(
    delivery: &DeliveryStore,
    peer: &PeerCertificate,
) -> io::Result<Option<SocketAddr>> {
    match delivery
        .peer_hint(peer.device_id())
        .map_err(io::Error::other)?
    {
        Some(hint) => hint.address(peer, discovery::now()?),
        None => Ok(None),
    }
}

fn accept(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    incoming: &ReceivedFrame,
    accepts_wakes: bool,
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
            .apply_ack(&ack, device_for(state, peer)?, &key)
            .map_err(io::Error::other)?;
        return Ok(None);
    }

    let unverified = howl_envelope::inspect_unverified(bytes).map_err(io::Error::other)?;
    if !accepts_wakes && unverified.intent.is_wake() {
        return Err(forbidden("client-only device cannot receive wakes"));
    }
    let receipt = accept_envelope(
        state,
        identity,
        delivery,
        bytes,
        unverified,
        EnvelopeSource::Peer(peer),
    )?;
    Ok(Some(receipt.acknowledgment))
}

pub(crate) enum EnvelopeSource<'a> {
    Peer(&'a PeerCertificate),
    Mailbox,
}

pub(crate) fn accept_envelope(
    state: &Path,
    identity: &LocalIdentity,
    delivery: &mut DeliveryStore,
    bytes: &[u8],
    unverified: Metadata,
    source: EnvelopeSource<'_>,
) -> io::Result<Receipt> {
    let local = identity.certificate();
    let peer_pin;
    let peer = match source {
        EnvelopeSource::Peer(peer) => peer,
        EnvelopeSource::Mailbox => {
            if unverified.routing.sender.device == *local.device_id() {
                return Err(invalid("mailbox envelope claims the local sender"));
            }
            peer_pin = PeerTrust::open(state)?.pinned(&unverified.routing.sender.device)?;
            &peer_pin
        }
    };
    let mailbox = matches!(source, EnvelopeSource::Mailbox);
    let roster = Channel::load(state, identity, &unverified.routing.channel)?;
    let wake = unverified.intent.is_wake();
    let permission = if unverified.intent.requires_wake_permission() {
        ChannelPermission::Wake
    } else {
        ChannelPermission::Send
    };
    if !roster.allows(peer.device_id(), permission) {
        return Err(forbidden(
            "sender lacks the required signed channel permission",
        ));
    }
    if !roster.allows(local.device_id(), ChannelPermission::Receive) {
        return Err(forbidden(
            "local device lacks the signed channel receive permission",
        ));
    }
    let account = Profile::account(state)?;
    let allowed = roster
        .members()
        .iter()
        .filter(|member| roster.allows(member.device_id(), ChannelPermission::Receive))
        .map(|member| recipient(device_with_account(member, account), member))
        .collect::<Vec<_>>();
    let key = zeroize::Zeroizing::new(identity.encryption_key().to_bytes());
    let secret = RecipientSecret::from_bytes(address(device_with_account(&local, account)), &key)
        .map_err(io::Error::other)?;
    let now = unix_time()?;
    if wake && !mailbox {
        delivery.observe_wake_time(now).map_err(io::Error::other)?;
        if !delivery
            .wake_sender_authorized(*roster.id(), device_with_account(peer, account))
            .map_err(io::Error::other)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sender has no wake grant",
            ));
        }
    }
    let policy = ReceivePolicy {
        channel: *roster.id(),
        epoch: roster.epoch(),
        now,
        sender: AuthorizedSender {
            address: address(device_with_account(peer, account)),
            signing_key: peer.signing_public(),
            chat: true,
            wake: unverified.intent.requires_wake_permission(),
        },
        authorized_recipients: &allowed,
    };
    let opened = if mailbox {
        howl_envelope::open_history(bytes, &policy, &secret)
    } else {
        howl_envelope::open(bytes, &policy, &secret)
    }
    .map_err(io::Error::other)?;
    delivery
        .set_epoch(*roster.id(), roster.epoch())
        .map_err(io::Error::other)?;
    let metadata = frame(opened.metadata);
    let payload = match &opened.body {
        Body::Chat(text) => Payload::Chat(text),
        Body::Wake { session, text } => Payload::Wake {
            target: *session,
            text,
        },
        Body::CancelWake { wake } => Payload::CancelWake { wake: *wake },
        Body::AgentReply(reply) => Payload::AgentReply(AgentReply {
            agent: reply.agent,
            role: reply.role,
            in_reply_to: reply.in_reply_to,
            context_digest: reply.context_digest,
            text: &reply.text,
        }),
    };
    let time = if mailbox {
        AdmissionTime::MailboxHistory(now)
    } else if wake {
        AdmissionTime::NetworkWake(&unix_time)
    } else {
        AdmissionTime::Known(now)
    };
    delivery
        .accept_payload(
            metadata,
            bytes,
            payload,
            time,
            opened.integration,
            identity.signing_key(),
        )
        .map_err(io::Error::other)
}

pub(crate) fn history_delivery(
    state: &Path,
    identity: &LocalIdentity,
    channel: Id,
) -> io::Result<(DeliveryStore, Stream)> {
    let local = identity.certificate();
    let directory = StateDirectory::open(state)?;
    if Channel::history_is_enrolled(state, identity, &channel)? {
        let delivery = open_delivery(state, &directory, &local)?;
        return Ok((delivery, local_stream(state, channel, &local)?));
    }
    let key = directory.key(DELIVERY_KEY)?;
    let device = device_with_account(&local, None);
    let delivery =
        DeliveryStore::open(&state.join(DELIVERY_DB), &key, device).map_err(io::Error::other)?;
    Ok((delivery, stream_from_device(channel, &local, device)))
}

pub(crate) fn open_delivery(
    state: &Path,
    directory: &StateDirectory,
    local: &PeerCertificate,
) -> io::Result<DeliveryStore> {
    let account = Profile::account(state)?;
    let key = directory.key(DELIVERY_KEY)?;
    let database = if account.is_some() {
        "delivery-enrolled.db"
    } else {
        DELIVERY_DB
    };
    DeliveryStore::open(
        &state.join(database),
        &key,
        device_with_account(local, account),
    )
    .map_err(io::Error::other)
}

fn address(device: Device) -> DeviceAddress {
    DeviceAddress {
        account: device.account,
        device: device.device,
    }
}

pub(crate) fn device_for(state: &Path, cert: &PeerCertificate) -> io::Result<Device> {
    Ok(device_with_account(cert, Profile::account(state)?))
}

fn device_with_account(cert: &PeerCertificate, account: Option<Id>) -> Device {
    Device {
        account: account.unwrap_or_else(|| cert.manual_account_id()),
        device: *cert.device_id(),
    }
}

fn recipient(device: Device, cert: &PeerCertificate) -> Recipient {
    Recipient {
        address: address(device),
        encryption_key: cert.encryption_public(),
    }
}

pub(crate) fn local_stream(
    state: &Path,
    channel: Id,
    certificate: &PeerCertificate,
) -> io::Result<Stream> {
    Ok(stream_from_device(
        channel,
        certificate,
        device_for(state, certificate)?,
    ))
}

fn stream_from_device(channel: Id, certificate: &PeerCertificate, device: Device) -> Stream {
    let mut hash = Sha256::new();
    hash.update(b"howl/key/v1/device-signing\0");
    hash.update(certificate.signing_public());
    Stream {
        channel,
        sender: device,
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

pub(crate) fn parse_route(route: &[u8]) -> io::Result<Option<SocketAddr>> {
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

pub(crate) fn unix_time() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(io::Error::other)
}

fn forbidden(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod integration_tests {
    use howl_envelope::{AgentRole, Intent};

    use super::*;

    #[test]
    fn integration_channel_post_uses_one_envelope_for_the_signed_roster() {
        let temp = tempfile::tempdir().unwrap();
        let gateway = temp.path().join("gateway");
        let sender = LocalIdentity::load_or_create(&gateway).unwrap();
        let peers = ["first", "second"].map(|name| {
            let identity = LocalIdentity::load_or_create(&temp.path().join(name)).unwrap();
            let peer = identity.certificate();
            PeerTrust::open(&gateway)
                .unwrap()
                .pin(&peer, &peer.fingerprint())
                .unwrap();
            peer
        });
        let channel = Channel::create(
            &gateway,
            &sender,
            &peers.each_ref().map(|peer| *peer.device_id()),
        )
        .unwrap();
        let channel = *channel.id();
        let mut outbox = run_delivery(&gateway).unwrap();
        let mut request = vec![b'P'];
        request.extend(channel);
        request.extend([0; 32]);
        request.extend(b"\x01-\x06sourcechannel discussion");
        let receipt = queue(&gateway, &sender, &mut outbox, false, &request).unwrap();
        let frames = outbox
            .claim_due(Some(channel), unix_time().unwrap(), 10)
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].frame, frames[1].frame);
        assert_ne!(frames[0].recipient, frames[1].recipient);
        let metadata = howl_envelope::inspect_unverified(&frames[0].frame).unwrap();
        assert_eq!(
            receipt,
            format!("queued {}", hex::encode(metadata.message_id))
        );
        let events = outbox.channel_events(channel, 0, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].recipient, None);
        let local = device_for(&gateway, &sender.certificate()).unwrap();
        for attempt in frames {
            assert!(
                outbox
                    .direct_events(channel, local, attempt.recipient, 0, 10)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn integration_chat_and_run_sign_the_same_owner_across_the_wire() {
        let temp = tempfile::tempdir().unwrap();
        let gateway = temp.path().join("gateway");
        let receiver = temp.path().join("receiver");
        let sender = LocalIdentity::load_or_create(&gateway).unwrap();
        let recipient = LocalIdentity::load_or_create(&receiver).unwrap();
        let sender_cert = sender.certificate();
        let recipient_cert = recipient.certificate();
        let peer = *recipient_cert.device_id();
        PeerTrust::open(&gateway)
            .unwrap()
            .pin(&recipient_cert, &recipient_cert.fingerprint())
            .unwrap();
        PeerTrust::open(&receiver)
            .unwrap()
            .pin(&sender_cert, &sender_cert.fingerprint())
            .unwrap();
        let channel = Channel::create(&gateway, &sender, &[peer]).unwrap();
        Channel::join(&receiver, &recipient, channel.manifest()).unwrap();
        let channel = *channel.id();
        let mut outbox = run_delivery(&gateway).unwrap();
        let mut inbox = run_delivery(&receiver).unwrap();
        let owner = "review-source";

        let command = |operation, body: &[u8]| {
            let mut command = vec![operation];
            command.extend_from_slice(&channel);
            command.extend_from_slice(&peer);
            command.extend_from_slice(b"\x01-");
            command.extend_from_slice(body);
            command
        };
        let mut chat = vec![owner.len() as u8];
        chat.extend_from_slice(owner.as_bytes());
        chat.extend_from_slice(b"private note from the connector");
        queue(&gateway, &sender, &mut outbox, true, &command(b'I', &chat)).unwrap();

        let request = NewIntegrationRun {
            owner,
            key: "review-once",
            channel,
            peer,
            target: AgentRole::Reviewer.agent_id(&peer),
            lifetime: 60,
            text: "review the selected documents",
        };
        let run = outbox
            .prepare_integration_run(&request, unix_time().unwrap())
            .unwrap();
        let mut wake = run.id.to_vec();
        wake.extend(encode_wake(request.target, request.lifetime, request.text).unwrap());
        let wake = command(b'T', &wake);
        let first = queue(&gateway, &sender, &mut outbox, true, &wake).unwrap();
        assert_eq!(
            queue(&gateway, &sender, &mut outbox, true, &wake).unwrap(),
            first
        );
        let actor = Some(integration_actor(sender_cert.device_id(), owner));
        let events = outbox.channel_events(channel, 0, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.message.integration == actor)
        );

        let frames = outbox
            .claim_due(Some(channel), unix_time().unwrap(), 10)
            .unwrap();
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().any(|frame| {
            howl_envelope::inspect_unverified(&frame.frame)
                .unwrap()
                .intent
                == Intent::IntegrationWake
        }));
        let chat = frames
            .iter()
            .find(|frame| {
                howl_envelope::inspect_unverified(&frame.frame)
                    .unwrap()
                    .intent
                    == Intent::IntegrationChat
            })
            .unwrap();
        accept_envelope(
            &receiver,
            &recipient,
            &mut inbox,
            &chat.frame,
            howl_envelope::inspect_unverified(&chat.frame).unwrap(),
            EnvelopeSource::Peer(&sender_cert),
        )
        .unwrap();
        let events = inbox.channel_events(channel, 0, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message.integration, actor);
        assert_ne!(
            actor,
            Some(integration_actor(sender_cert.device_id(), "other-reviewer"))
        );
    }
}
