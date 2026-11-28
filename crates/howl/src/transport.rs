use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use iroh::{
    Endpoint, EndpointId, RelayConfig, RelayMap, TransportAddr, Watcher,
    endpoint::{Connection, QuicTransportConfig, RelayMode, WeakConnectionHandle, presets},
};
pub use iroh::{EndpointAddr, RelayUrl};
use netdev::ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::identity::{LocalIdentity, PeerCertificate, PeerTrust};

const ALPN: &[u8] = b"howl/mesh/1";
pub const MAX_FRAME_BYTES: usize = 77_112;
const FRAME_PREFIX_BYTES: usize = 4;
const CONNECTION_LIMIT: usize = 32;
pub const MAX_REPORTED_PATHS: usize = 2 * CONNECTION_LIMIT;
const RECEIVE_QUEUE_LEN: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const LAN_HEAD_START: Duration = Duration::from_millis(750);
const STREAM_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_RTT: Duration = Duration::from_millis(333);

pub enum Network {
    Direct,
    Hosted,
    Automatic(RelayUrl),
    RelayOnly(RelayUrl),
}

#[derive(Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    Direct,
    Relay,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPath {
    pub device: String,
    pub kind: PathKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_rtt_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_rtt_us: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

struct PathSample {
    kind: PathKind,
    selected: bool,
    rtt: Option<u32>,
    relay: Option<String>,
}

fn relay_for_report(url: &RelayUrl) -> Option<String> {
    (url.scheme() == "https" && url.as_str().len() <= 255).then(|| url.to_string())
}

#[derive(Default)]
struct ActiveConnections(Mutex<Vec<([u8; 32], WeakConnectionHandle)>>);

impl ActiveConnections {
    async fn record(&self, device: [u8; 32], connection: &Connection) {
        let mut connections = self.0.lock().await;
        connections.retain(|(_, handle)| {
            handle
                .upgrade()
                .is_some_and(|connection| connection.close_reason().is_none())
        });
        if connections.len() < MAX_REPORTED_PATHS {
            connections.push((device, connection.weak_handle()));
        }
    }

    async fn paths(&self) -> Vec<PeerPath> {
        let mut paths = BTreeMap::new();
        for (device, handle) in self.0.lock().await.iter() {
            let Some(connection) = handle.upgrade() else {
                continue;
            };
            if connection.close_reason().is_some() {
                continue;
            }
            let samples: Vec<_> = connection
                .paths()
                .iter()
                .filter_map(|path| {
                    let (kind, relay) = match path.remote_addr() {
                        TransportAddr::Ip(_) => (PathKind::Direct, None),
                        TransportAddr::Relay(url) => (PathKind::Relay, relay_for_report(url)),
                        _ => return None,
                    };
                    let stats = path.stats();
                    let received_response = stats.frame_rx.acks > 0
                        || stats.frame_rx.path_acks > 0
                        || stats.frame_rx.path_response > 0;
                    let rtt =
                        if received_response && stats.rtt != INITIAL_RTT && !stats.rtt.is_zero() {
                            u32::try_from(stats.rtt.as_micros().max(1)).ok()
                        } else {
                            None
                        };
                    Some(PathSample {
                        kind,
                        selected: path.is_selected(),
                        rtt,
                        relay,
                    })
                })
                .collect();
            if let Some(selected) = samples.iter().find(|sample| sample.selected) {
                let best = |kind| {
                    samples
                        .iter()
                        .filter(|sample| sample.kind == kind)
                        .min_by_key(|sample| (!sample.selected, sample.rtt.unwrap_or(u32::MAX)))
                };
                let relay = best(PathKind::Relay);
                paths.insert(
                    (*device, selected.kind),
                    PeerPath {
                        device: hex::encode(device),
                        kind: selected.kind,
                        direct_rtt_us: best(PathKind::Direct).and_then(|sample| sample.rtt),
                        relay_rtt_us: relay.and_then(|sample| sample.rtt),
                        relay: relay.and_then(|sample| sample.relay.clone()),
                    },
                );
            }
        }
        paths.into_values().collect()
    }
}

pub struct ReceivedFrame {
    pub peer: PeerCertificate,
    pub bytes: Vec<u8>,
    connection: Connection,
    trust: Arc<PeerTrust>,
}

impl ReceivedFrame {
    pub async fn reply(&self, bytes: &[u8]) -> io::Result<()> {
        validate_frame(bytes)?;
        self.trust
            .authorize(self.peer.device_id(), self.connection.remote_id())?;
        let stream = open_frame(&self.connection).await?;
        write_frame(&self.connection, stream, bytes).await
    }
}

pub struct Transport {
    endpoint: Endpoint,
    relays: RelayMap,
    device_id: [u8; 32],
    trust: Arc<PeerTrust>,
    active: Arc<ActiveConnections>,
    outgoing: Mutex<VecDeque<CachedConnection>>,
    send_slots: Semaphore,
    frames: mpsc::Sender<ReceivedFrame>,
    received: Mutex<mpsc::Receiver<ReceivedFrame>>,
    accepting: JoinHandle<()>,
}

struct CachedConnection {
    device_id: [u8; 32],
    endpoint: EndpointId,
    connection: Arc<Mutex<Option<CachedSession>>>,
}

struct CachedSession {
    connection: Connection,
    receiving: JoinHandle<()>,
}

impl Drop for CachedSession {
    fn drop(&mut self) {
        self.receiving.abort();
        self.connection
            .close(0u32.into(), b"transport cache released");
    }
}

impl Transport {
    pub async fn bind(
        identity: &LocalIdentity,
        trust: PeerTrust,
        network: Network,
        bind_address: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let window = (MAX_FRAME_BYTES + FRAME_PREFIX_BYTES + 1) as u32;
        let config = QuicTransportConfig::builder()
            .initial_rtt(INITIAL_RTT)
            .max_concurrent_uni_streams(1u32.into())
            .max_concurrent_bidi_streams(1u32.into())
            .stream_receive_window(window.into())
            .receive_window((2 * window).into())
            .send_window(u64::from(2 * window))
            .datagram_receive_buffer_size(None)
            .build();
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(identity.transport_key().clone())
            .alpns(vec![ALPN.to_vec()])
            .transport_config(config);
        let relay_mode = match network {
            Network::Direct => RelayMode::Disabled,
            Network::Hosted => iroh::endpoint::default_relay_mode(),
            Network::Automatic(url) => RelayMode::custom([url]),
            Network::RelayOnly(url) => {
                if bind_address.is_some() {
                    return Err(invalid_input(
                        "relay-only transport cannot bind a UDP address",
                    ));
                }
                let relay = RelayConfig::new(url, None);
                builder = builder.clear_ip_transports();
                RelayMode::Custom([relay].into_iter().collect())
            }
        };
        let relays = relay_mode.relay_map();
        builder = builder.relay_mode(relay_mode);
        if let Some(address) = bind_address {
            builder = builder
                .clear_ip_transports()
                .bind_addr(address)
                .map_err(io::Error::other)?;
        }
        let endpoint = builder.bind().await.map_err(io::Error::other)?;
        let device_id = *identity.certificate().device_id();
        let trust = Arc::new(trust);
        let active = Arc::new(ActiveConnections::default());
        let (sender, received) = mpsc::channel(RECEIVE_QUEUE_LEN);
        let accepting = tokio::spawn(accept_connections(
            endpoint.clone(),
            device_id,
            trust.clone(),
            sender.clone(),
            active.clone(),
        ));
        Ok(Self {
            endpoint,
            relays,
            device_id,
            trust,
            active,
            outgoing: Mutex::new(VecDeque::new()),
            send_slots: Semaphore::new(CONNECTION_LIMIT),
            frames: sender,
            received: Mutex::new(received),
            accepting,
        })
    }

    pub fn address(&self) -> EndpointAddr {
        let address = self.endpoint.addr();
        let loopback = self
            .endpoint
            .bound_sockets()
            .into_iter()
            .filter(|address| address.ip().is_loopback())
            .map(iroh::TransportAddr::Ip);
        address.with_addrs(loopback)
    }

    pub(crate) fn allows_relay(&self, relay: &RelayUrl) -> bool {
        self.relays.contains(relay)
    }

    pub(crate) fn lan_networks(&self) -> Vec<IpNet> {
        let sockets = self.endpoint.bound_sockets();
        netdev::get_interfaces()
            .into_iter()
            .filter(|interface| {
                interface.is_up() && !interface.is_loopback() && !interface.is_point_to_point()
            })
            .flat_map(|interface| {
                interface
                    .ipv4
                    .into_iter()
                    .map(IpNet::V4)
                    .chain(interface.ipv6.into_iter().map(IpNet::V6))
            })
            .filter(|network| {
                let ip = network.addr();
                !tailnet_address(ip)
                    && sockets.iter().any(|socket| {
                        socket.ip() == ip
                            || (socket.ip().is_unspecified() && socket.is_ipv4() == ip.is_ipv4())
                    })
            })
            .collect()
    }

    pub async fn wait_for_relay(&self) -> io::Result<()> {
        within(CONNECT_TIMEOUT, async {
            self.endpoint.online().await;
            Ok(())
        })
        .await
    }

    pub(crate) fn connected_relay(&self) -> Option<String> {
        self.endpoint
            .home_relay_status()
            .get()
            .iter()
            .filter(|relay| relay.is_connected())
            .find_map(|relay| relay_for_report(relay.url()))
    }

    pub(crate) async fn peer_paths(&self) -> Vec<PeerPath> {
        self.active.paths().await
    }

    pub async fn send(
        &self,
        peer_device_id: &[u8; 32],
        address: EndpointAddr,
        frame: &[u8],
    ) -> io::Result<()> {
        self.send_authorized(peer_device_id, address, frame, || Ok(()))
            .await
    }

    pub(crate) async fn send_authorized(
        &self,
        peer_device_id: &[u8; 32],
        address: EndpointAddr,
        frame: &[u8],
        authorize: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        validate_frame(frame)?;
        let _slot = within(STREAM_TIMEOUT, async {
            self.send_slots.acquire().await.map_err(io::Error::other)
        })
        .await?;
        let mut connection = self.connect(peer_device_id, address.clone()).await?;
        let stream = match open_frame(&connection).await {
            Ok(stream) => stream,
            Err(_) if connection.close_reason().is_some() => {
                connection = self.connect(peer_device_id, address).await?;
                open_frame(&connection).await?
            }
            Err(error) => {
                connection.close(1u32.into(), b"transport stream unavailable");
                return Err(error);
            }
        };
        authorize()?;
        write_frame(&connection, stream, frame).await
    }

    pub async fn receive(&self) -> Option<ReceivedFrame> {
        self.received.lock().await.recv().await
    }

    pub async fn close(self) {
        self.endpoint.close().await;
        self.accepting.abort();
    }

    async fn connect(&self, device_id: &[u8; 32], address: EndpointAddr) -> io::Result<Connection> {
        self.trust.authorize(device_id, address.id)?;
        let slot = {
            let mut cache = self.outgoing.lock().await;
            let entry = if let Some(index) = cache
                .iter()
                .position(|entry| entry.device_id == *device_id && entry.endpoint == address.id)
            {
                cache.remove(index).expect("cache entry exists")
            } else {
                if cache.len() == CONNECTION_LIMIT {
                    let index = cache
                        .iter()
                        .position(|entry| Arc::strong_count(&entry.connection) == 1)
                        .ok_or_else(|| io::Error::other("transport connection cache is busy"))?;
                    cache.remove(index);
                }
                CachedConnection {
                    device_id: *device_id,
                    endpoint: address.id,
                    connection: Arc::new(Mutex::new(None)),
                }
            };
            let slot = entry.connection.clone();
            cache.push_back(entry);
            slot
        };
        let mut entry = within(CONNECT_TIMEOUT, async { Ok(slot.lock().await) }).await?;
        if let Some(session) = &*entry
            && session.connection.close_reason().is_none()
        {
            return Ok(session.connection.clone());
        }

        let connection = within(CONNECT_TIMEOUT, async {
            let connection = self.dial(address).await?;
            let (mut send, mut receive) = connection.open_bi().await.map_err(io::Error::other)?;
            send.write_all(&self.device_id)
                .await
                .map_err(io::Error::other)?;
            send.finish().map_err(io::Error::other)?;
            let claimed = read_device_id(&mut receive).await?;
            if claimed != *device_id {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "peer claimed an unexpected device ID",
                ));
            }
            self.trust.authorize(&claimed, connection.remote_id())?;
            Ok(connection)
        })
        .await?;

        self.active.record(*device_id, &connection).await;
        let receiving = tokio::spawn(read_frames(
            connection.clone(),
            *device_id,
            self.trust.clone(),
            self.frames.clone(),
        ));
        *entry = Some(CachedSession {
            connection: connection.clone(),
            receiving,
        });
        Ok(connection)
    }

    async fn dial(&self, address: EndpointAddr) -> io::Result<Connection> {
        if address.relay_urls().next().is_some() && address.ip_addrs().next().is_some() {
            let networks = self.lan_networks();
            let local = EndpointAddr::from_parts(
                address.id,
                address
                    .ip_addrs()
                    .filter(|address| on_link(&networks, address.ip()))
                    .copied()
                    .map(iroh::TransportAddr::Ip),
            );
            if !local.is_empty()
                && let Ok(Ok(connection)) =
                    timeout(LAN_HEAD_START, self.endpoint.connect(local, ALPN)).await
            {
                return Ok(connection);
            }
        }
        self.endpoint
            .connect(address, ALPN)
            .await
            .map_err(io::Error::other)
    }
}

pub(crate) fn on_link(networks: &[IpNet], ip: IpAddr) -> bool {
    !tailnet_address(ip) && networks.iter().any(|network| network.contains(&ip))
}

pub(crate) fn tailnet_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.octets()[0] == 100 && ip.octets()[1] >> 6 == 1,
        IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

async fn accept_connections(
    endpoint: Endpoint,
    device_id: [u8; 32],
    trust: Arc<PeerTrust>,
    frames: mpsc::Sender<ReceivedFrame>,
    active: Arc<ActiveConnections>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                if connections.len() >= CONNECTION_LIMIT {
                    incoming.refuse();
                    continue;
                }
                let frames = frames.clone();
                let trust = trust.clone();
                let active = active.clone();
                connections.spawn(async move {
                    let connection = within(CONNECT_TIMEOUT, async {
                        incoming.await.map_err(io::Error::other)
                    }).await?;
                    match accept_peer(&connection, &device_id, &trust).await {
                        Ok(peer) => {
                            active.record(peer, &connection).await;
                            read_frames(connection, peer, trust, frames).await;
                        }
                        Err(_) => connection.close(1u32.into(), b"transport peer rejected"),
                    }
                    Ok::<_, io::Error>(())
                });
            }
        }
    }
}

async fn accept_peer(
    connection: &Connection,
    device_id: &[u8; 32],
    trust: &PeerTrust,
) -> io::Result<[u8; 32]> {
    within(CONNECT_TIMEOUT, async {
        let (mut send, mut receive) = connection.accept_bi().await.map_err(io::Error::other)?;
        let peer_device_id = read_device_id(&mut receive).await?;
        trust.authorize(&peer_device_id, connection.remote_id())?;
        send.write_all(device_id).await.map_err(io::Error::other)?;
        send.finish().map_err(io::Error::other)?;
        Ok(peer_device_id)
    })
    .await
}

async fn read_frames(
    connection: Connection,
    peer_device_id: [u8; 32],
    trust: Arc<PeerTrust>,
    frames: mpsc::Sender<ReceivedFrame>,
) {
    let endpoint = connection.remote_id();
    while let Ok(mut stream) = connection.accept_uni().await {
        let result = within(STREAM_TIMEOUT, async {
            let reserve = frames.reserve();
            let permit = tokio::select! {
                result = reserve => result.map_err(io::Error::other)?,
                error = connection.closed() => return Err(io::Error::other(error)),
            };
            trust.authorize(&peer_device_id, endpoint)?;
            let mut length = [0; FRAME_PREFIX_BYTES];
            stream
                .read_exact(&mut length)
                .await
                .map_err(io::Error::other)?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid transport frame length",
                ));
            }
            let bytes = stream.read_to_end(length).await.map_err(io::Error::other)?;
            if bytes.len() != length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete transport frame",
                ));
            }
            let peer = trust.authorize(&peer_device_id, endpoint)?;
            permit.send(ReceivedFrame {
                peer,
                bytes,
                connection: connection.clone(),
                trust: trust.clone(),
            });
            Ok(())
        })
        .await;
        if result.is_err() {
            connection.close(1u32.into(), b"transport frame rejected");
            return;
        }
    }
}

async fn open_frame(connection: &Connection) -> io::Result<iroh::endpoint::SendStream> {
    within(STREAM_TIMEOUT, async {
        connection.open_uni().await.map_err(io::Error::other)
    })
    .await
}

async fn write_frame(
    connection: &Connection,
    mut stream: iroh::endpoint::SendStream,
    frame: &[u8],
) -> io::Result<()> {
    let result = within(STREAM_TIMEOUT, async {
        let length = (frame.len() as u32).to_be_bytes();
        stream.write_all(&length).await.map_err(io::Error::other)?;
        stream.write_all(frame).await.map_err(io::Error::other)?;
        stream.finish().map_err(io::Error::other)?;
        if stream.stopped().await.map_err(io::Error::other)?.is_some() {
            return Err(io::Error::other("peer stopped the transport frame"));
        }
        Ok(())
    })
    .await;
    if result.is_err() {
        connection.close(1u32.into(), b"transport frame failed");
    }
    result
}

fn validate_frame(frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(invalid_input("invalid transport frame length"));
    }
    Ok(())
}

async fn read_device_id(receive: &mut iroh::endpoint::RecvStream) -> io::Result<[u8; 32]> {
    receive
        .read_to_end(32)
        .await
        .map_err(io::Error::other)?
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed transport identity"))
}

async fn within<T>(
    deadline: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout(deadline, operation)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))?
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests;
