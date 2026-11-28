use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::{Duration, Instant},
};

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    control_client::{self, ControlClient, read_response},
    delivery::Id,
    discovery_client,
    enrollment::hosted::{self, Candidate, Network},
    identity::{LocalIdentity, PeerCertificate, StateDirectory, retry_state_lock},
    transport::Transport,
};

const PIN: &str = "hosted-network-origin";
const MAX_STATE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Membership {
    Legacy,
    Founder,
    Pending,
    Approved,
    Denied,
}

impl Membership {
    fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Founder => "founder",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

#[derive(Deserialize)]
struct Status {
    state: Membership,
    #[serde(default)]
    account_managed: bool,
    network: Option<String>,
    founder: Option<String>,
    snapshot: Option<Network>,
    authority: Vec<String>,
    designation: Option<String>,
    pending: Vec<Candidate>,
}

impl Status {
    fn origin(&self, local: &Id) -> io::Result<(Id, Id)> {
        let network = id(self.network.as_deref())?;
        let founder = id(self.founder.as_deref())?;
        if self.account_managed && self.state == Membership::Founder
            || !self.account_managed && (self.state == Membership::Founder) != (*local == founder)
        {
            return Err(invalid("network founder identity mismatch"));
        }
        Ok((network, founder))
    }

    fn snapshot(&self, founder: &Id) -> io::Result<&Network> {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid("missing network membership"))?;
        if !(self.account_managed && snapshot.pin()?.0 == *founder)
            && snapshot
                .devices
                .first()
                .ok_or_else(|| invalid("empty network"))?
                .identity()?
                .device_id()
                != founder
        {
            return Err(invalid("network certificate does not match the founder"));
        }
        Ok(snapshot)
    }
}

#[derive(Serialize)]
struct DeviceIdentity {
    id: String,
    fingerprint: String,
}

impl From<PeerCertificate> for DeviceIdentity {
    fn from(peer: PeerCertificate) -> Self {
        Self {
            id: hex::encode(peer.device_id()),
            fingerprint: hex::encode(peer.fingerprint()),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct DeviceRequests {
    membership: &'static str,
    local: DeviceIdentity,
    pending: Vec<DeviceIdentity>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn id(value: Option<&str>) -> io::Result<Id> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(value.unwrap_or_default(), &mut bytes)
        .map_err(|_| invalid("invalid network identity"))?;
    Ok(bytes)
}

async fn status(client: &ControlClient) -> io::Result<Status> {
    let response = client
        .signed(Method::GET, "/v1/network", "network-read", &[], None)
        .await?;
    if response.status() == StatusCode::CONFLICT {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Sign in to your Howl control plane in a browser to create your network, then run howl control devices with this state directory.",
        ));
    }
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(Status {
            state: Membership::Legacy,
            account_managed: false,
            network: None,
            founder: None,
            snapshot: None,
            authority: Vec::new(),
            designation: None,
            pending: Vec::new(),
        });
    }
    serde_json::from_slice(&read_response(response, MAX_STATE).await?).map_err(io::Error::other)
}

async fn post(
    client: &ControlClient,
    path: &str,
    op: &str,
    body: &impl Serialize,
) -> io::Result<()> {
    let response = client
        .post_json(path, op, &serde_json::to_vec(body)?)
        .await?;
    match response.status() {
        StatusCode::NO_CONTENT => Ok(()),
        StatusCode::CONFLICT => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Network membership changed. Refresh the device list and retry.",
        )),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "The control plane did not authorize this request.",
        )),
        status => Err(io::Error::other(format!(
            "Network request failed with HTTP {status}"
        ))),
    }
}

fn pin(state: &Path, network: Id, founder: Id) -> io::Result<()> {
    let directory = StateDirectory::open(state)?;
    let expected = [network, founder].concat();
    match directory.read_bounded(PIN, 64) {
        Ok(current) if current == expected => return Ok(()),
        Ok(_) => {
            return Err(invalid(
                "this profile is already linked to a different network",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    hosted::reserve(state, network)?;
    if directory.write(PIN, &expected)? || directory.read_bounded(PIN, 64)? == expected {
        return Ok(());
    }
    Err(invalid("another network is already linked to this profile"))
}

async fn sync(
    state: &Path,
    client: &ControlClient,
    previous: &mut Option<Id>,
) -> io::Result<Status> {
    let mut view = status(client).await?;
    if view.state == Membership::Legacy {
        if state.join(PIN).try_exists()? {
            return Err(invalid("hosted network no longer matches this device"));
        }
        return Ok(view);
    }
    let (network, founder) = view.origin(client.identity().certificate().device_id())?;
    retry_state_lock(|| pin(state, network, founder)).await?;
    match view.state {
        Membership::Founder if view.snapshot.is_none() => {
            let bootstrap = retry_state_lock(|| hosted::bootstrap(state, network)).await?;
            post(client, "/v1/network/approve", "network-approve", &bootstrap).await?;
            view = status(client).await?;
            if view.state != Membership::Founder
                || id(view.network.as_deref())? != network
                || id(view.founder.as_deref())? != founder
            {
                return Err(invalid("network changed during setup"));
            }
        }
        Membership::Pending => {
            if let Some(designation) = &view.designation {
                let request = hosted::candidate(state, &view.authority, designation)?;
                post(client, "/v1/network/devices", "network-register", &request).await?;
            }
            return Ok(view);
        }
        Membership::Denied => return Ok(view),
        _ => {}
    }
    let snapshot = view.snapshot(&founder)?;
    let digest: Id = Sha256::digest(serde_json::to_vec(snapshot)?).into();
    if *previous != Some(digest) {
        retry_state_lock(|| hosted::apply(state, network, snapshot)).await?;
        *previous = Some(digest);
    }
    Ok(view)
}

pub async fn login(state: &Path) -> io::Result<()> {
    network_login(state, control_client::LoginMode::Hosted(None)).await
}

pub async fn login_with_name(state: &Path, name: &str) -> io::Result<()> {
    let name = control_client::device_name(name)?;
    network_login(state, control_client::LoginMode::Hosted(Some(name))).await
}

pub async fn login_with_device_code(state: &Path) -> io::Result<()> {
    network_login(state, control_client::LoginMode::DeviceCode).await
}

async fn network_login(state: &Path, mode: control_client::LoginMode<'_>) -> io::Result<()> {
    if !hosted::can_join(state)? {
        if matches!(mode, control_client::LoginMode::Hosted(Some(_))) {
            return Err(io::Error::other(
                "Device names are available when linking a device to a hosted network.",
            ));
        }
        control_client::login(state).await?;
        println!(
            "Existing mesh profile signed in. Use a fresh state directory to join a hosted network."
        );
        return Ok(());
    }
    control_client::login_device(state, mode).await?;
    devices(state).await
}

pub async fn devices(state: &Path) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
    let view = sync(state, &client, &mut None).await?;
    let local = client.identity().certificate();
    println!("Device {}", hex::encode(local.device_id()));
    println!("Fingerprint {}", hex::encode(local.fingerprint()));
    if let Some(network) = &view.network {
        println!("Network {network}");
    }
    println!("Membership {}", view.state.name());
    if let Some(snapshot) = view.snapshot {
        for device in snapshot.devices {
            println!("Approved {}", hex::encode(device.identity()?.device_id()));
        }
    }
    for candidate in view.pending {
        println!("Pending {}", hex::encode(candidate.identity()?.device_id()));
    }
    Ok(())
}

pub async fn approve(state: &Path, device: Id) -> io::Result<()> {
    approve_request(state, device, None).await?;
    println!("Approved {}", hex::encode(device));
    Ok(())
}

pub async fn transfer(state: &Path) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
    let view = pinned_status(state, &client).await?;
    let local = client.identity().certificate();
    if id(view.founder.as_deref())? != *local.device_id() {
        return Err(invalid("transfer requires the original founding device"));
    }
    if view.account_managed {
        println!("This network already uses GitHub account approvals.");
        return Ok(());
    }
    let snapshot = view.snapshot(local.device_id())?;
    snapshot.verify(id(view.network.as_deref())?)?;
    let signer = crate::enrollment::cli::operator_signer(&StateDirectory::open(state)?)?;
    if signer.verifying_key().to_bytes() != snapshot.signer()? {
        return Err(invalid("local signing key does not match the network"));
    }
    #[derive(Serialize)]
    struct Transfer<'a> {
        signer: &'a str,
    }
    let seed = zeroize::Zeroizing::new(hex::encode(signer.as_bytes()));
    post(
        &client,
        "/v1/network/transfer",
        "network-transfer",
        &Transfer { signer: &seed },
    )
    .await?;
    println!("GitHub account approvals are enabled for this network.");
    Ok(())
}

async fn pinned_status(state: &Path, client: &ControlClient) -> io::Result<Status> {
    let view = status(client).await?;
    if view.state == Membership::Legacy {
        return Err(invalid("hosted network no longer matches this device"));
    }
    let (network, founder) = view.origin(client.identity().certificate().device_id())?;
    if StateDirectory::open(state)?.read_bounded(PIN, 64)? != [network, founder].concat() {
        return Err(invalid("hosted network no longer matches this device"));
    }
    Ok(view)
}

pub(crate) async fn device_requests(state: &Path) -> io::Result<DeviceRequests> {
    let local = LocalIdentity::load_or_create(state)?.certificate().into();
    let mut list = DeviceRequests {
        membership: "unconfigured",
        local,
        pending: Vec::new(),
    };
    if !configured(state)? {
        if ControlClient::has_credentials(state)? {
            list.membership = "legacy";
        }
        return Ok(list);
    }
    let client = ControlClient::open(state).await?;
    let view = pinned_status(state, &client).await?;
    list.membership = view.state.name();
    if view.state == Membership::Founder {
        for candidate in &view.pending {
            let designation = view
                .designation
                .as_deref()
                .ok_or_else(|| invalid("missing network designation"))?;
            list.pending
                .push(candidate.verify(&view.authority, designation)?.into());
        }
    }
    Ok(list)
}

async fn founder(state: &Path) -> io::Result<(ControlClient, Status)> {
    if !configured(state)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "This device does not manage a hosted network.",
        ));
    }
    let client = ControlClient::open(state).await?;
    let view = pinned_status(state, &client).await?;
    if view.state != Membership::Founder {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Only the founding device can decide a device request.",
        ));
    }
    Ok((client, view))
}

fn check_fingerprint(peer: &PeerCertificate, expected: Option<Id>) -> io::Result<()> {
    if expected.is_some_and(|value| value != peer.fingerprint()) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Device fingerprint changed. Refresh the requests and compare it again.",
        ));
    }
    Ok(())
}

pub(crate) async fn approve_request(
    state: &Path,
    device: Id,
    fingerprint: Option<Id>,
) -> io::Result<()> {
    let (client, view) = founder(state).await?;
    let network = id(view.network.as_deref())?;
    let current = view.snapshot(client.identity().certificate().device_id())?;
    retry_state_lock(|| hosted::apply(state, network, current)).await?;
    for member in &current.devices {
        let peer = member.identity()?;
        if peer.device_id() == &device {
            return check_fingerprint(&peer, fingerprint);
        }
    }
    for candidate in &view.pending {
        let peer = candidate.identity()?;
        if peer.device_id() == &device {
            check_fingerprint(&peer, fingerprint)?;
            let next = hosted::approve(state, network, current, candidate)?;
            post(&client, "/v1/network/approve", "network-approve", &next).await?;
            retry_state_lock(|| hosted::apply(state, network, &next)).await?;
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No pending request for this device.",
    ))
}

pub(crate) async fn deny_request(state: &Path, device: Id, fingerprint: Id) -> io::Result<()> {
    let (client, _) = founder(state).await?;
    post(
        &client,
        "/v1/network/deny",
        "network-deny",
        &serde_json::json!({
            "device": hex::encode(device),
            "fingerprint": hex::encode(fingerprint),
        }),
    )
    .await
}

pub(crate) fn configured(state: &Path) -> io::Result<bool> {
    state.join(PIN).try_exists()
}

pub(crate) async fn await_approval(state: &Path) -> io::Result<()> {
    loop {
        let client = ControlClient::open(state).await?;
        let membership = sync(state, &client, &mut None).await?.state;
        if membership == Membership::Denied {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "The founder denied this device request.",
            ));
        }
        if membership != Membership::Pending {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

pub(crate) async fn discover(state: &Path, transport: &Transport, bind: Option<SocketAddr>) {
    let mut previous = None;
    let mut published = None;
    let mut last_error = None;
    let mut fetched = HashMap::new();
    loop {
        let result = refresh_routes(
            state,
            transport,
            bind,
            &mut previous,
            &mut published,
            &mut fetched,
        )
        .await;
        match result {
            Ok(()) => last_error = None,
            Err(error) => {
                let message = error.to_string();
                if last_error.as_ref() != Some(&message) {
                    eprintln!("Hosted discovery will retry. {message}");
                    last_error = Some(message);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn refresh_routes(
    state: &Path,
    transport: &Transport,
    bind: Option<SocketAddr>,
    previous: &mut Option<Id>,
    published: &mut Option<(SocketAddr, Instant)>,
    fetched: &mut HashMap<Id, Instant>,
) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
    let view = sync(state, &client, previous).await?;
    let snapshot = view
        .snapshot
        .ok_or_else(|| invalid("device is awaiting membership"))?;
    let endpoint = transport.address();
    let address = endpoint
        .ip_addrs()
        .copied()
        .filter(|addr| addr.port() > 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast())
        .min_by_key(|addr| {
            let explicit = bind.is_some_and(|bind| bind.ip() == addr.ip());
            let tailnet = match addr.ip() {
                IpAddr::V4(ip) => ip.octets()[0] == 100 && ip.octets()[1] >> 6 == 1,
                IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
            };
            (
                !explicit,
                addr.ip().is_loopback(),
                !tailnet,
                !addr.is_ipv4(),
            )
        });
    if let Some(address) = address
        && published
            .as_ref()
            .is_none_or(|(last, at)| *last != address || at.elapsed() > Duration::from_secs(3600))
    {
        discovery_client::publish_with(&client, address).await?;
        *published = Some((address, Instant::now()));
    }
    let local = *client.identity().certificate().device_id();
    for device in &snapshot.devices {
        let target = *device.identity()?.device_id();
        if target != local
            && fetched
                .get(&target)
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(60))
            && discovery_client::fetch_with(state, &client, target).await?
        {
            fetched.insert(target, Instant::now());
        }
    }
    Ok(())
}
