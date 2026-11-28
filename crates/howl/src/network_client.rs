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
    identity::StateDirectory,
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
}

#[derive(Deserialize)]
struct Status {
    state: Membership,
    network: Option<String>,
    founder: Option<String>,
    snapshot: Option<Network>,
    authority: Vec<String>,
    designation: Option<String>,
    pending: Vec<Candidate>,
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
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(Status {
            state: Membership::Legacy,
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
        StatusCode::CONFLICT => Err(io::Error::other(
            "Network membership changed. Refresh the device list and retry.",
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
    let network = id(view.network.as_deref())?;
    let founder = id(view.founder.as_deref())?;
    let local = *client.identity().certificate().device_id();
    if (view.state == Membership::Founder) != (local == founder) {
        return Err(invalid("network founder identity mismatch"));
    }
    pin(state, network, founder)?;
    match view.state {
        Membership::Founder if view.snapshot.is_none() => {
            let bootstrap = hosted::bootstrap(state, network)?;
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
        _ => {}
    }
    let snapshot = view
        .snapshot
        .as_ref()
        .ok_or_else(|| invalid("missing network membership"))?;
    if snapshot
        .devices
        .first()
        .ok_or_else(|| invalid("empty network"))?
        .identity()?
        .device_id()
        != &founder
    {
        return Err(invalid("network certificate does not match the founder"));
    }
    let digest: Id = Sha256::digest(serde_json::to_vec(snapshot)?).into();
    if *previous != Some(digest) {
        hosted::apply(state, network, snapshot)?;
        *previous = Some(digest);
    }
    Ok(view)
}

pub async fn login(state: &Path) -> io::Result<()> {
    if !hosted::can_join(state)? {
        control_client::login(state).await?;
        println!(
            "Existing mesh profile signed in. Use a fresh state directory to join a hosted network."
        );
        return Ok(());
    }
    control_client::login_device(state, true).await?;
    devices(state).await
}

pub async fn devices(state: &Path) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
    let view = sync(state, &client, &mut None).await?;
    println!(
        "Device {}",
        hex::encode(client.identity().certificate().device_id())
    );
    if let Some(network) = &view.network {
        println!("Network {network}");
    }
    println!(
        "Membership {}",
        match view.state {
            Membership::Founder => "founder",
            Membership::Pending => "pending",
            Membership::Approved => "approved",
            Membership::Legacy => "legacy",
        }
    );
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
    let client = ControlClient::open(state).await?;
    let view = sync(state, &client, &mut None).await?;
    if view.state != Membership::Founder {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Only the founding device can approve a device.",
        ));
    }
    let network = id(view.network.as_deref())?;
    let current = view
        .snapshot
        .ok_or_else(|| invalid("missing network membership"))?;
    for member in &current.devices {
        if member.identity()?.device_id() == &device {
            println!("Approved {}", hex::encode(device));
            return Ok(());
        }
    }
    for candidate in &view.pending {
        if candidate.identity()?.device_id() == &device {
            let next = hosted::approve(state, network, &current, candidate)?;
            post(&client, "/v1/network/approve", "network-approve", &next).await?;
            hosted::apply(state, network, &next)?;
            println!("Approved {}", hex::encode(device));
            return Ok(());
        }
    }
    Err(invalid("no pending request for this device"))
}

pub(crate) fn configured(state: &Path) -> io::Result<bool> {
    state.join(PIN).try_exists()
}

pub(crate) async fn await_approval(state: &Path) -> io::Result<()> {
    loop {
        let client = ControlClient::open(state).await?;
        let membership = sync(state, &client, &mut None).await?.state;
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
