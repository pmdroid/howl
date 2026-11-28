use std::{io, net::SocketAddr, path::Path};

use reqwest::{Method, StatusCode, header};

use crate::{
    control_client::{ControlClient, read_response},
    delivery::Id,
    discovery::{self, HINT_LEN, MAX_ROUTE_SET_LEN, RouteHint, Routes},
    identity::PeerTrust,
    node,
    transport::Transport,
};

pub const MESH_STATUS_OPERATION: &str = "mesh-status";
pub const MESH_STATUS_PATH: &str = "/v1/discovery/status";

pub(crate) async fn report_status(state: &Path, transport: &Transport) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(10));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        let _ = send_status(state, transport).await;
    }
}

async fn send_status(state: &Path, transport: &Transport) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
    let paths = transport.peer_paths().await;
    let report = serde_json::json!({"paths": &paths, "home_relay": transport.connected_relay()});
    let body = serde_json::to_vec(&report)?;
    let mut response = client
        .post_json("/v2/discovery/status", MESH_STATUS_OPERATION, &body)
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        let legacy: Vec<_> = paths
            .iter()
            .map(|path| serde_json::json!({"device":path.device,"kind":path.kind}))
            .collect();
        let body = serde_json::to_vec(&legacy)?;
        response = client
            .post_json(MESH_STATUS_PATH, MESH_STATUS_OPERATION, &body)
            .await?;
    }
    if response.status() != StatusCode::NO_CONTENT {
        return Err(refused());
    }
    Ok(())
}

pub async fn publish(state: &Path, address: SocketAddr) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
    publish_with(&client, address).await
}

pub(crate) async fn publish_with(client: &ControlClient, address: SocketAddr) -> io::Result<()> {
    let identity = client.identity();
    let hint = RouteHint::issue(identity, address, discovery::now()?)?;
    if publish_hint(client, "/v1/discovery/hints", hint.as_bytes()).await? != StatusCode::NO_CONTENT
    {
        return Err(refused());
    }
    Ok(())
}

pub(crate) async fn publish_routes(client: &ControlClient, routes: &Routes) -> io::Result<()> {
    let payload = discovery::sign_routes(client.identity(), routes, discovery::now()?)?;
    let status = publish_hint(client, "/v2/discovery/hints", &payload).await?;
    if !matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_FOUND) {
        return Err(refused());
    }
    if let Some(address) = routes.addresses.first() {
        publish_with(client, *address).await?;
    }
    Ok(())
}

async fn publish_hint(
    client: &ControlClient,
    path: &str,
    payload: &[u8],
) -> io::Result<StatusCode> {
    let certificate = client.identity().certificate();
    let body = [certificate.as_bytes().as_slice(), payload].concat();
    Ok(client
        .signed(
            Method::POST,
            path,
            "discovery-write",
            &body,
            Some(("application/octet-stream", &body)),
        )
        .await?
        .status())
}

pub async fn fetch(state: &Path, target: Id) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
    if fetch_with(state, &client, target).await? {
        Ok(())
    } else {
        Err(refused())
    }
}

pub(crate) async fn fetch_with(
    state: &Path,
    client: &ControlClient,
    target: Id,
) -> io::Result<bool> {
    let peer = PeerTrust::open(state)?.pinned(&target)?;
    let Some(bytes) = fetch_hint(client, 1, &target, HINT_LEN).await? else {
        return Ok(false);
    };
    let hint = RouteHint::from_bytes(bytes.as_slice().try_into().map_err(|_| refused())?);
    if hint.address(&peer, discovery::now()?)?.is_none() {
        return Err(refused());
    }
    node::import_hint(state, &hex::encode(hint.as_bytes()))?;
    Ok(true)
}

pub(crate) async fn fetch_routes(
    state: &Path,
    client: &ControlClient,
    target: Id,
) -> io::Result<bool> {
    if let Some(bytes) = fetch_hint(client, 2, &target, MAX_ROUTE_SET_LEN).await? {
        node::import_routes(state, &target, &bytes)?;
        return Ok(true);
    }
    fetch_with(state, client, target).await
}

async fn fetch_hint(
    client: &ControlClient,
    version: u8,
    target: &Id,
    max_len: usize,
) -> io::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let path = format!("/v{version}/discovery/hints/{}", hex::encode(target));
    let response = client
        .signed(Method::GET, &path, "discovery-read", target, None)
        .await?;
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND
    ) {
        return Ok(None);
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(refused());
    }
    Ok(Some(read_response(response, max_len).await?))
}

fn refused() -> io::Error {
    io::Error::other("hosted discovery request failed")
}
