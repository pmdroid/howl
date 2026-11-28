use std::{io, net::SocketAddr, path::Path};

use reqwest::{Method, StatusCode, header};

use crate::{
    control_client::{ControlClient, read_response},
    delivery::Id,
    discovery::{self, HINT_LEN, RouteHint},
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
    let body = serde_json::to_vec(&transport.peer_paths().await)?;
    let response = client
        .post_json(MESH_STATUS_PATH, MESH_STATUS_OPERATION, &body)
        .await?;
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
    let body = [
        identity.certificate().as_bytes().as_slice(),
        hint.as_bytes(),
    ]
    .concat();
    let response = client
        .signed(
            Method::POST,
            "/v1/discovery/hints",
            "discovery-write",
            &body,
            Some(("application/octet-stream", &body)),
        )
        .await?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(refused());
    }
    Ok(())
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
    let path = format!("/v1/discovery/hints/{}", hex::encode(target));
    let response = client
        .signed(Method::GET, &path, "discovery-read", &target, None)
        .await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Ok(false);
    }
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(refused());
    }
    let bytes = read_response(response, HINT_LEN).await?;
    let hint = RouteHint::from_bytes(bytes.as_slice().try_into().map_err(|_| refused())?);
    if hint.address(&peer, discovery::now()?)?.is_none() {
        return Err(refused());
    }
    node::import_hint(state, &hex::encode(hint.as_bytes()))?;
    Ok(true)
}

fn refused() -> io::Error {
    io::Error::other("hosted discovery request failed")
}
