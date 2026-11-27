use std::{io, net::SocketAddr, path::Path};

use reqwest::{Method, StatusCode, header};

use crate::{
    control_client::{ControlClient, read_response},
    delivery::Id,
    discovery::{self, HINT_LEN, RouteHint},
    identity::PeerTrust,
    node,
};

pub async fn publish(state: &Path, address: SocketAddr) -> io::Result<()> {
    let client = ControlClient::open(state).await?;
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
    let peer = PeerTrust::open(state)?.pinned(&target)?;
    let client = ControlClient::open(state).await?;
    let path = format!("/v1/discovery/hints/{}", hex::encode(target));
    let response = client
        .signed(Method::GET, &path, "discovery-read", &target, None)
        .await?;
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
    node::import_hint(state, &hex::encode(hint.as_bytes()))
}

fn refused() -> io::Error {
    io::Error::other("hosted discovery request failed")
}
