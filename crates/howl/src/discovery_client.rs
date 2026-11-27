use std::{
    env, io,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

use reqwest::{Client, RequestBuilder, Response, StatusCode, Url, header, redirect::Policy};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    control_proof::signing_bytes,
    delivery::Id,
    discovery::{self, HINT_LEN, RouteHint},
    identity::{LocalIdentity, PeerTrust},
    node,
};

struct Discovery {
    http: Client,
    origin: Url,
    audience: Id,
    subject: Id,
    token: Zeroizing<String>,
    token_digest: Id,
}

#[derive(Deserialize)]
struct Challenge {
    nonce: String,
}

pub async fn publish(state: &Path, address: SocketAddr) -> io::Result<()> {
    let identity = LocalIdentity::load_or_create(state)?;
    let discovery = Discovery::configured()?;
    let hint = RouteHint::issue(&identity, address, discovery::now()?)?;
    let body = [
        identity.certificate().as_bytes().as_slice(),
        hint.as_bytes(),
    ]
    .concat();
    let request = discovery
        .http
        .post(
            discovery
                .origin
                .join("v1/discovery/hints")
                .map_err(|_| configuration())?,
        )
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(body.clone());
    let response = discovery
        .prove(request, &identity, "discovery-write", &body)
        .await?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(refused());
    }
    Ok(())
}

pub async fn fetch(state: &Path, target: Id) -> io::Result<()> {
    let peer = PeerTrust::open(state)?.pinned(&target)?;
    let identity = LocalIdentity::load_or_create(state)?;
    let discovery = Discovery::configured()?;
    let url = discovery
        .origin
        .join(&format!("v1/discovery/hints/{}", hex::encode(target)))
        .map_err(|_| configuration())?;
    let response = discovery
        .prove(
            discovery.http.get(url),
            &identity,
            "discovery-read",
            &target,
        )
        .await?;
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(refused());
    }
    let bytes = bounded(response, HINT_LEN).await?;
    let hint = RouteHint::from_bytes(bytes.try_into().map_err(|_| refused())?);
    if hint.address(&peer, discovery::now()?)?.is_none() {
        return Err(refused());
    }
    node::import_hint(state, &hex::encode(hint.as_bytes()))
}

impl Discovery {
    fn configured() -> io::Result<Self> {
        let origin = Url::parse(&configured("HOWL_CONTROL_URL")?).map_err(|_| configuration())?;
        let loopback = origin
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if !(origin.scheme() == "https" || origin.scheme() == "http" && loopback)
            || origin.host().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(configuration());
        }
        let audience = parse_id(&configured("HOWL_CONTROL_AUDIENCE")?)?;
        let subject = parse_id(&configured("HOWL_CONTROL_SESSION_ID")?)?;
        let token = Zeroizing::new(configured("HOWL_CONTROL_ACCESS_TOKEN")?);
        let secret = Zeroizing::new(parse_id(&token)?);
        let http = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| configuration())?;
        Ok(Self {
            http,
            origin,
            audience,
            subject,
            token,
            token_digest: Sha256::digest(&secret[..]).into(),
        })
    }

    async fn prove(
        &self,
        request: RequestBuilder,
        identity: &LocalIdentity,
        operation: &str,
        body: &[u8],
    ) -> io::Result<Response> {
        let url = self
            .origin
            .join("v1/auth/challenge")
            .map_err(|_| configuration())?;
        let challenge = self
            .http
            .post(url)
            .bearer_auth(&*self.token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::json!({ "operation": operation }).to_string())
            .send()
            .await
            .map_err(|_| refused())?;
        let challenge: Challenge =
            serde_json::from_slice(&bounded(challenge, 256).await?).map_err(|_| refused())?;
        let nonce = parse_id(&challenge.nonce).map_err(|_| refused())?;
        let signature = identity.sign(&signing_bytes(
            self.audience,
            self.subject,
            operation,
            nonce,
            self.token_digest,
            body,
        ));
        request
            .bearer_auth(&*self.token)
            .header("howl-nonce", challenge.nonce)
            .header("howl-signature", hex::encode(signature))
            .send()
            .await
            .map_err(|_| refused())
    }
}

async fn bounded(mut response: Response, maximum: usize) -> io::Result<Vec<u8>> {
    if response.status() != StatusCode::OK {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| refused())? {
        if bytes.len() + chunk.len() > maximum {
            return Err(refused());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn configured(variable: &str) -> io::Result<String> {
    env::var(variable).map_err(|_| configuration())
}

fn parse_id(value: &str) -> io::Result<Id> {
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id).map_err(|_| configuration())?;
    Ok(id)
}

fn configuration() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid hosted discovery configuration",
    )
}

fn refused() -> io::Error {
    io::Error::other("hosted discovery request failed")
}
