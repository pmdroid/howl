use std::{
    collections::HashSet,
    fs::OpenOptions,
    future::Future,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use howl_envelope::Id;
use reqwest::{Client, StatusCode, Url, header, redirect::Policy};
use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    net::lookup_host,
    time::{sleep, timeout},
};
use zeroize::Zeroizing;

use crate::{
    delivery::{DeliveryStore, WebhookAttempt, WebhookEventKind, WebhookFilter, WebhookOutcome},
    enrollment::ChannelPermission,
    identity::{LocalIdentity, StateDirectory},
    interaction::LocalInteraction,
    node,
};

const MAX_CONFIG_BYTES: u64 = 65_536;
const MAX_ENDPOINTS: usize = 16;
const MAX_CHANNELS: usize = 64;
const MAX_ADDRESSES: usize = 16;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    endpoints: Vec<EndpointConfig>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EndpointConfig {
    name: String,
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grok_bot_key: Option<String>,
    channels: Vec<String>,
    events: Vec<WebhookEventKind>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    include_content: bool,
    #[serde(default)]
    allow_private_ips: Vec<IpAddr>,
}

enum Authentication {
    Standard(Zeroizing<Id>),
    GrokBot(header::HeaderValue),
}

struct Endpoint {
    name: String,
    url: Url,
    authentication: Authentication,
    revision: Id,
    channels: Vec<Id>,
    events: Vec<WebhookEventKind>,
    include_content: bool,
    allow_private_ips: Vec<IpAddr>,
}

impl Endpoint {
    fn compile(config: EndpointConfig, revision: Id) -> io::Result<Self> {
        let authentication = match (
            config.signing_secret.map(Zeroizing::new),
            config.grok_bot_key.map(Zeroizing::new),
        ) {
            (Some(signing_secret), None) => {
                let secret = Zeroizing::new(parse_id(&signing_secret)?);
                if secret.iter().all(|byte| *byte == 0) {
                    return Err(config_error());
                }
                Authentication::Standard(secret)
            }
            (None, Some(key))
                if !key.is_empty()
                    && key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte)) =>
            {
                let bearer = Zeroizing::new(format!("Bearer {}", &*key));
                let mut value =
                    header::HeaderValue::from_str(&bearer).map_err(|_| config_error())?;
                value.set_sensitive(true);
                Authentication::GrokBot(value)
            }
            _ => return Err(config_error()),
        };
        let url = Url::parse(&config.url).map_err(|_| config_error())?;
        let host = destination_host(&url).ok_or_else(config_error)?;
        let literal = host.parse::<IpAddr>().ok();
        let allow_http = url.scheme() == "http"
            && literal.is_some_and(|ip| ip.is_loopback() && config.allow_private_ips.contains(&ip));
        if (url.scheme() != "https" && !allow_http)
            || url.port_or_known_default().is_none_or(|port| port == 0)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || config.channels.is_empty()
            || config.channels.len() > MAX_CHANNELS
            || config.events.is_empty()
            || config.events.len() > 6
            || config.allow_private_ips.len() > MAX_ADDRESSES
            || !config.allow_private_ips.iter().copied().all(usable_address)
        {
            return Err(config_error());
        }
        let channels = config
            .channels
            .iter()
            .map(|id| parse_id(id))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            name: config.name,
            url,
            authentication,
            revision,
            channels,
            events: config.events,
            include_content: config.include_content,
            allow_private_ips: config.allow_private_ips,
        })
    }

    fn permitted(&self, address: IpAddr) -> bool {
        usable_address(address)
            && (public_address(address) || self.allow_private_ips.contains(&address))
    }

    fn filter<'a>(&'a self, channels: &'a [Id]) -> WebhookFilter<'a> {
        WebhookFilter {
            name: &self.name,
            revision: self.revision,
            channels,
            events: &self.events,
            include_content: self.include_content,
        }
    }
}

pub async fn run(state: &Path, configuration: &Path) -> io::Result<()> {
    load_config(configuration)?;
    let _lock = StateDirectory::open(state)?.lock("webhooks.lock")?;
    let mut delivery = webhook_store(state)?;
    delivery.initialize_webhooks().map_err(io::Error::other)?;
    loop {
        let endpoints = load_config(configuration)?;
        let authorized = endpoints
            .iter()
            .map(|endpoint| readable_channels(state, endpoint))
            .collect::<Vec<_>>();
        let filters = endpoints
            .iter()
            .zip(&authorized)
            .map(|(endpoint, channels)| endpoint.filter(channels))
            .collect::<Vec<_>>();
        let now = node::unix_time()?;
        delivery
            .synchronize_webhooks(&filters, now)
            .map_err(io::Error::other)?;
        let Some(attempt) = delivery.claim_webhook(now).map_err(io::Error::other)? else {
            sleep(Duration::from_secs(1)).await;
            continue;
        };
        let outcome = match endpoints.iter().find(|endpoint| {
            endpoint.name == attempt.destination && endpoint.revision == attempt.revision
        }) {
            Some(endpoint) if readable(state, attempt.channel) => {
                deliver(state, configuration, endpoint, &attempt).await
            }
            _ => WebhookOutcome::Revoked,
        };
        delivery
            .finish_webhook(&attempt, outcome, node::unix_time()?)
            .map_err(io::Error::other)?;
    }
}

pub fn status(state: &Path) -> io::Result<serde_json::Value> {
    let delivery = webhook_store(state)?;
    let failures = if delivery.webhooks_initialized().map_err(io::Error::other)? {
        delivery.webhook_failures().map_err(io::Error::other)?
    } else {
        Vec::new()
    };
    Ok(serde_json::json!({ "failed_or_retrying": failures }))
}

pub fn replay(state: &Path, configuration: &Path, endpoint: &str, event: Id) -> io::Result<bool> {
    let delivery = webhook_store(state)?;
    if !delivery.webhooks_initialized().map_err(io::Error::other)? {
        return Ok(false);
    }
    let endpoints = load_config(configuration)?;
    let Some(endpoint) = endpoints
        .iter()
        .find(|candidate| candidate.name == endpoint)
    else {
        return Ok(false);
    };
    let channels = readable_channels(state, endpoint);
    delivery
        .replay_webhook(&endpoint.filter(&channels), event, node::unix_time()?)
        .map_err(io::Error::other)
}

fn webhook_store(state: &Path) -> io::Result<DeliveryStore> {
    LocalInteraction::new(state).require_enrolled()?;
    let identity = LocalIdentity::load_or_create(state)?;
    let directory = StateDirectory::open(state)?;
    node::open_delivery(state, &directory, &identity.certificate())
}

fn load_config(path: &Path) -> io::Result<Vec<Endpoint>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| config_error())?;
    let meta = file.metadata().map_err(|_| config_error())?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o077 != 0
        || (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
    {
        return Err(config_error());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| config_error())?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(config_error());
    }
    let parsed: Configuration = serde_json::from_slice(&bytes).map_err(|_| config_error())?;
    if parsed.endpoints.len() > MAX_ENDPOINTS {
        return Err(config_error());
    }
    let mut seen = HashSet::new();
    let mut endpoints = Vec::new();
    for endpoint in parsed.endpoints {
        if endpoint.name.is_empty()
            || endpoint.name.len() > 64
            || !endpoint
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            || !seen.insert(endpoint.name.clone())
        {
            return Err(config_error());
        }
        let canonical = Zeroizing::new(serde_json::to_vec(&endpoint).map_err(|_| config_error())?);
        let enabled = endpoint.enabled;
        let endpoint = Endpoint::compile(endpoint, Sha256::digest(&*canonical).into())?;
        if enabled {
            endpoints.push(endpoint);
        }
    }
    Ok(endpoints)
}

fn readable_channels(state: &Path, endpoint: &Endpoint) -> Vec<Id> {
    endpoint
        .channels
        .iter()
        .copied()
        .filter(|channel| readable(state, *channel))
        .collect()
}

fn readable(state: &Path, channel: Id) -> bool {
    let local = LocalInteraction::new(state);
    local.require_enrolled().is_ok() && local.authorize(channel, ChannelPermission::Receive).is_ok()
}

async fn deliver(
    state: &Path,
    configuration: &Path,
    endpoint: &Endpoint,
    attempt: &WebhookAttempt,
) -> WebhookOutcome {
    let pin = match pinned_destination(endpoint, |host, port| async move {
        lookup_host((host, port))
            .await
            .map(|addresses| addresses.take(MAX_ADDRESSES + 1).collect())
    })
    .await
    {
        Ok(pin) => pin,
        Err(outcome) => return outcome,
    };
    let Ok(current) = load_config(configuration) else {
        return WebhookOutcome::Retry;
    };
    let current = current.iter().any(|current| {
        current.name == endpoint.name
            && current.revision == endpoint.revision
            && current.channels.contains(&attempt.channel)
    });
    if !current || !readable(state, attempt.channel) {
        return WebhookOutcome::Revoked;
    }
    let Ok(now) = node::unix_time() else {
        return WebhookOutcome::Retry;
    };
    send(
        endpoint,
        pin,
        &hex::encode(attempt.event),
        now,
        &attempt.body,
    )
    .await
}

struct PinnedDestination {
    host: String,
    addresses: Vec<SocketAddr>,
}

async fn pinned_destination<F>(
    endpoint: &Endpoint,
    resolver: impl FnOnce(String, u16) -> F,
) -> Result<PinnedDestination, WebhookOutcome>
where
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let host = destination_host(&endpoint.url).ok_or(WebhookOutcome::DestinationBlocked)?;
    let port = endpoint
        .url
        .port_or_known_default()
        .ok_or(WebhookOutcome::DestinationBlocked)?;
    let addresses = if let Ok(literal) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(literal, port)]
    } else {
        timeout(LOOKUP_TIMEOUT, resolver(host.to_owned(), port))
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or(WebhookOutcome::Retry)?
    };
    if addresses.is_empty()
        || addresses.len() > MAX_ADDRESSES
        || addresses.iter().any(|address| {
            address.port() != port
                || !endpoint.permitted(address.ip())
                || matches!(address, SocketAddr::V6(address) if address.scope_id() != 0)
        })
    {
        return Err(WebhookOutcome::DestinationBlocked);
    }
    Ok(PinnedDestination {
        host: host.to_owned(),
        addresses,
    })
}

async fn send(
    endpoint: &Endpoint,
    pinned: PinnedDestination,
    id: &str,
    timestamp: u64,
    body: &str,
) -> WebhookOutcome {
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .resolve_to_addrs(&pinned.host, &pinned.addresses)
        .timeout(SEND_TIMEOUT)
        .build();
    let Ok(client) = client else {
        return WebhookOutcome::Retry;
    };
    let request = client
        .post(endpoint.url.clone())
        .header(header::CONTENT_TYPE, "application/json")
        .header("Webhook-Id", id);
    let request = match &endpoint.authentication {
        Authentication::Standard(secret) => request
            .header("Webhook-Timestamp", timestamp.to_string())
            .header("Webhook-Signature", signature(secret, id, timestamp, body)),
        Authentication::GrokBot(bearer) => request.header(header::AUTHORIZATION, bearer.clone()),
    };
    let response = request.body(body.to_owned()).send().await;
    match response.map(|response| response.status()) {
        Ok(status)
            if status == StatusCode::OK
                || (status.is_success()
                    && matches!(endpoint.authentication, Authentication::Standard(_))) =>
        {
            WebhookOutcome::Delivered
        }
        Ok(status)
            if status.is_server_error()
                || matches!(
                    status,
                    StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_EARLY
                        | StatusCode::TOO_MANY_REQUESTS
                ) =>
        {
            WebhookOutcome::Retry
        }
        Ok(_) => WebhookOutcome::Rejected,
        Err(_) => WebhookOutcome::Retry,
    }
}

fn signature(secret: &Id, id: &str, timestamp: u64, body: &str) -> String {
    let mut mac = Hmac::<sha2_10::Sha256>::new_from_slice(secret).expect("valid HMAC key");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
}

fn destination_host(url: &Url) -> Option<&str> {
    let host = url
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.parse::<IpAddr>().is_ok()
        || (host.len() <= 253
            && host.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
    {
        Some(host)
    } else {
        None
    }
}

fn usable_address(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && match address {
            IpAddr::V4(address) => !address.is_broadcast(),
            IpAddr::V6(address) => address.to_ipv4_mapped().is_none(),
        }
}

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => !matches!(
            address.octets(),
            [0 | 10 | 127 | 224..=255, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0, 0 | 2, _]
                | [192, 88, 99, _]
                | [192, 168, ..]
                | [198, 18 | 19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
        ),
        IpAddr::V6(address) => match address.segments() {
            [0x2001, 0x0000..=0x01ff | 0x0db8, ..] | [0x2002 | 0x3fff, ..] => false,
            [0x2000..=0x3fff, ..] => true,
            _ => false,
        },
    }
}

fn parse_id(value: &str) -> io::Result<Id> {
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id).map_err(|_| config_error())?;
    Ok(id)
}

fn config_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unprotected webhook configuration",
    )
}

#[cfg(test)]
mod tests;
