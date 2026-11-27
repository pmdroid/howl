use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use reqwest::Url;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncReadExt, net::TcpListener};

pub const DEFAULT_BIND: &str = "127.0.0.1:8470";
const ENDPOINT: &str = "/mcp";
const DISCOVERY: &str = "/.well-known/oauth-protected-resource/mcp";
const SESSION: HeaderName = HeaderName::from_static("mcp-session-id");
const MAX_CONFIG_BYTES: u64 = 65_536;
const WINDOW: Duration = Duration::from_secs(60);
const SESSION_IDLE: Duration = Duration::from_secs(300);
const MAX_SESSIONS: usize = 4096;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationPermission {
    Read,
    Send,
    Wake,
    Cancel,
}

#[derive(Clone)]
pub struct IntegrationPrincipal {
    id: String,
    channels: Vec<[u8; 32]>,
    permissions: Vec<IntegrationPermission>,
    revision: [u8; 32],
    configuration: Arc<PathBuf>,
}

impl IntegrationPrincipal {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn channels(&self) -> &[[u8; 32]] {
        &self.channels
    }

    pub fn permits(&self, channel: &[u8; 32], permission: IntegrationPermission) -> bool {
        self.permissions.contains(&permission) && self.channels.contains(channel)
    }

    pub async fn is_current(&self) -> bool {
        load_config(&self.configuration).await.is_ok_and(|config| {
            let now = unix_time();
            config.grants.iter().any(|grant| {
                grant.id == self.id
                    && now.is_some_and(|now| grant.expires_at > now)
                    && grant.revision() == self.revision
            })
        })
    }
}

pub fn authenticated(
    context: &RequestContext<RoleServer>,
) -> Result<&IntegrationPrincipal, ErrorData> {
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<IntegrationPrincipal>())
        .ok_or_else(|| ErrorData::invalid_request("missing integration authentication", None))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default = "default_rate")]
    requests_per_minute: u16,
    grants: Vec<Grant>,
}

fn default_rate() -> u16 {
    120
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    id: String,
    token_sha256: String,
    expires_at: u64,
    channels: Vec<String>,
    permissions: Vec<IntegrationPermission>,
}

impl Grant {
    fn revision(&self) -> [u8; 32] {
        Sha256::digest(serde_json::to_vec(self).expect("serializable grant")).into()
    }
}

struct Gateway {
    configuration: Arc<PathBuf>,
    challenge: HeaderValue,
    sessions: Mutex<HashMap<HeaderValue, ([u8; 32], Instant)>>,
    rate: Mutex<HashMap<String, (Instant, u16)>>,
}

pub async fn serve<S>(listener: TcpListener, configuration: &Path, handler: S) -> io::Result<()>
where
    S: ServerHandler + Clone,
{
    let (app, public_https) = router(configuration.to_owned(), handler).await?;
    if !listener.local_addr()?.ip().is_loopback() && !public_https {
        return Err(configuration_error(
            "non-loopback MCP listeners require an HTTPS public resource",
        ));
    }
    axum::serve(listener, app).await
}

async fn router<S>(configuration: PathBuf, handler: S) -> io::Result<(Router, bool)>
where
    S: ServerHandler + Clone,
{
    let config = load_config(&configuration).await?;
    let resource = resource_url(&config.resource)?;
    let origin = resource.origin().ascii_serialization();
    let authority = origin
        .split_once("://")
        .map(|(_, authority)| authority)
        .ok_or_else(|| configuration_error("invalid MCP resource authority"))?;
    let challenge =
        HeaderValue::from_str(&format!("Bearer resource_metadata=\"{origin}{DISCOVERY}\""))
            .map_err(|_| configuration_error("invalid MCP discovery URL"))?;
    let sdk_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts([authority])
        .with_allowed_origins(config.allowed_origins)
        .enforce_origin_validation()
        .with_stateless_protocol_metadata_required(true)
        .with_json_response(true)
        .with_max_request_body_bytes(65_536);
    let state = Arc::new(Gateway {
        configuration: Arc::new(configuration),
        challenge,
        sessions: Mutex::new(HashMap::new()),
        rate: Mutex::new(HashMap::new()),
    });
    let mut metadata = json!({
        "resource": resource.as_str(),
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["howl:read", "howl:send", "howl:wake", "howl:cancel"]
    });
    if !config.authorization_servers.is_empty() {
        metadata["authorization_servers"] = json!(config.authorization_servers);
    }
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        sdk_config,
    );
    let app = Router::new()
        .route_service(ENDPOINT, service)
        .route_layer(middleware::from_fn_with_state(state, guard))
        .route(
            DISCOVERY,
            get(move || async move { ([(header::CACHE_CONTROL, "no-store")], Json(metadata)) }),
        );
    Ok((app, resource.scheme() == "https"))
}

async fn load_config(path: &Path) -> io::Result<Config> {
    let file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(configuration_error("MCP config must be a protected file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(configuration_error("MCP config is too large"));
    }
    let config: Config =
        serde_json::from_slice(&bytes).map_err(|_| configuration_error("invalid MCP config"))?;
    let mut ids = HashSet::new();
    let mut tokens = HashSet::new();
    if !(1..=1_000).contains(&config.requests_per_minute)
        || config.grants.iter().any(|grant| {
            grant.id.is_empty()
                || grant.id.len() > 64
                || !grant
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                || !ids.insert(grant.id.as_str())
                || hex32(&grant.token_sha256).is_none_or(|digest| !tokens.insert(digest))
                || grant
                    .channels
                    .iter()
                    .any(|channel| hex32(channel).is_none())
                || grant.channels.is_empty()
                || grant.permissions.is_empty()
        })
    {
        return Err(configuration_error("invalid MCP integration grant"));
    }
    if config.authorization_servers.iter().any(|issuer| {
        !Url::parse(issuer).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
    }) {
        return Err(configuration_error(
            "invalid MCP OAuth authorization server",
        ));
    }
    Ok(config)
}

fn configuration_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn resource_url(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| configuration_error("invalid MCP resource URL"))?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != ENDPOINT
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(configuration_error(
            "MCP resource must be an HTTPS or loopback HTTP /mcp URL",
        ));
    }
    Ok(url)
}

fn unix_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

fn hex32(input: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(input, &mut bytes).ok()?;
    Some(bytes)
}

fn bearer_digest(headers: &HeaderMap) -> Option<[u8; 32]> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (scheme, token) = values.next()?.to_str().ok()?.split_once(' ')?;
    if values.next().is_some()
        || !scheme.eq_ignore_ascii_case("bearer")
        || !(32..=8192).contains(&token.len())
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
}

fn principal(state: &Gateway, config: &Config, digest: &[u8; 32]) -> Option<IntegrationPrincipal> {
    let now = unix_time()?;
    let grant = config.grants.iter().find(|grant| {
        grant.expires_at > now
            && hex32(&grant.token_sha256).is_some_and(|hash| bool::from(hash.ct_eq(digest)))
    })?;
    Some(IntegrationPrincipal {
        id: grant.id.clone(),
        channels: grant
            .channels
            .iter()
            .filter_map(|value| hex32(value))
            .collect(),
        permissions: grant.permissions.clone(),
        revision: grant.revision(),
        configuration: Arc::clone(&state.configuration),
    })
}

impl Gateway {
    fn unauthorized(&self) -> Response {
        uncached((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, self.challenge.clone())],
        ))
    }

    fn within_rate(&self, id: &str, limit: u16) -> bool {
        let mut rate = self.rate.lock().unwrap();
        rate.retain(|_, (start, _)| start.elapsed() < WINDOW);
        let (_, requests) = rate.entry(id.to_owned()).or_insert((Instant::now(), 0));
        if *requests >= limit {
            return false;
        }
        *requests += 1;
        true
    }

    fn owns_session(&self, id: Option<&HeaderValue>, revision: [u8; 32]) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, (_, used)| used.elapsed() < SESSION_IDLE);
        match id {
            None => sessions.len() < MAX_SESSIONS,
            Some(id) => sessions.get_mut(id).is_some_and(|(owner, used)| {
                if *owner == revision {
                    *used = Instant::now();
                    return true;
                }
                false
            }),
        }
    }
}

fn uncached(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn guard(State(state): State<Arc<Gateway>>, mut request: Request, next: Next) -> Response {
    let Some(digest) = bearer_digest(request.headers()) else {
        return state.unauthorized();
    };
    let Ok(config) = load_config(&state.configuration).await else {
        return uncached(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(principal) = principal(&state, &config, &digest) else {
        return state.unauthorized();
    };
    if !state.within_rate(principal.id(), config.requests_per_minute) {
        return uncached((StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")]));
    }

    let mut sessions = request.headers().get_all(&SESSION).iter();
    let session = sessions.next().cloned();
    if sessions.next().is_some()
        || request
            .headers()
            .get_all(header::ORIGIN)
            .iter()
            .nth(1)
            .is_some()
    {
        return uncached(StatusCode::BAD_REQUEST);
    }
    if !state.owns_session(session.as_ref(), principal.revision) {
        return uncached(if session.is_some() {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        });
    }

    let method = request.method().clone();
    let id = principal.id.clone();
    let revision = principal.revision;
    request.headers_mut().remove(header::AUTHORIZATION);
    request.extensions_mut().insert(principal);
    let response = next.run(request).await;
    if response.status().is_success() {
        let mut owners = state.sessions.lock().unwrap();
        if let Some(new_session) = response.headers().get(&SESSION) {
            owners.insert(new_session.clone(), (revision, Instant::now()));
        }
        if method == Method::DELETE
            && let Some(session) = session
        {
            owners.remove(&session);
        }
    }
    eprintln!(
        "howl_mcp request integration={id} method={method} status={}",
        response.status().as_u16()
    );
    uncached(response)
}

#[cfg(test)]
mod tests;
