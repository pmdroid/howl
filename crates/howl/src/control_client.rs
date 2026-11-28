mod device_link;
mod device_name;

pub use device_name::device_name;

use std::{
    env, io,
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};

use reqwest::{
    Client, Method, RequestBuilder, Response, StatusCode, Url, header, redirect::Policy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    control_proof::signing_bytes,
    delivery::Id,
    enrollment::{AuthorityStore, Designation, DeviceCertificate},
    identity::{LocalIdentity, StateDirectory},
    node,
};

const CREDENTIALS: &str = "credentials";
const LOCK: &str = "control-auth.lock";
const STATE_LIMIT: u64 = 4_096;
const AUTHORIZATION_URL: &str = "https://github.com/login/device";
const DEFAULT_CONTROL_URL: &str = "https://howl-control-plane-d1-prototype.pascal.workers.dev";

pub struct ControlClient {
    service: Service,
    identity: LocalIdentity,
    subject: Id,
    token: Zeroizing<String>,
}

struct Service {
    http: Client,
    origin: Url,
    audience: Id,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    origin: String,
    audience: String,
    access_expires: u64,
    credentials: Credentials,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    session: PendingSession,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PendingSession {
    id: String,
    github_id: i64,
    device_id: String,
    signing_key: String,
}

#[derive(Deserialize)]
struct Login {
    login: String,
    user_code: String,
    verification_uri: String,
    interval: u64,
    expires_in: u64,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Poll {
    Pending { interval: u64 },
    Verified { credentials: Credentials },
}

#[derive(Deserialize)]
struct Challenge {
    nonce: String,
}

#[derive(Serialize)]
struct Proof {
    nonce: String,
    signature: String,
}

pub async fn login(state: &Path) -> io::Result<()> {
    login_device(state, LoginMode::Manual).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginMode<'a> {
    Manual,
    Hosted(Option<&'a str>),
    DeviceCode,
}

pub(crate) async fn login_device(path: &Path, mode: LoginMode<'_>) -> io::Result<()> {
    let identity = LocalIdentity::load_or_create(path)?;
    let state = StateDirectory::open(path)?;
    let _lock = crate::identity::retry_state_lock(|| state.lock(LOCK)).await?;
    let existing = load(&state)?;
    let (service, browser) = Service::for_login(existing.as_ref()).await?;
    if let Some(stored) = &existing {
        validate(&stored.credentials, &identity)?;
        match service.resume_login(&state, &identity, stored).await {
            Ok(()) => {
                if matches!(mode, LoginMode::Hosted(Some(_))) {
                    println!(
                        "Device is already signed in. Manage its name in the device dashboard."
                    );
                } else {
                    println!("Device is already signed in.");
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            Err(error) => return Err(error),
        }
    }
    let previous_owner = existing
        .as_ref()
        .map(|stored| stored.credentials.session.github_id);
    let credentials = match (mode, browser) {
        (LoginMode::Hosted(name), Some(browser)) => {
            device_link::login(&service, &identity, path, browser, name, previous_owner).await?
        }
        (LoginMode::Hosted(Some(_)), None) => return Err(device_link::unsupported_name()),
        _ => github_device_login(&service, &identity, mode != LoginMode::Manual).await?,
    };
    validate_login(&credentials, &identity, previous_owner)?;
    save(&state, &service, credentials)?;
    println!("Howl sign-in complete.");
    Ok(())
}

async fn github_device_login(
    service: &Service,
    identity: &LocalIdentity,
    join_network: bool,
) -> io::Result<Credentials> {
    let certificate = identity.certificate();
    let request = serde_json::json!({
        "device_id": hex::encode(certificate.device_id()),
        "signing_key": hex::encode(certificate.signing_public()),
    });
    let started = Instant::now();
    let path = if join_network {
        "/v1/network/login/device"
    } else {
        "/v1/login/device"
    };
    let mut response = service
        .json(path, &request)?
        .send()
        .await
        .map_err(|_| refused())?;
    if join_network && response.status() == StatusCode::NOT_FOUND {
        response = service
            .json("/v1/login/device", &request)?
            .send()
            .await
            .map_err(|_| refused())?;
    }
    let login: Login =
        serde_json::from_slice(&read_response(response, STATE_LIMIT as usize).await?)?;
    let subject = parse_id(&login.login)?;
    if login.verification_uri != AUTHORIZATION_URL
        || login.user_code.len() != 9
        || !login
            .user_code
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        || !(1..=900).contains(&login.expires_in)
        || !(1..=900).contains(&login.interval)
    {
        return Err(refused());
    }
    println!(
        "Open {AUTHORIZATION_URL} and enter code {}.",
        login.user_code
    );
    let deadline = started + Duration::from_secs(login.expires_in);
    let mut interval = login.interval;
    loop {
        let delay = Duration::from_secs(interval);
        if deadline.saturating_duration_since(Instant::now()) <= delay {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "GitHub device login expired",
            ));
        }
        tokio::time::sleep(delay).await;
        let challenge = service.challenge("poll", None, Some(&login.login)).await?;
        let proof = service.proof(identity, subject, "poll", challenge, None, b"")?;
        let response = service
            .json(&format!("/v1/login/device/{}/poll", login.login), &proof)?
            .send()
            .await
            .map_err(|_| refused())?;
        if matches!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS | StatusCode::BAD_GATEWAY
        ) {
            continue;
        }
        match serde_json::from_slice::<Poll>(&read_response(response, STATE_LIMIT as usize).await?)
            .map_err(|_| refused())?
        {
            Poll::Pending { interval: next } if (1..=900).contains(&next) => interval = next,
            Poll::Pending { .. } => return Err(refused()),
            Poll::Verified { credentials } => return Ok(credentials),
        }
    }
}

pub async fn enroll(
    state: &Path,
    authority_state: &Path,
    designation_file: &Path,
    certificate_file: &Path,
) -> io::Result<()> {
    let identity = LocalIdentity::load_or_create(state)?;
    let authority = AuthorityStore::open(authority_state)?.load()?;
    let designation_bytes = public_record(designation_file, 165_000)?;
    let designation = Designation::verify(&designation_bytes, authority.head()?)?;
    let certificate_bytes = public_record(certificate_file, 512)?;
    let certificate = DeviceCertificate::verify(&certificate_bytes, &designation)?;
    if !certificate.matches(&identity.certificate()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "certificate does not match this device",
        ));
    }
    let records = authority
        .records()
        .iter()
        .map(|record| hex::encode(record.as_bytes()))
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&serde_json::json!({"authority":records,
        "designation":hex::encode(designation.as_bytes()), "certificate":hex::encode(certificate.as_bytes())}))?;
    if body.len() > 512 * 1024 {
        return Err(io::Error::other(
            "public enrollment payload exceeds the hosted limit",
        ));
    }
    let client = ControlClient::open(state).await?;
    let response = client
        .post_json("/v1/enrollment/device", "enrollment", &body)
        .await?;
    if response.status() != StatusCode::NO_CONTENT {
        return Err(refused());
    }
    println!("Signed device enrollment uploaded.");
    Ok(())
}

impl ControlClient {
    pub(crate) fn has_credentials(state: &Path) -> io::Result<bool> {
        state.join(CREDENTIALS).try_exists()
    }

    pub async fn open(state: &Path) -> io::Result<Self> {
        let identity = LocalIdentity::load_or_create(state)?;
        let state = StateDirectory::open(state)?;
        let _lock = crate::identity::retry_state_lock(|| state.lock(LOCK)).await?;
        let Some(mut stored) = load(&state)? else {
            let token = Zeroizing::new(configured("HOWL_CONTROL_ACCESS_TOKEN")?);
            let _decoded = Zeroizing::new(parse_id(&token)?);
            return Ok(Self {
                service: Service::configured()?,
                identity,
                subject: parse_id(&configured("HOWL_CONTROL_SESSION_ID")?)?,
                token,
            });
        };
        let service = Service::new(&stored.origin, parse_id(&stored.audience)?)?;
        validate(&stored.credentials, &identity)?;
        if stored.access_expires <= node::unix_time()?.saturating_add(15) {
            stored = service.refresh_stored(&state, &identity, &stored).await?;
        }
        Ok(Self {
            service,
            identity,
            subject: parse_id(&stored.credentials.session.id)?,
            token: Zeroizing::new(std::mem::take(&mut stored.credentials.access_token)),
        })
    }

    pub async fn post_json(
        &self,
        path: &str,
        operation: &str,
        body: &[u8],
    ) -> io::Result<Response> {
        self.signed(
            Method::POST,
            path,
            operation,
            body,
            Some(("application/json", body)),
        )
        .await
    }

    pub(crate) fn identity(&self) -> &LocalIdentity {
        &self.identity
    }

    pub(crate) async fn signed(
        &self,
        method: Method,
        path: &str,
        operation: &str,
        proof_body: &[u8],
        data: Option<(&'static str, &[u8])>,
    ) -> io::Result<Response> {
        let url = self.service.endpoint(path)?;
        let nonce = self
            .service
            .challenge(operation, Some(&self.token), None)
            .await?;
        let proof = self.service.proof(
            &self.identity,
            self.subject,
            operation,
            nonce,
            Some(&self.token),
            proof_body,
        )?;
        let mut request = self
            .service
            .http
            .request(method, url)
            .bearer_auth(&*self.token)
            .header("howl-nonce", proof.nonce)
            .header("howl-signature", proof.signature);
        if let Some((content_type, bytes)) = data {
            request = request
                .header(header::CONTENT_TYPE, content_type)
                .body(bytes.to_vec());
        }
        request.send().await.map_err(|_| refused())
    }
}

impl Service {
    fn configured() -> io::Result<Self> {
        Self::new(
            &configured("HOWL_CONTROL_URL")?,
            parse_id(&configured("HOWL_CONTROL_AUDIENCE")?)?,
        )
    }

    async fn resume_login(
        &self,
        state: &StateDirectory,
        identity: &LocalIdentity,
        stored: &Stored,
    ) -> io::Result<()> {
        if stored.access_expires <= node::unix_time()?.saturating_add(15) {
            self.refresh_stored(state, identity, stored).await?;
            return Ok(());
        }
        let token = &stored.credentials.access_token;
        let nonce = self.challenge("session", Some(token), None).await?;
        let proof = self.proof(
            identity,
            parse_id(&stored.credentials.session.id)?,
            "session",
            nonce,
            Some(token),
            b"",
        )?;
        let session: PendingSession = self
            .decode(
                self.http
                    .get(self.endpoint("/v1/auth/session")?)
                    .bearer_auth(token)
                    .header("howl-nonce", proof.nonce)
                    .header("howl-signature", proof.signature),
            )
            .await?;
        if session != stored.credentials.session {
            return Err(refused());
        }
        Ok(())
    }

    async fn refresh_stored(
        &self,
        state: &StateDirectory,
        identity: &LocalIdentity,
        stored: &Stored,
    ) -> io::Result<Stored> {
        let token = &stored.credentials.refresh_token;
        let nonce = self.challenge("refresh", Some(token), None).await?;
        let subject = parse_id(&stored.credentials.session.id)?;
        let proof = self.proof(identity, subject, "refresh", nonce, Some(token), b"")?;
        let credentials: Credentials = self
            .decode(self.json("/v1/auth/refresh", &proof)?.bearer_auth(token))
            .await?;
        validate(&credentials, identity)?;
        if credentials.session != stored.credentials.session {
            return Err(refused());
        }
        save(state, self, credentials)
    }

    async fn for_login(
        existing: Option<&Stored>,
    ) -> io::Result<(Self, Option<device_link::Browser>)> {
        let configured_origin = match env::var("HOWL_CONTROL_URL") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => existing
                .map(|stored| stored.origin.clone())
                .unwrap_or_else(|| DEFAULT_CONTROL_URL.to_owned()),
            Err(env::VarError::NotUnicode(_)) => return Err(configuration()),
        };
        let (origin, http) = Self::connection(&configured_origin)?;
        if existing.is_some_and(|stored| stored.origin != origin.as_str()) {
            return Err(io::Error::other(
                "Local credentials belong to a different control plane.",
            ));
        }
        let pinned = match env::var("HOWL_CONTROL_AUDIENCE") {
            Ok(audience) => Some(parse_id(&audience)?),
            Err(env::VarError::NotUnicode(_)) => return Err(configuration()),
            Err(env::VarError::NotPresent) => None,
        };
        let previous = existing
            .map(|stored| parse_id(&stored.audience))
            .transpose()?;
        if previous.zip(pinned).is_some_and(|(a, b)| a != b) {
            return Err(configuration());
        }
        let expected = pinned.or(previous);
        let url = origin
            .join("/v1/auth/config")
            .map_err(|_| configuration())?;
        let response = http.get(url).send().await.map_err(|_| refused())?;
        if response.status() == StatusCode::NOT_FOUND
            && let Some(audience) = expected
        {
            return Ok((Self::from_parts(origin, http, audience)?, None));
        }
        #[derive(Deserialize)]
        struct PublicConfig {
            audience: String,
            browser_link_origin: Option<String>,
            #[serde(default)]
            device_names: bool,
        }
        let config: PublicConfig =
            serde_json::from_slice(&read_response(response, 1024).await?).map_err(|_| refused())?;
        let audience = parse_id(&config.audience)?;
        if expected.is_some_and(|pinned| pinned != audience) {
            return Err(io::Error::other("The control plane audience has changed."));
        }
        let browser = config
            .browser_link_origin
            .as_deref()
            .map(|origin| device_link::Browser::new(origin, config.device_names))
            .transpose()?;
        Ok((Self::from_parts(origin, http, audience)?, browser))
    }

    fn new(origin: &str, audience: Id) -> io::Result<Self> {
        let (origin, http) = Self::connection(origin)?;
        Self::from_parts(origin, http, audience)
    }

    fn from_parts(origin: Url, http: Client, audience: Id) -> io::Result<Self> {
        if audience == [0; 32] {
            return Err(configuration());
        }
        Ok(Self {
            http,
            origin,
            audience,
        })
    }

    fn connection(origin: &str) -> io::Result<(Url, Client)> {
        if origin.len() > 512 {
            return Err(configuration());
        }
        let origin = Url::parse(origin).map_err(|_| configuration())?;
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
        let http = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| configuration())?;
        Ok((origin, http))
    }

    fn endpoint(&self, path: &str) -> io::Result<Url> {
        let url = self.origin.join(path).map_err(|_| configuration())?;
        if !path.starts_with("/v1/")
            || url.origin() != self.origin.origin()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(configuration());
        }
        Ok(url)
    }

    fn json(&self, path: &str, request: &impl Serialize) -> io::Result<RequestBuilder> {
        Ok(self
            .http
            .post(self.endpoint(path)?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(request)?))
    }

    async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> io::Result<T> {
        let response = request.send().await.map_err(|_| refused())?;
        serde_json::from_slice(&read_response(response, STATE_LIMIT as usize).await?)
            .map_err(|_| refused())
    }

    async fn challenge(
        &self,
        operation: &str,
        token: Option<&str>,
        login: Option<&str>,
    ) -> io::Result<String> {
        let payload = match login {
            Some(login) => serde_json::json!({ "operation": operation, "login": login }),
            None => serde_json::json!({ "operation": operation }),
        };
        let mut request = self.json("/v1/auth/challenge", &payload)?;
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let challenge: Challenge = self.decode(request).await?;
        Ok(challenge.nonce)
    }

    fn proof(
        &self,
        identity: &LocalIdentity,
        subject: Id,
        operation: &str,
        nonce: String,
        token: Option<&str>,
        body: &[u8],
    ) -> io::Result<Proof> {
        let digest = match token {
            Some(token) => Sha256::digest(&Zeroizing::new(parse_id(token)?)[..]).into(),
            None => [0; 32],
        };
        let bytes = signing_bytes(
            self.audience,
            subject,
            operation,
            parse_id(&nonce)?,
            digest,
            body,
        );
        Ok(Proof {
            nonce,
            signature: hex::encode(identity.sign(&bytes)),
        })
    }
}

pub async fn read_response(
    mut response: Response,
    maximum: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "The control plane rejected the device credentials.",
        ));
    }
    if !response.status().is_success() {
        return Err(refused());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| refused())? {
        if bytes.len() + chunk.len() > maximum {
            return Err(refused());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn load(directory: &StateDirectory) -> io::Result<Option<Stored>> {
    match directory.read_bounded(CREDENTIALS, STATE_LIMIT) {
        Ok(bytes) => serde_json::from_slice(&Zeroizing::new(bytes))
            .map(Some)
            .map_err(|_| configuration()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn save(
    directory: &StateDirectory,
    service: &Service,
    credentials: Credentials,
) -> io::Result<Stored> {
    let stored = Stored {
        origin: service.origin.as_str().to_owned(),
        audience: hex::encode(service.audience),
        access_expires: node::unix_time()?.saturating_add(credentials.expires_in),
        credentials,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&stored)?);
    directory.replace(CREDENTIALS, &bytes)?;
    Ok(stored)
}

fn validate_login(
    credentials: &Credentials,
    identity: &LocalIdentity,
    previous_owner: Option<i64>,
) -> io::Result<()> {
    validate(credentials, identity)?;
    if previous_owner.is_some_and(|id| id != credentials.session.github_id) {
        return Err(io::Error::other(
            "This device profile is linked to a different GitHub account.",
        ));
    }
    Ok(())
}

fn validate(credentials: &Credentials, identity: &LocalIdentity) -> io::Result<()> {
    let certificate = identity.certificate();
    if !(1..=300).contains(&credentials.expires_in)
        || credentials.session.github_id <= 0
        || parse_id(&credentials.session.device_id)? != *certificate.device_id()
        || parse_id(&credentials.session.signing_key)? != certificate.signing_public()
    {
        return Err(refused());
    }
    parse_id(&credentials.session.id)?;
    let _access = Zeroizing::new(parse_id(&credentials.access_token)?);
    let _refresh = Zeroizing::new(parse_id(&credentials.refresh_token)?);
    Ok(())
}

fn public_record(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open};
    use std::io::Read;
    let file = std::fs::File::from(open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(configuration());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(configuration());
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
        "invalid hosted control configuration",
    )
}
fn refused() -> io::Error {
    io::Error::other("hosted control request failed")
}
