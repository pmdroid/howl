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
    let identity = LocalIdentity::load_or_create(state)?;
    let state = StateDirectory::open(state)?;
    let _lock = crate::identity::retry_state_lock(|| state.lock(LOCK)).await?;
    let existing = load(&state)?;
    let service = Service::for_login(existing.as_ref()).await?;
    if let Some(existing) = &existing
        && (existing.origin != service.origin.as_str()
            || parse_id(&existing.audience)? != service.audience)
    {
        return Err(io::Error::other(
            "local control credentials belong to a different hosted service",
        ));
    }
    let certificate = identity.certificate();
    let request = serde_json::json!({
        "device_id": hex::encode(certificate.device_id()),
        "signing_key": hex::encode(certificate.signing_public()),
    });
    let started = Instant::now();
    let login: Login = service
        .decode(service.json("/v1/login/device", &request)?)
        .await?;
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
        let proof = service.proof(&identity, subject, "poll", challenge, None, b"")?;
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
            Poll::Verified { credentials } => {
                validate(&credentials, &identity)?;
                if existing.as_ref().is_some_and(|prior| {
                    prior.credentials.session.github_id != credentials.session.github_id
                }) {
                    return Err(io::Error::other(
                        "This device profile is linked to a different GitHub account.",
                    ));
                }
                save(&state, &service, credentials)?;
                println!("GitHub login complete.");
                return Ok(());
            }
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
            let token = &stored.credentials.refresh_token;
            let nonce = service.challenge("refresh", Some(token), None).await?;
            let subject = parse_id(&stored.credentials.session.id)?;
            let proof = service.proof(&identity, subject, "refresh", nonce, Some(token), b"")?;
            let credentials: Credentials = service
                .decode(service.json("/v1/auth/refresh", &proof)?.bearer_auth(token))
                .await?;
            validate(&credentials, &identity)?;
            if credentials.session != stored.credentials.session {
                return Err(refused());
            }
            stored = save(&state, &service, credentials)?;
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

    async fn for_login(existing: Option<&Stored>) -> io::Result<Self> {
        let origin = configured("HOWL_CONTROL_URL")?;
        match env::var("HOWL_CONTROL_AUDIENCE") {
            Ok(audience) => return Self::new(&origin, parse_id(&audience)?),
            Err(env::VarError::NotUnicode(_)) => return Err(configuration()),
            Err(env::VarError::NotPresent) => {}
        }
        if let Some(existing) = existing {
            return Self::new(&origin, parse_id(&existing.audience)?);
        }
        let (origin, http) = Self::connection(&origin)?;
        let url = origin
            .join("/v1/auth/config")
            .map_err(|_| configuration())?;
        let response = http.get(url).send().await.map_err(|_| refused())?;
        #[derive(Deserialize)]
        struct PublicConfig {
            audience: String,
        }
        let config: PublicConfig = serde_json::from_slice(&read_response(response, 256).await?)?;
        Self::from_parts(origin, http, parse_id(&config.audience)?)
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
