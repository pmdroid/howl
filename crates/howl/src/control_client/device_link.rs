use std::{
    io::{IsTerminal, Write},
    process::Stdio,
};

use super::*;
use crate::enrollment::hosted::{self, Candidate};

pub(super) struct Browser {
    origin: Url,
    device_names: bool,
}

impl Browser {
    pub(super) fn new(value: &str, device_names: bool) -> io::Result<Self> {
        let origin = Url::parse(value).map_err(|_| configuration())?;
        if value.len() > 512
            || origin.scheme() != "https"
            || origin.origin().ascii_serialization() != value
        {
            return Err(configuration());
        }
        Ok(Self {
            origin,
            device_names,
        })
    }
}

pub(super) fn unsupported_name() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "This control plane does not support device names. To continue, run howl control login without --name.",
    )
}

#[derive(Deserialize)]
struct Started {
    id: String,
    secret: String,
    nonce: String,
    expires_in: u64,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
enum Status {
    Waiting {
        nonce: String,
        network: Option<String>,
        authority: Option<Vec<String>>,
        designation: Option<String>,
    },
    Approved {
        credentials: Credentials,
    },
    Denied,
}

#[derive(Serialize)]
struct PollRequest<'a> {
    #[serde(flatten)]
    proof: Proof,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate: Option<&'a Candidate>,
}

struct Enrollment {
    channel: Id,
    candidate: Candidate,
    digest: Id,
}

fn show_link(
    origin: &Url,
    secret: &str,
    identity: &LocalIdentity,
    name: Option<&str>,
) -> io::Result<()> {
    let _secret = Zeroizing::new(parse_id(secret)?);
    let link = Zeroizing::new(format!("{}link#{secret}", origin.as_str()));
    println!("Open {}", link.as_str());
    println!(
        "Fingerprint {}",
        hex::encode(identity.certificate().fingerprint())
    );
    if let Some(name) = name {
        println!("Name {name}");
    }
    io::stdout().flush()?;
    if io::stdout().is_terminal() && env::var_os("HOWL_NO_BROWSER").is_none() {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        if let Ok(mut child) = std::process::Command::new(opener)
            .arg(link.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
    Ok(())
}

async fn poll(
    service: &Service,
    identity: &LocalIdentity,
    id: &str,
    mut nonce: String,
    candidate: Option<&Candidate>,
) -> io::Result<Status> {
    let bytes = candidate
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    let path = format!("/v1/device-links/{id}");
    for attempt in 0..2 {
        let proof = service.proof(identity, parse_id(id)?, "device-link", nonce, None, &bytes)?;
        let request = service.json(&format!("{path}/poll"), &PollRequest { proof, candidate })?;
        match request.send().await {
            Ok(response) if response.status().is_success() => {
                let body = read_response(response, 512 * 1024).await;
                match body {
                    Ok(body) => return serde_json::from_slice(&body).map_err(|_| refused()),
                    Err(_) if attempt == 0 => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(response) if response.status() == StatusCode::NOT_FOUND => return Err(expired()),
            Ok(response) if response.status() != StatusCode::UNAUTHORIZED => return Err(refused()),
            _ => {}
        }
        if attempt == 1 {
            return Err(refused());
        }
        let challenge: Challenge = service
            .decode(
                service
                    .http
                    .get(service.endpoint(&format!("{path}/challenge"))?),
            )
            .await?;
        nonce = challenge.nonce;
    }
    Err(refused())
}

fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "Device link expired. Run howl control login again.",
    )
}

pub(super) async fn login(
    service: &Service,
    identity: &LocalIdentity,
    state: &Path,
    browser: Browser,
    explicit_name: Option<&str>,
    previous_owner: Option<i64>,
) -> io::Result<Credentials> {
    let started = Instant::now();
    let peer = hex::encode(identity.certificate().as_bytes());
    if explicit_name.is_some() && !browser.device_names {
        return Err(unsupported_name());
    }
    let hostname = rustix::system::uname();
    let suggested = hostname
        .nodename()
        .to_str()
        .ok()
        .and_then(|value| device_name(value).ok());
    let name = explicit_name.or(suggested).filter(|_| browser.device_names);
    #[derive(Serialize)]
    struct Start<'a> {
        peer: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<&'a str>,
    }
    let mut link: Started = service
        .decode(service.json("/v1/device-links", &Start { peer, name })?)
        .await?;
    parse_id(&link.id)?;
    parse_id(&link.nonce)?;
    if !(1..=900).contains(&link.expires_in) {
        return Err(refused());
    }
    let secret = Zeroizing::new(std::mem::take(&mut link.secret));
    show_link(&browser.origin, &secret, identity, name)?;
    let deadline = started + Duration::from_secs(link.expires_in);
    let mut nonce = link.nonce;
    let mut enrollment: Option<Enrollment> = None;
    loop {
        if Instant::now() >= deadline {
            return Err(expired());
        }
        match poll(
            service,
            identity,
            &link.id,
            nonce,
            enrollment.as_ref().map(|e| &e.candidate),
        )
        .await?
        {
            Status::Waiting {
                nonce: next,
                network,
                authority,
                designation,
            } => {
                parse_id(&next)?;
                nonce = next;
                match (network, authority, designation) {
                    (Some(network), Some(records), Some(designation)) => {
                        let channel = parse_id(&network)?;
                        let (candidate, digest) =
                            hosted::link_candidate(state, &records, &designation)?;
                        if enrollment
                            .as_ref()
                            .is_some_and(|prior| prior.channel != channel || prior.digest != digest)
                        {
                            return Err(refused());
                        }
                        enrollment = Some(Enrollment {
                            channel,
                            candidate,
                            digest,
                        });
                    }
                    (None, None, None) => {}
                    _ => return Err(refused()),
                }
            }
            Status::Approved { credentials } => {
                validate_login(&credentials, identity, previous_owner)?;
                let enrollment = enrollment.ok_or_else(refused)?;
                hosted::reserve(state, enrollment.channel)?;
                hosted::pin_designation(state, &enrollment.digest)?;
                return Ok(credentials);
            }
            Status::Denied => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "The network owner denied this device link.",
                ));
            }
        }
        tokio::time::sleep(
            Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now())),
        )
        .await;
    }
}
