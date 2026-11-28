use std::{
    ffi::OsString,
    io::{self, Read},
    path::Path,
    time::Duration,
};

use howl_envelope::{
    AuthorizedSender, Body, DeviceAddress, ReceivePolicy, Recipient, RecipientSecret, Routing,
};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    control_client::read_response,
    identity::{LocalIdentity, PeerCertificate, PeerTrust, StateDirectory},
    node::unix_time,
};

const PROFILE: &str = "cloudflare-beta-profile";
const PAGE_LIMIT: usize = 16 * (2 * howl_envelope::MAX_FRAME_SIZE + 512) + 512;

#[derive(Serialize, Deserialize)]
struct Profile {
    origin: String,
    secret: Option<String>,
    account: Option<String>,
    sequence: u64,
}

#[derive(Deserialize)]
struct Link {
    secret: String,
    device: String,
    fingerprint: String,
    url: String,
}

#[derive(Deserialize)]
struct LinkStatus {
    account: Option<String>,
    state: String,
}

#[derive(Deserialize)]
struct Page {
    envelopes: Vec<Envelope>,
}

#[derive(Deserialize)]
struct Envelope {
    cursor: i64,
    message: String,
    sender: String,
    digest: String,
    ciphertext: String,
}

pub async fn run(args: &[OsString]) -> io::Result<()> {
    let args = args
        .iter()
        .map(|arg| arg.to_str().ok_or_else(invalid))
        .collect::<io::Result<Vec<_>>>()?;
    let state = match args.as_slice() {
        ["link", _, state, _] | ["status" | "fetch", state] | ["send", state, _] => {
            Path::new(state)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Usage: howl cloudflare-beta link ORIGIN STATE NAME | status STATE | send STATE DEVICE | fetch STATE",
            ));
        }
    };
    let directory = StateDirectory::open(state)?;
    let _lock = directory.lock("cloudflare-beta.lock")?;
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(io::Error::other)?;
    let identity = LocalIdentity::load_or_create(state)?;
    if let ["link", origin, _, name] = args.as_slice() {
        let origin = Url::parse(origin).map_err(io::Error::other)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || origin.path() != "/"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(invalid());
        }
        match directory.read_bounded(PROFILE, 4096) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "This beta device already has a link.",
                ));
            }
        }
        let certificate = identity.certificate();
        let link: Link = decode(
            http.post(origin.join("/v1/device-links").map_err(io::Error::other)?)
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(
                    &json!({ "peer": hex::encode(certificate.as_bytes()), "name": name }),
                )?)
                .send()
                .await
                .map_err(io::Error::other)?,
            4096,
        )
        .await?;
        if parse::<32>(&link.device)? != *certificate.device_id()
            || parse::<32>(&link.fingerprint)? != certificate.fingerprint()
            || link.url != format!("{}link#{}", origin, link.secret)
        {
            return Err(invalid());
        }
        parse::<32>(&link.secret)?;
        save(
            &directory,
            &Profile {
                origin: origin.to_string(),
                secret: Some(link.secret),
                account: None,
                sequence: 0,
            },
        )?;
        println!(
            "{}",
            json!({ "device": link.device, "fingerprint": link.fingerprint, "url": link.url })
        );
        return Ok(());
    }

    let mut profile: Profile =
        serde_json::from_slice(&Zeroizing::new(directory.read_bounded(PROFILE, 4096)?))?;
    let origin = Url::parse(&profile.origin).map_err(io::Error::other)?;
    if let ["status", _] = args.as_slice() {
        if let Some(secret) = &profile.secret {
            let status: LinkStatus = decode(
                http.post(
                    origin
                        .join("/v1/device-links/status")
                        .map_err(io::Error::other)?,
                )
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&json!({ "secret": secret }))?)
                .send()
                .await
                .map_err(io::Error::other)?,
                4096,
            )
            .await?;
            if let Some(account) = status.account {
                parse::<32>(&account)?;
                profile.account = Some(account);
                profile.secret = None;
                save(&directory, &profile)?;
            }
            println!("{}", status.state);
        } else {
            println!("approved");
        }
        return Ok(());
    }
    let account = profile.account.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Approve this device and run cloudflare-beta status first.",
        )
    })?;
    let mut client = Device {
        profile,
        origin,
        account,
        http,
        identity,
        state,
    };
    match args.as_slice() {
        ["send", _, recipient] => client.send(&directory, recipient).await,
        ["fetch", _] => client.fetch(&directory).await,
        _ => Err(invalid()),
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid Cloudflare beta control-plane data.",
    )
}

fn parse<const N: usize>(encoded: &str) -> io::Result<[u8; N]> {
    let mut value = [0; N];
    hex::decode_to_slice(encoded, &mut value).map_err(|_| invalid())?;
    Ok(value)
}

fn save(directory: &StateDirectory, profile: &Profile) -> io::Result<()> {
    directory.replace(PROFILE, &Zeroizing::new(serde_json::to_vec(profile)?))
}

async fn decode<T: DeserializeOwned>(response: reqwest::Response, max: usize) -> io::Result<T> {
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "Cloudflare beta request returned HTTP {}.",
            response.status().as_u16()
        )));
    }
    Ok(serde_json::from_slice(
        &read_response(response, max).await?,
    )?)
}

struct Device<'a> {
    profile: Profile,
    origin: Url,
    account: String,
    http: Client,
    identity: LocalIdentity,
    state: &'a Path,
}

impl Device<'_> {
    fn address(&self, device: [u8; 32]) -> io::Result<DeviceAddress> {
        Ok(DeviceAddress {
            account: parse(&self.account)?,
            device,
        })
    }

    fn channel(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"howl/d1-beta-mailbox/v1\0");
        hash.update(self.account.as_bytes());
        hash.finalize().into()
    }

    async fn signed(&self, path: &str, body: Value) -> io::Result<reqwest::Response> {
        let device = hex::encode(self.identity.certificate().device_id());
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let nonce = hex::encode(nonce);
        let expires = unix_time()? + 45;
        let body = serde_json::to_vec(&body)?;
        let proof = serde_json::to_vec(&(
            "howl-d1-proof-v1",
            path,
            &self.account,
            &device,
            &nonce,
            expires,
            hex::encode(Sha256::digest(&body)),
        ))?;
        self.http
            .post(self.origin.join(path).map_err(io::Error::other)?)
            .header("Content-Type", "application/json")
            .header("Howl-Account", &self.account)
            .header("Howl-Device", device)
            .header("Howl-Nonce", nonce)
            .header("Howl-Expires", expires.to_string())
            .header("Howl-Signature", hex::encode(self.identity.sign(&proof)))
            .body(body)
            .send()
            .await
            .map_err(io::Error::other)
    }

    async fn peer(&self, device: &str) -> io::Result<PeerCertificate> {
        let expected = parse::<32>(device)?;
        let trust = PeerTrust::open(self.state)?;
        #[derive(Deserialize)]
        struct Peer {
            peer: String,
        }
        let peer: Peer = decode(
            self.signed("/v1/devices/lookup", json!({ "device": device }))
                .await?,
            4096,
        )
        .await?;
        let certificate = PeerCertificate::from_bytes(parse(&peer.peer)?)?;
        if certificate.device_id() != &expected {
            return Err(invalid());
        }
        trust.pin(&certificate, &certificate.fingerprint())?;
        Ok(certificate)
    }

    async fn send(&mut self, directory: &StateDirectory, recipient: &str) -> io::Result<()> {
        let peer = self.peer(recipient).await?;
        let mut text = Zeroizing::new(String::new());
        io::stdin().take(65_537).read_to_string(&mut text)?;
        let now = unix_time()?;
        self.profile.sequence = self.profile.sequence.checked_add(1).ok_or_else(invalid)?;
        save(directory, &self.profile)?;
        let seed = Zeroizing::new(self.identity.signing_key().to_bytes());
        let signer = howl_envelope::SigningKey::from_bytes(&seed);
        let ciphertext = howl_envelope::seal(
            Routing {
                channel: self.channel(),
                sender: self.address(*self.identity.certificate().device_id())?,
                epoch: 1,
                sequence: self.profile.sequence,
                created_at: now,
                expires_at: 0,
            },
            Body::Chat(&text),
            &signer,
            &[Recipient {
                address: self.address(*peer.device_id())?,
                encryption_key: peer.encryption_public(),
            }],
        )
        .map_err(io::Error::other)?;
        let metadata = howl_envelope::inspect_unverified(&ciphertext).map_err(io::Error::other)?;
        let message = hex::encode(metadata.message_id);
        let response = self.signed("/v1/mailbox/deposit", json!({
            "recipient": recipient, "message": message, "ciphertext": hex::encode(ciphertext), "expires_at": now + 3600
        })).await?;
        match response.status() {
            StatusCode::CREATED | StatusCode::NO_CONTENT => {
                println!("{message}");
                Ok(())
            }
            status => Err(io::Error::other(format!(
                "Cloudflare beta deposit returned HTTP {status}."
            ))),
        }
    }

    async fn fetch(&self, directory: &StateDirectory) -> io::Result<()> {
        let receiver = RecipientSecret::from_bytes(
            self.address(*self.identity.certificate().device_id())?,
            &self.identity.encryption_key().to_bytes(),
        )
        .map_err(io::Error::other)?;
        let mut after = 0;
        for _ in 0..16 {
            let page: Page = decode(
                self.signed("/v1/mailbox/fetch", json!({ "after": after, "limit": 16 }))
                    .await?,
                PAGE_LIMIT,
            )
            .await?;
            if page.envelopes.is_empty() {
                return Ok(());
            }
            for envelope in page.envelopes {
                if envelope.cursor <= after {
                    return Err(invalid());
                }
                after = envelope.cursor;
                let ciphertext = hex::decode(&envelope.ciphertext).map_err(io::Error::other)?;
                if hex::encode(Sha256::digest(&ciphertext)) != envelope.digest {
                    return Err(invalid());
                }
                let sender = self.peer(&envelope.sender).await?;
                let opened = howl_envelope::open(
                    &ciphertext,
                    &ReceivePolicy {
                        channel: self.channel(),
                        epoch: 1,
                        now: unix_time()?,
                        sender: AuthorizedSender {
                            address: self.address(*sender.device_id())?,
                            signing_key: sender.signing_public(),
                            chat: true,
                            wake: false,
                        },
                        authorized_recipients: &[receiver.public_recipient()],
                    },
                    &receiver,
                )
                .map_err(io::Error::other)?;
                let Body::Chat(text) = opened.body else {
                    return Err(invalid());
                };
                if hex::encode(opened.metadata.message_id) != envelope.message {
                    return Err(invalid());
                }
                if directory.write(
                    &format!("cloudflare-beta-mail-{}", envelope.message),
                    &ciphertext,
                )? {
                    println!(
                        "{}",
                        json!({ "message": envelope.message, "sender": envelope.sender, "text": text })
                    );
                }
                let response = self.signed("/v1/mailbox/ack", json!({
                    "cursor": envelope.cursor, "message": envelope.message, "digest": envelope.digest
                })).await?;
                if response.status() != StatusCode::NO_CONTENT {
                    return Err(io::Error::other(format!(
                        "Cloudflare beta acknowledgment returned HTTP {}.",
                        response.status()
                    )));
                }
            }
        }
        Ok(())
    }
}
