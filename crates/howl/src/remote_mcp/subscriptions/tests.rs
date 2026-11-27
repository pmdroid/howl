use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use reqwest::{Client, RequestBuilder, Response, header};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{
    channel::Channel,
    delivery::{DeliveryStore, Frame, Payload, Stream},
    enrollment::{AuthorityRecord, AuthorityStore, Designation, Enroll, PairingTicket},
    identity::{LocalIdentity, StateDirectory},
    node,
    remote_mcp_handler::serve_gateway,
};

use super::*;

const TOKEN: &str = "3d448e8a8fc2f5b3d158972de2ac8806";
const NEW_PROTOCOL: &str = "2026-07-28";
const OLD_PROTOCOL: &str = "2025-11-25";

struct Gateway {
    _temp: tempfile::TempDir,
    configuration: PathBuf,
    identity: LocalIdentity,
    delivery: DeliveryStore,
    channel: Id,
    other: Id,
    sequence: u64,
    device: crate::delivery::Device,
    endpoint: String,
    client: Client,
    server: JoinHandle<std::io::Result<()>>,
}

impl Gateway {
    async fn start() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("node");
        let identity = enrolled(&state);
        let certificate = identity.certificate();
        let channel = *Channel::create(&state, &identity, &[]).unwrap().id();
        let other = *Channel::create(&state, &identity, &[]).unwrap().id();
        let directory = StateDirectory::open(&state).unwrap();
        let mut delivery = node::open_delivery(&state, &directory, &certificate).unwrap();
        for channel in [channel, other] {
            delivery.set_epoch(channel, 1).unwrap();
        }
        let device = node::device_for(&state, &certificate).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let configuration = temp.path().join("gateway.json");
        write_config(&configuration, &endpoint, channel, true);
        let config = configuration.clone();
        let server = tokio::spawn(async move { serve_gateway(&state, &config, listener).await });
        Self {
            _temp: temp,
            configuration,
            identity,
            delivery,
            channel,
            other,
            sequence: 0,
            device,
            endpoint,
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            server,
        }
    }

    fn commit(&mut self, channel: Id) -> u64 {
        self.sequence += 1;
        let now = node::unix_time().unwrap();
        let frame = Frame {
            stream: Stream {
                channel,
                signing_key: [9; 32],
                sender: self.device,
            },
            message: [self.sequence.try_into().unwrap(); 32],
            sequence: self.sequence,
            epoch: 1,
            created_at: now,
            expires_at: 0,
        };
        self.delivery
            .accept_authenticated(
                frame,
                &self.sequence.to_be_bytes(),
                Payload::Chat(&format!("fixture {}", self.sequence)),
                now,
                self.identity.signing_key(),
            )
            .unwrap();
        self.delivery
            .channel_events(channel, 0, 256)
            .unwrap()
            .last()
            .unwrap()
            .cursor
    }

    fn post(&self, body: Value) -> RequestBuilder {
        self.client
            .post(&self.endpoint)
            .bearer_auth(TOKEN)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(body.to_string())
    }

    fn modern(&self, method: &str, name: Option<&str>, mut params: Value) -> RequestBuilder {
        params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!(NEW_PROTOCOL);
        params["_meta"]["io.modelcontextprotocol/clientInfo"] =
            json!({"name": "subscription-test", "version": "1"});
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
        let request = self
            .post(json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params}))
            .header("Mcp-Protocol-Version", NEW_PROTOCOL)
            .header("Mcp-Method", method);
        if let Some(name) = name {
            request.header("Mcp-Name", name)
        } else {
            request
        }
    }

    async fn modern_listen(&self, channel: Id) -> Sse {
        let response = self
            .modern(
                "subscriptions/listen",
                None,
                json!({"notifications": {"resourceSubscriptions": [history(channel)]}}),
            )
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        Sse::new(response)
    }

    async fn read_events(&self, after: u64, limit: usize) -> Value {
        let response = self
            .modern(
                "tools/call",
                Some("read_events"),
                json!({
                    "name": "read_events",
                    "arguments": {"channel": hex::encode(self.channel), "after": after, "limit": limit}
                }),
            )
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        rpc_result(response).await["structuredContent"].clone()
    }

    fn legacy_call(&self, session: &str, uri: String, method: &str) -> RequestBuilder {
        self.post(json!({"jsonrpc": "2.0", "id": 9, "method": method, "params": {"uri": uri}}))
            .header("Mcp-Protocol-Version", OLD_PROTOCOL)
            .header("Mcp-Session-Id", session)
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn enrolled(state: &Path) -> LocalIdentity {
    let identity = LocalIdentity::load_or_create(state).unwrap();
    let peer = identity.certificate();
    let operator = SigningKey::from_bytes(&[1; 32]);
    let offline = SigningKey::from_bytes(&[2; 32]);
    let signer = SigningKey::from_bytes(&[3; 32]);
    let genesis = AuthorityRecord::genesis(&operator, &offline);
    let account = genesis.digest();
    let authority = AuthorityStore::open(state).unwrap();
    authority
        .initialize(std::slice::from_ref(&genesis), account, account)
        .unwrap();
    let designation =
        Designation::issue(authority.current().unwrap(), 1, &operator, &signer, &[]).unwrap();
    let (ticket, offer) =
        PairingTicket::create(&designation, &signer, &peer, peer.fingerprint(), 1, 100).unwrap();
    let response = offer
        .respond(&designation, &identity, ticket.invitation_secret(), 110)
        .unwrap();
    let certificate = ticket
        .enroll(Enroll {
            state,
            designation: &designation,
            signer: &signer,
            peer: &peer,
            offer: &offer,
            response: &response,
            now: 120,
        })
        .unwrap();
    let directory = StateDirectory::open(state).unwrap();
    directory
        .replace("enrollment-designation", designation.as_bytes())
        .unwrap();
    directory
        .replace("enrollment-certificate", certificate.as_bytes())
        .unwrap();
    directory
        .replace("enrollment-signer-key", &signer.to_bytes())
        .unwrap();
    identity
}

fn write_config(path: &Path, endpoint: &str, channel: Id, granted: bool) {
    let grants = if granted {
        vec![json!({
            "id": "reader",
            "token_sha256": hex::encode(Sha256::digest(TOKEN)),
            "expires_at": node::unix_time().unwrap() + 300,
            "channels": [hex::encode(channel)],
            "permissions": ["read"]
        })]
    } else {
        Vec::new()
    };
    let next = path.with_extension("next");
    std::fs::write(
        &next,
        json!({"resource": endpoint, "grants": grants}).to_string(),
    )
    .unwrap();
    std::fs::rename(next, path).unwrap();
}

fn history(channel: Id) -> String {
    format!("howl://channels/{}/history", hex::encode(channel))
}

struct Sse {
    response: Response,
    bytes: Vec<u8>,
}

impl Sse {
    fn new(response: Response) -> Self {
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/event-stream")
        );
        Self {
            response,
            bytes: Vec::new(),
        }
    }

    async fn next(&mut self) -> Option<Value> {
        loop {
            if let Some(end) = self.bytes.windows(2).position(|pair| pair == b"\n\n") {
                let event: Vec<_> = self.bytes.drain(..end + 2).collect();
                if let Some(data) = std::str::from_utf8(&event)
                    .unwrap()
                    .lines()
                    .find_map(|line| line.strip_prefix("data: ").filter(|data| !data.is_empty()))
                {
                    return Some(serde_json::from_str(data).unwrap());
                }
            } else {
                let bytes = self.response.chunk().await.unwrap()?;
                self.bytes.extend_from_slice(&bytes);
            }
        }
    }

    async fn message(&mut self) -> Value {
        timeout(Duration::from_secs(3), self.next())
            .await
            .unwrap()
            .unwrap()
    }
}

async fn rpc_result(response: Response) -> Value {
    let reply = if response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("application/json")
    {
        serde_json::from_str::<Value>(&response.text().await.unwrap()).unwrap()
    } else {
        Sse::new(response).message().await
    };
    reply
        .get("result")
        .unwrap_or_else(|| panic!("unexpected MCP response {reply}"))
        .clone()
}

#[tokio::test]
async fn modern_listen_catches_up_after_disconnect_and_stops_on_revocation() {
    let mut gateway = Gateway::start().await;
    let mut stream = gateway.modern_listen(gateway.channel).await;
    let ack = stream.message().await;
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
    assert_eq!(
        ack["params"]["notifications"]["resourceSubscriptions"][0],
        history(gateway.channel)
    );
    let initial = stream.message().await;
    assert_eq!(initial["method"], "notifications/resources/updated");
    assert_eq!(initial["params"]["uri"], history(gateway.channel));
    gateway.commit(gateway.other);
    assert!(timeout(TICK + TICK, stream.next()).await.is_err());

    let mut timings = Vec::new();
    let mut last = 0;
    for _ in 0..15 {
        let started = Instant::now();
        last = gateway.commit(gateway.channel);
        let notification = stream.message().await;
        assert_eq!(notification["method"], "notifications/resources/updated");
        assert_eq!(notification["params"]["uri"], history(gateway.channel));
        timings.push(started.elapsed());
    }
    timings.sort_unstable();
    let p50 = timings[timings.len() / 2];
    let p95 = timings[(timings.len() * 95).div_ceil(100) - 1];
    eprintln!(
        "Howl MCP resource notification p50={}ms p95={}ms",
        p50.as_millis(),
        p95.as_millis()
    );
    assert!(p95 < Duration::from_secs(1));

    drop(stream);
    let missed = gateway.commit(gateway.channel);
    let newest = gateway.commit(gateway.channel);
    let first = gateway.read_events(last, 1).await;
    assert_eq!(first["cursor"], missed);
    assert_eq!(first["more"], true);
    let caught_up = gateway.read_events(missed, 1).await;
    assert_eq!(caught_up["cursor"], newest);
    assert_eq!(caught_up["more"], false);
    assert!(
        gateway.read_events(newest, 1).await["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let lost = gateway.commit(gateway.channel);
    let now = node::unix_time().unwrap();
    gateway
        .delivery
        .prune(gateway.channel, now + 1, now)
        .unwrap();
    let gap = gateway.read_events(newest, 1).await;
    assert_eq!(gap["cursor"], lost);
    assert_eq!(gap["gap"], true);
    assert_eq!(gateway.read_events(lost, 1).await["gap"], false);

    let mut denied = gateway.modern_listen(gateway.other).await;
    assert_eq!(
        denied.message().await["method"],
        "notifications/subscriptions/acknowledged"
    );
    assert!(denied.message().await.get("error").is_some());
    let mut resumed = gateway.modern_listen(gateway.channel).await;
    assert_eq!(
        resumed.message().await["method"],
        "notifications/subscriptions/acknowledged"
    );
    assert_eq!(
        resumed.message().await["method"],
        "notifications/resources/updated"
    );
    write_config(
        &gateway.configuration,
        &gateway.endpoint,
        gateway.channel,
        false,
    );
    gateway.commit(gateway.channel);
    assert!(resumed.message().await.get("error").is_some());
}

#[tokio::test]
async fn bounded_wait_emits_request_progress_and_reads_after_the_saved_cursor() {
    let mut gateway = Gateway::start().await;
    let after = gateway.commit(gateway.channel);
    let request = gateway.modern(
        "tools/call",
        Some("wait_for_events"),
        json!({
            "name": "wait_for_events",
            "arguments": {
                "channel": hex::encode(gateway.channel),
                "after": after,
                "wait_ms": 5000
            },
            "_meta": { "progressToken": "wait-test" }
        }),
    );
    let response = request.send().await.unwrap().error_for_status().unwrap();
    let mut stream = Sse::new(response);
    let progress = stream.message().await;
    assert_eq!(progress["method"], "notifications/progress");
    assert_eq!(progress["params"]["progressToken"], "wait-test");
    assert_eq!(progress["params"]["message"], "Waiting for channel events");
    let next = gateway.commit(gateway.channel);
    let result = stream.message().await;
    assert_eq!(result["result"]["structuredContent"]["cursor"], next);
    assert_eq!(
        result["result"]["structuredContent"]["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn legacy_sse_pushes_updates_to_only_subscribed_resources() {
    let mut gateway = Gateway::start().await;
    let initialize = gateway
        .post(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": OLD_PROTOCOL,
                "clientInfo": {"name": "subscription-test", "version": "1"},
                "capabilities": {}
            }
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let session = initialize.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        rpc_result(initialize).await["protocolVersion"],
        OLD_PROTOCOL
    );
    gateway
        .post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .header("Mcp-Protocol-Version", OLD_PROTOCOL)
        .header("Mcp-Session-Id", &session)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let response = gateway
        .client
        .get(&gateway.endpoint)
        .bearer_auth(TOKEN)
        .header(header::ACCEPT, "text/event-stream")
        .header("Mcp-Protocol-Version", OLD_PROTOCOL)
        .header("Mcp-Session-Id", &session)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let mut stream = Sse::new(response);
    let uri = history(gateway.channel);
    for method in ["resources/subscribe", "resources/subscribe"] {
        let response = gateway
            .legacy_call(&session, uri.clone(), method)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        assert!(rpc_result(response).await.is_object());
    }
    gateway.commit(gateway.channel);
    let update = stream.message().await;
    assert_eq!(update["method"], "notifications/resources/updated");
    assert_eq!(update["params"]["uri"], uri);
    assert!(timeout(TICK + TICK, stream.next()).await.is_err());
    let response = gateway
        .legacy_call(&session, uri, "resources/unsubscribe")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert!(rpc_result(response).await.is_object());
    gateway.commit(gateway.channel);
    assert!(timeout(TICK + TICK, stream.next()).await.is_err());
}
