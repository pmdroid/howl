use std::{path::Path, time::Duration};

use ed25519_dalek::SigningKey;
use howl_envelope::{AgentReply, AgentRole, Body, DeviceAddress, Id, Recipient, Routing};
use reqwest::{Client, RequestBuilder, Response};
use rmcp::model::{ClientCapabilities, Implementation, ProtocolVersion, RequestMetaObject};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, task::JoinHandle};

use crate::{
    channel::Channel,
    enrollment::{AuthorityRecord, AuthorityStore, Designation, Enroll, PairingTicket},
    identity::{LocalIdentity, PeerTrust, StateDirectory},
    node, remote_mcp_handler,
};

const PRIMARY: &str = "test-primary-connector-token-00000001";
const OTHER: &str = "test-secondary-connector-token-0000002";

fn enroll(gateway: &Path, peer: &Path) -> (Id, Id) {
    let local = LocalIdentity::load_or_create(gateway).unwrap();
    let remote = LocalIdentity::load_or_create(peer).unwrap();
    let operator = SigningKey::from_bytes(&[41; 32]);
    let recovery = SigningKey::from_bytes(&[42; 32]);
    let signer = SigningKey::from_bytes(&[43; 32]);
    let genesis = AuthorityRecord::genesis(&operator, &recovery);
    let account = genesis.digest();
    let store = AuthorityStore::open(gateway).unwrap();
    store.initialize(&[genesis], account, account).unwrap();
    let designation =
        Designation::issue(store.current().unwrap(), 1, &operator, &signer, &[]).unwrap();
    let files = StateDirectory::open(gateway).unwrap();
    files
        .write("enrollment-designation", designation.as_bytes())
        .unwrap();
    files
        .write("enrollment-signer-key", &signer.to_bytes())
        .unwrap();
    for (identity, name) in [
        (&local, "enrollment-certificate".to_owned()),
        (
            &remote,
            format!(
                "enrollment-peer-{}",
                hex::encode(remote.certificate().device_id())
            ),
        ),
    ] {
        let certificate = identity.certificate();
        let (ticket, offer) = PairingTicket::create(
            &designation,
            &signer,
            &certificate,
            certificate.fingerprint(),
            1,
            100,
        )
        .unwrap();
        let response = offer
            .respond(&designation, identity, ticket.invitation_secret(), 105)
            .unwrap();
        let signed = ticket
            .enroll(Enroll {
                state: gateway,
                designation: &designation,
                signer: &signer,
                peer: &certificate,
                offer: &offer,
                response: &response,
                now: 110,
            })
            .unwrap();
        files.write(&name, signed.as_bytes()).unwrap();
    }
    let certificate = remote.certificate();
    PeerTrust::open(gateway)
        .unwrap()
        .pin(&certificate, &certificate.fingerprint())
        .unwrap();
    let device = *certificate.device_id();
    let channel = Channel::create(gateway, &local, &[device]).unwrap();
    let hint = node::export_hint(peer, "127.0.0.1:1".parse().unwrap()).unwrap();
    node::import_hint(gateway, &hint).unwrap();
    (*channel.id(), device)
}

async fn start_gateway(
    gateway: &Path,
    configuration: &Path,
    channel: Id,
) -> (String, JoinHandle<std::io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let grants: Vec<_> = [("primary", PRIMARY), ("secondary", OTHER)]
        .into_iter()
        .map(|(id, token)| {
            json!({
                "id": id, "token_sha256": hex::encode(Sha256::digest(token.as_bytes())),
                "expires_at": node::unix_time().unwrap() + 600,
                "channels": [hex::encode(channel)], "permissions": ["read", "wake", "cancel"],
            })
        })
        .collect();
    std::fs::write(
        configuration,
        json!({"resource": url, "grants": grants}).to_string(),
    )
    .unwrap();
    let gateway = gateway.to_owned();
    let configuration = configuration.to_owned();
    let server = tokio::spawn(async move {
        remote_mcp_handler::serve_gateway(&gateway, &configuration, listener).await
    });
    (url, server)
}

fn accept_signed_reply(gateway: &Path, peer: &Path, channel: Id, wake: &str) {
    let local = LocalIdentity::load_or_create(gateway).unwrap();
    let remote = LocalIdentity::load_or_create(peer).unwrap();
    let local_cert = local.certificate();
    let remote_cert = remote.certificate();
    let account = node::device_for(gateway, &local_cert).unwrap().account;
    let signer = howl_envelope::SigningKey::from_bytes(&remote.signing_key().to_bytes());
    let wake = hex::decode(wake).unwrap().try_into().unwrap();
    let packet = howl_envelope::seal(
        Routing {
            channel,
            sender: DeviceAddress {
                account,
                device: *remote_cert.device_id(),
            },
            epoch: Channel::load(gateway, &local, &channel).unwrap().epoch(),
            sequence: 1,
            created_at: node::unix_time().unwrap(),
            expires_at: 0,
        },
        Body::AgentReply(AgentReply {
            agent: AgentRole::Reviewer.agent_id(remote_cert.device_id()),
            role: AgentRole::Reviewer,
            in_reply_to: wake,
            context_digest: [51; 32],
            text: "review completed by the signed peer",
        }),
        &signer,
        &[Recipient {
            address: DeviceAddress {
                account,
                device: *local_cert.device_id(),
            },
            encryption_key: local_cert.encryption_public(),
        }],
    )
    .unwrap();
    let mut delivery = node::open_delivery(
        gateway,
        &StateDirectory::open(gateway).unwrap(),
        &local_cert,
    )
    .unwrap();
    node::accept_envelope(
        gateway,
        &local,
        &mut delivery,
        &packet,
        howl_envelope::inspect_unverified(&packet).unwrap(),
        node::EnvelopeSource::Peer(&remote_cert),
    )
    .unwrap();
}

struct WireClient {
    client: Client,
    url: String,
}

impl WireClient {
    fn post(&self, token: &str) -> RequestBuilder {
        self.client
            .post(&self.url)
            .bearer_auth(token)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
    }

    async fn modern(&self, token: &str, tasks: bool, method: &str, mut params: Value) -> Value {
        let name = params
            .get("name")
            .or_else(|| params.get("taskId"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let capabilities = if tasks {
            ClientCapabilities::builder().enable_tasks().build()
        } else {
            ClientCapabilities::default()
        };
        params["_meta"] = serde_json::to_value(RequestMetaObject::with_client_context(
            ProtocolVersion::V_2026_07_28,
            Implementation::new("howl-smoke", "1"),
            capabilities,
        ))
        .unwrap();
        let mut request = self
            .post(token)
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = name {
            request = request.header("mcp-name", name);
        }
        send(
            request,
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        )
        .await
    }

    async fn legacy_wake(&self, params: Value) -> Value {
        let initialized = rpc(self.post(PRIMARY), json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "clientInfo": {"name": "legacy-smoke", "version": "1"},
                "capabilities": {"extensions": {"io.modelcontextprotocol/tasks": {}}},
            }
        })).await;
        let session = initialized.headers().get("mcp-session-id").unwrap().clone();
        let response = decode(initialized).await;
        assert_eq!(
            response["result"]["protocolVersion"], "2025-11-25",
            "{response}"
        );
        assert!(
            response["result"]["capabilities"]["extensions"]
                .get("io.modelcontextprotocol/tasks")
                .is_none()
        );
        let request = || {
            self.post(PRIMARY)
                .header("mcp-protocol-version", "2025-11-25")
                .header("mcp-session-id", &session)
        };
        rpc(
            request(),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
        send(
            request(),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params,
            }),
        )
        .await
    }
}

async fn rpc(request: RequestBuilder, body: Value) -> Response {
    request.body(body.to_string()).send().await.unwrap()
}

async fn decode(response: Response) -> Value {
    let text = response.text().await.unwrap();
    serde_json::from_str(&text)
        .ok()
        .or_else(|| {
            text.lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .find_map(|payload| serde_json::from_str(payload).ok())
        })
        .unwrap_or_else(|| panic!("invalid MCP response: {text}"))
}

async fn send(request: RequestBuilder, body: Value) -> Value {
    decode(rpc(request, body).await).await
}

#[tokio::test]
async fn modern_tasks_and_tools_only_clients_share_a_run_after_gateway_restart() {
    let scratch = tempfile::tempdir().unwrap();
    let gateway = scratch.path().join("gateway");
    let peer = scratch.path().join("peer");
    let configuration = scratch.path().join("gateway.json");
    let (channel, device) = enroll(&gateway, &peer);
    let mesh = tokio::spawn({
        let gateway = gateway.clone();
        async move { node::run(&gateway, "127.0.0.1:0", None).await }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !gateway.join("mesh.sock").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (url, server) = start_gateway(&gateway, &configuration, channel).await;
    let mut wire = WireClient {
        client: Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
        url,
    };
    let discovery = wire
        .modern(PRIMARY, true, "server/discover", json!({}))
        .await;
    assert!(
        discovery["result"]["capabilities"]["extensions"]
            .get("io.modelcontextprotocol/tasks")
            .is_some(),
        "{discovery}"
    );
    let wake = json!({"name": "wake", "arguments": {
        "channel": hex::encode(channel), "peer": hex::encode(device),
        "target": hex::encode(AgentRole::Reviewer.agent_id(&device)),
        "key": "one-discussion", "lifetime": 90, "text": "review the plan",
    }});
    let native = wire.modern(PRIMARY, true, "tools/call", wake.clone()).await;
    assert_eq!(native["result"]["resultType"], "task", "{native}");
    let id = native["result"]["taskId"].as_str().unwrap();
    let fallback = wire
        .modern(PRIMARY, false, "tools/call", wake.clone())
        .await;
    let run = &fallback["result"]["structuredContent"];
    assert_eq!(run["run"], id, "{fallback}");
    assert!(run["wake_message"].is_string());
    let legacy = wire.legacy_wake(wake).await;
    assert_eq!(legacy["result"]["structuredContent"]["run"], id, "{legacy}");
    let task = json!({"taskId": id});
    let status = wire.modern(PRIMARY, true, "tasks/get", task.clone()).await;
    assert_eq!(status["result"]["status"], "working", "{status}");
    accept_signed_reply(
        &gateway,
        &peer,
        channel,
        run["wake_message"].as_str().unwrap(),
    );

    server.abort();
    let _ = server.await;
    let (url, restarted) = start_gateway(&gateway, &configuration, channel).await;
    wire.url = url;
    let status = wire.modern(PRIMARY, true, "tasks/get", task.clone()).await;
    assert_eq!(status["result"]["status"], "completed", "{status}");
    let fallback_status = wire
        .modern(
            PRIMARY,
            false,
            "tools/call",
            json!({
                "name": "get_run", "arguments": {"channel": hex::encode(channel), "run": id},
            }),
        )
        .await;
    let result = &status["result"]["result"]["structuredContent"];
    assert_eq!(
        result["reply"]["text"], "review completed by the signed peer",
        "{status}"
    );
    assert_eq!(
        *result, fallback_status["result"]["structuredContent"],
        "{fallback_status}"
    );
    let denied = wire.modern(OTHER, true, "tasks/get", task.clone()).await;
    assert_eq!(denied["error"]["code"], -32602, "{denied}");
    let no_extension = wire.modern(PRIMARY, false, "tasks/get", task.clone()).await;
    assert_eq!(no_extension["error"]["code"], -32021, "{no_extension}");
    let update = wire
        .modern(
            PRIMARY,
            true,
            "tasks/update",
            json!({"taskId": id, "inputResponses": {}}),
        )
        .await;
    assert_eq!(update["error"]["code"], -32602, "{update}");
    let cancelled = wire.modern(PRIMARY, true, "tasks/cancel", task).await;
    assert_eq!(cancelled["result"]["resultType"], "complete", "{cancelled}");
    restarted.abort();
    node::stop(&gateway).await.unwrap();
    mesh.await.unwrap().unwrap();
}
