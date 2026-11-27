use std::borrow::Cow;

use reqwest::{Client, RequestBuilder};
use rmcp::model::{
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
    Tool,
};
use serde_json::Value;

use super::*;

const READ_TOKEN: &str = "a7838f771730ee0ea0a2efd953d383336";
const SEND_TOKEN: &str = "01ef1de2129e68e998fa6e0bb3f08d14a";
const ROTATED_TOKEN: &str = "319a3511ee73504410b9d519c681778cf";
const EXPIRED_TOKEN: &str = "282b5cfae7e5b22c751463435f16d256";
const NEW: &str = "2026-07-28";
const OLD: &str = "2025-11-25";
const CHANNEL: [u8; 32] = [0x11; 32];
const OTHER_CHANNEL: [u8; 32] = [0x22; 32];

#[derive(Clone)]
struct Probe;

impl ServerHandler for Probe {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28])
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let parts = context
            .extensions
            .get::<axum::http::request::Parts>()
            .unwrap();
        assert!(!parts.headers.contains_key(header::AUTHORIZATION));
        let principal = authenticated(&context)?;
        assert!(principal.is_current().await);
        assert!(!principal.permits(&OTHER_CHANNEL, IntegrationPermission::Read));
        let mut tools = Vec::new();
        for (name, permission) in [
            ("read", IntegrationPermission::Read),
            ("send", IntegrationPermission::Send),
        ] {
            if principal.permits(&CHANNEL, permission) {
                tools.push(Tool::new(
                    name,
                    "Test scoped tool",
                    Arc::new(json!({"type": "object"}).as_object().unwrap().clone()),
                ));
            }
        }
        Ok(ListToolsResult::with_all_items(tools))
    }
}

fn grant(id: &str, token: &str, expires_at: u64, permission: &str) -> Value {
    json!({
        "id": id,
        "token_sha256": hex::encode(Sha256::digest(token)),
        "expires_at": expires_at,
        "channels": [hex::encode(CHANNEL)],
        "permissions": [permission]
    })
}

struct Http {
    temp: tempfile::TempDir,
    resource: String,
    client: Client,
    task: tokio::task::JoinHandle<io::Result<()>>,
}

impl Http {
    async fn start(rate: u16) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let resource = format!("http://{}/mcp", listener.local_addr().unwrap());
        let config = temp.path().join("mcp.json");
        Self::write_config(&config, &resource, READ_TOKEN, rate);
        let (app, _) = router(config, Probe).await.unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        Self {
            temp,
            resource,
            client,
            task,
        }
    }

    fn write_config(path: &Path, resource: &str, reader: &str, rate: u16) {
        let expires_at = unix_time().unwrap() + 300;
        let value = json!({
            "resource": resource,
            "authorization_servers": ["https://auth.example.test/howl"],
            "allowed_origins": ["https://allowed.example.test"],
            "requests_per_minute": rate,
            "grants": [
                grant("reader", reader, expires_at, "read"),
                grant("writer", SEND_TOKEN, expires_at, "send"),
                grant("expired", EXPIRED_TOKEN, 1, "read")
            ]
        });
        let next = path.with_extension("next");
        std::fs::write(&next, value.to_string()).unwrap();
        std::fs::rename(next, path).unwrap();
    }

    fn post(&self, body: Value) -> RequestBuilder {
        self.client
            .post(&self.resource)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .body(body.to_string())
    }

    fn stateless(&self, method: &str) -> RequestBuilder {
        self.post(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": NEW,
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }))
        .header("MCP-Protocol-Version", NEW)
        .header("Mcp-Method", method)
    }

    fn initialize(&self, token: &str) -> RequestBuilder {
        self.post(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": OLD,
                "clientInfo": {"name": "gateway-test", "version": "1"},
                "capabilities": {}
            }
        }))
        .bearer_auth(token)
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn rpc_response(response: reqwest::Response) -> Value {
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    let data = body
        .lines()
        .find_map(|line| {
            line.strip_prefix("data:")
                .map(str::trim)
                .filter(|data| !data.is_empty())
        })
        .unwrap_or(&body);
    serde_json::from_str(data).unwrap()
}

#[tokio::test]
async fn discovers_the_protected_resource_and_serves_stateless_scoped_tools() {
    let http = Http::start(100).await;
    let response = http.stateless("server/discover").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge_url = response.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .strip_prefix("Bearer resource_metadata=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();
    let response = http.client.get(challenge_url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let metadata: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(metadata["resource"], http.resource);
    assert_eq!(
        metadata["authorization_servers"][0],
        "https://auth.example.test/howl"
    );

    let response = http
        .stateless("server/discover")
        .bearer_auth(READ_TOKEN)
        .send()
        .await
        .unwrap();
    assert!(response.headers().get(&SESSION).is_none());
    let discovery = rpc_response(response).await;
    assert_eq!(discovery["result"]["supportedVersions"], json!([OLD, NEW]));

    for (token, expected) in [(READ_TOKEN, "read"), (SEND_TOKEN, "send")] {
        let response = http
            .stateless("tools/list")
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let results = rpc_response(response).await;
        let tools = results["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], expected);
    }
}

#[tokio::test]
async fn binds_legacy_sessions_to_a_single_active_credential() {
    let http = Http::start(100).await;
    let response = http.initialize(READ_TOKEN).send().await.unwrap();
    let session = response.headers()[&SESSION].clone();
    let initialized = rpc_response(response).await;
    assert_eq!(initialized["result"]["protocolVersion"], OLD);
    let response = http
        .post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .bearer_auth(READ_TOKEN)
        .header(&SESSION, &session)
        .header("MCP-Protocol-Version", OLD)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let tools = http
        .post(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .bearer_auth(READ_TOKEN)
        .header(&SESSION, &session)
        .header("MCP-Protocol-Version", OLD)
        .send()
        .await
        .unwrap();
    assert_eq!(
        rpc_response(tools).await["result"]["tools"][0]["name"],
        "read"
    );

    for method in [Method::GET, Method::POST, Method::DELETE] {
        let wrong_owner = http
            .client
            .request(method, &http.resource)
            .bearer_auth(SEND_TOKEN)
            .header(&SESSION, &session)
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_owner.status(), StatusCode::NOT_FOUND);
    }

    Http::write_config(
        &http.temp.path().join("mcp.json"),
        &http.resource,
        ROTATED_TOKEN,
        100,
    );
    let rejected = http.initialize(READ_TOKEN).send().await.unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let rejected = http
        .client
        .delete(&http.resource)
        .bearer_auth(ROTATED_TOKEN)
        .header(&SESSION, &session)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        http.initialize(ROTATED_TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejects_expired_grants_disallowed_origins_hosts_excess_body_and_rate() {
    let http = Http::start(3).await;
    let expired = http.initialize(EXPIRED_TOKEN).send().await.unwrap();
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
    let bad_origin = http
        .initialize(READ_TOKEN)
        .header(header::ORIGIN, "https://denied.example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);
    let bad_host = http
        .initialize(READ_TOKEN)
        .header(header::HOST, "denied.example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);
    let allowed = http
        .initialize(READ_TOKEN)
        .header(header::ORIGIN, "https://allowed.example.test")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    let rate_limited = http.initialize(READ_TOKEN).send().await.unwrap();
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(rate_limited.headers().contains_key(header::RETRY_AFTER));
    let oversized = http
        .post(json!({"data": "a".repeat(70_000)}))
        .bearer_auth(SEND_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
