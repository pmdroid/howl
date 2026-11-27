use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use reqwest::{Client, Response, StatusCode, header};
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(15);

struct Howl(Child);

impl Drop for Howl {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(state: &Path, args: &[&str], final_line: &str) -> (Howl, Vec<String>) {
    let mut child = Howl(
        Command::new(env!("CARGO_BIN_EXE_howl"))
            .args(args)
            .arg(state)
            .args((args[0] == "mesh").then_some("127.0.0.1:0"))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + WAIT;
    let mut lines = Vec::new();
    while let Ok(line) = receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        let final_line = line.starts_with(final_line);
        lines.push(line);
        if final_line {
            return (child, lines);
        }
    }
    panic!("Howl did not start");
}

struct Browser {
    client: Client,
    origin: String,
    token: String,
}

impl Browser {
    fn start(state: &Path) -> (Howl, Self) {
        let (process, lines) = start(state, &["web"], "Open ");
        let (url, token) = lines[0]
            .strip_prefix("Open ")
            .unwrap()
            .split_once('#')
            .unwrap();
        let origin = url.trim_end_matches('/');
        assert!(origin.starts_with("http://127.0.0.1:"));
        assert_eq!(token.len(), 64);
        (
            process,
            Self {
                client: Client::builder().no_proxy().timeout(WAIT).build().unwrap(),
                origin: origin.to_owned(),
                token: token.to_owned(),
            },
        )
    }

    fn request(&self, body: Value) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}/api", self.origin))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
    }

    async fn api(&self, body: Value) -> Value {
        let response = self
            .request(body)
            .header(header::ORIGIN, &self.origin)
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert!(status.is_success(), "HTTP {status}: {body}");
        serde_json::from_str(&body).unwrap()
    }

    async fn get(&self, path: &str) -> Response {
        self.client
            .get(format!("{}{path}", self.origin))
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn loopback_ui_rejects_spoofed_hosts_cross_origin_and_csrf() {
    let directory = tempfile::tempdir().unwrap();
    let (_process, browser) = Browser::start(&directory.path().join("state"));
    let page = browser.get("/").await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(page.headers()[header::REFERRER_POLICY], "no-referrer");
    let csp = page.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("connect-src 'self'"));
    let html = page.text().await.unwrap();
    assert!(html.contains("/app.js") && html.contains("/app.css"));
    assert!(!html.contains(&browser.token));
    assert_eq!(browser.get("/app.js").await.status(), StatusCode::OK);

    let wrong_host = browser
        .client
        .get(&browser.origin)
        .header(header::HOST, "rebound.example")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), StatusCode::FORBIDDEN);

    let create = json!({ "action": "create", "peers": [] });
    for (origin, token, expected) in [
        (None, Some(browser.token.as_str()), StatusCode::FORBIDDEN),
        (
            Some("https://example.test"),
            Some(browser.token.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (
            Some("null"),
            Some(browser.token.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(browser.origin.as_str()),
            Some("wrong"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some(browser.origin.as_str()),
            None,
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let mut request = browser.request(create.clone());
        if let Some(value) = origin {
            request = request.header(header::ORIGIN, value);
        }
        if let Some(value) = token {
            request = request.bearer_auth(value);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), expected);
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }
    let duplicate_origin = browser
        .request(create.clone())
        .header(header::ORIGIN, &browser.origin)
        .header(header::ORIGIN, "https://example.test")
        .bearer_auth(&browser.token)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate_origin.status(), StatusCode::FORBIDDEN);

    let preflight = browser
        .client
        .request(reqwest::Method::OPTIONS, format!("{}/api", browser.origin))
        .header(header::ORIGIN, "https://example.test")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .send()
        .await
        .unwrap();
    assert!(preflight.status().is_client_error());
    assert!(
        !preflight
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );

    assert_eq!(
        browser.api(json!({"action": "overview"})).await["channels"],
        json!([])
    );
    let channel = browser.api(create).await;
    assert_eq!(
        browser.api(json!({"action": "overview"})).await["channels"],
        json!([channel])
    );
}

#[tokio::test]
async fn paired_web_sessions_send_search_inspect_and_wake_through_two_nodes() {
    let directory = tempfile::tempdir().unwrap();
    let alice_state = directory.path().join("alice");
    let bob_state = directory.path().join("bob");
    let (_alice_web, alice) = Browser::start(&alice_state);
    let (_bob_web, bob) = Browser::start(&bob_state);
    let alice_info = alice.api(json!({"action": "overview"})).await;
    let bob_info = bob.api(json!({"action": "overview"})).await;
    for (session, info) in [(&alice, &bob_info), (&bob, &alice_info)] {
        session
            .api(json!({
                "action": "pair", "fingerprint": info["local"]["fingerprint"],
                "certificate": info["local"]["certificate"],
            }))
            .await;
    }
    let alice_id = &alice_info["local"]["id"];
    let bob_id = &bob_info["local"]["id"];
    let created = alice
        .api(json!({"action": "create", "peers": [bob_id]}))
        .await;
    let channel = &created["id"];
    let joined = bob
        .api(json!({"action": "join", "manifest": created["manifest"]}))
        .await;
    assert_eq!(&joined["id"], channel);

    let (_alice_node, _) = start(&alice_state, &["mesh", "run"], "Ready ");
    let (_bob_node, lines) = start(&bob_state, &["mesh", "run"], "Ready ");
    let route = lines
        .iter()
        .find_map(|line| line.strip_prefix("Listening "))
        .unwrap();
    let grant = bob
        .api(json!({
            "action": "grant", "channel": channel, "peer": alice_id, "generation": 1,
        }))
        .await;

    let text = "Read-only review <script>literal</script>";
    let sent = alice
        .api(json!({
            "action": "send", "channel": channel, "peer": bob_id, "route": route, "text": text,
        }))
        .await;
    let wake = alice
        .api(json!({
            "action": "wake", "channel": channel, "peer": bob_id, "route": route,
            "text": "Review this plan", "lifetime": 120,
        }))
        .await;
    tokio::time::timeout(WAIT, async {
        loop {
            let chat = alice
                .api(json!({
                    "action": "delivery", "channel": channel, "message": sent["message"],
                }))
                .await;
            let wake = alice
                .api(json!({
                    "action": "delivery", "channel": channel, "message": wake["message"],
                }))
                .await;
            if chat["recipients"][0]["acknowledged"] == true
                && wake["recipients"][0]["acknowledged"] == true
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Both envelopes should be acknowledged");

    let conversation = bob
        .api(json!({"action": "conversation", "channel": channel}))
        .await;
    assert_eq!(conversation["messages"][0]["text"], text);
    assert_eq!(conversation["messages"][0]["sender"], *alice_id);
    assert_eq!(conversation["work"][0]["message"], wake["message"]);
    assert_eq!(conversation["work"][0]["target"], grant["target"]);
    assert_eq!(conversation["work"][0]["state"], "pending");
    let missing = bob
        .request(json!({
            "action": "pause", "channel": channel, "root": "00".repeat(32),
        }))
        .header(header::ORIGIN, &bob.origin)
        .bearer_auth(&bob.token)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let search = bob
        .api(json!({"action": "search", "channel": channel, "query": "literal"}))
        .await;
    assert_eq!(search["matches"], json!([text]));
}
