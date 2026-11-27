use std::{env, io, path::Path, process::Child, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use reqwest::{Client, Method, redirect::Policy};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    process::{ChildStdin, ChildStdout},
    sync::mpsc,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::codec::{FramedRead, LinesCodec};
use zeroize::Zeroizing;

use crate::observer::ObserverProcess;

const REQUEST_BYTES: usize = 2 * 1024 * 1024;
const WIRE_BYTES: usize = 6 * 1024 * 1024;
const RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const REQUESTS: usize = 64;
const OUTPUT_TOKENS: u64 = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    OpenAi,
    XAi,
    ChatGptPlan,
    OpenCodeGo,
}

impl Provider {
    fn origin(self) -> &'static str {
        match self {
            Self::OpenAi | Self::ChatGptPlan => "https://api.openai.com",
            Self::XAi => "https://api.x.ai",
            Self::OpenCodeGo => "https://opencode.ai",
        }
    }

    fn base_path(self) -> &'static str {
        match self {
            Self::OpenCodeGo => "/inference/go/openai",
            _ => "",
        }
    }

    fn allows(self, method: &str, path: &str) -> bool {
        matches!(
            (self, method, path),
            (
                Self::OpenAi | Self::ChatGptPlan | Self::XAi,
                "GET",
                "/v1/models"
            ) | (Self::OpenAi | Self::ChatGptPlan, "POST", "/v1/responses")
                | (Self::XAi | Self::OpenCodeGo, "POST", "/v1/chat/completions")
        )
    }

    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::OpenAi => 1,
            Self::XAi => 2,
            Self::ChatGptPlan => 3,
            Self::OpenCodeGo => 4,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("set {0} in the host environment to enable this provider")]
    MissingKey(&'static str),
    #[error("sign in to ChatGPT from the host to use the ChatGPT plan")]
    MissingPlan,
    #[error("invalid host provider credential")]
    InvalidKey,
    #[error("invalid provider model")]
    Model,
    #[error("could not initialize the HTTPS provider client")]
    Client,
    #[error("the sandbox provider bridge failed to start")]
    Bridge,
    #[error("provider bridge I/O failed")]
    Io(#[from] io::Error),
}

pub(crate) struct Broker {
    provider: Provider,
    client: Client,
    key: Zeroizing<String>,
    origin: String,
    model: String,
    session: Option<String>,
}

impl Broker {
    pub(crate) fn from_environment(provider: Provider, model: &str) -> Result<Self, Error> {
        let keys: &[&str] = match provider {
            Provider::OpenAi => &["HOWL_OPENAI_API_KEY", "OPENAI_API_KEY"],
            Provider::XAi => &["HOWL_XAI_API_KEY", "XAI_API_KEY"],
            Provider::OpenCodeGo => &["HOWL_OPENCODE_GO_API_KEY"],
            Provider::ChatGptPlan => return Err(Error::MissingPlan),
        };
        let key = keys
            .iter()
            .find_map(env::var_os)
            .ok_or(Error::MissingKey(keys[0]))?;
        let key = Zeroizing::new(key.into_string().map_err(|_| Error::InvalidKey)?);
        Self::new(provider, model, key, 4096)
    }

    pub(crate) fn from_chatgpt_plan(model: &str, token: Zeroizing<String>) -> Result<Self, Error> {
        Self::new(Provider::ChatGptPlan, model, token, 16 * 1024)
    }

    fn new(
        provider: Provider,
        model: &str,
        key: Zeroizing<String>,
        key_limit: usize,
    ) -> Result<Self, Error> {
        if model.is_empty()
            || model.len() > 128
            || !model.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::Model);
        }
        if key.is_empty()
            || key.len() > key_limit
            || !key.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::InvalidKey);
        }
        let client = Self::http_client(provider, true)?;
        Ok(Broker {
            provider,
            client,
            key,
            origin: provider.origin().to_owned(),
            model: model.to_owned(),
            session: None,
        })
    }

    fn http_client(provider: Provider, https_only: bool) -> Result<Client, Error> {
        let mut client = Client::builder()
            .https_only(https_only)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120));
        if matches!(provider, Provider::ChatGptPlan | Provider::OpenCodeGo) {
            client = client.user_agent(concat!("Howl/", env!("CARGO_PKG_VERSION")));
        }
        client.build().map_err(|_| Error::Client)
    }

    #[cfg(test)]
    pub(crate) fn fixture(provider: Provider, model: &str, port: u16) -> Self {
        Self {
            provider,
            client: Self::http_client(provider, false).unwrap(),
            key: Zeroizing::new("fixture-host-key".to_owned()),
            origin: format!("http://127.0.0.1:{port}"),
            model: model.to_owned(),
            session: None,
        }
    }

    pub(crate) async fn attach(
        mut self,
        observer: &ObserverProcess,
        session: &str,
    ) -> Result<BrokerTask, Error> {
        if self.provider == Provider::OpenCodeGo {
            self.session = Some(session.to_owned());
        }
        timeout(Duration::from_secs(10), self.attach_when_running(observer))
            .await
            .map_err(|_| Error::Bridge)?
    }

    async fn attach_when_running(self, observer: &ObserverProcess) -> Result<BrokerTask, Error> {
        loop {
            let child = observer
                .start_broker(
                    Path::new("/usr/local/bin/node"),
                    &["-e", include_str!("provider_bridge.cjs")],
                )
                .map_err(|_| Error::Bridge)?;
            let mut task = BrokerTask { child, job: None };
            let stdin = ChildStdin::from_std(task.child.stdin.take().ok_or(Error::Bridge)?)?;
            let stdout = ChildStdout::from_std(task.child.stdout.take().ok_or(Error::Bridge)?)?;
            let mut reader = FramedRead::new(stdout, LinesCodec::new_with_max_length(WIRE_BYTES));
            match reader.next().await {
                Some(Ok(value)) if value == "ready" => {
                    task.job = Some(tokio::spawn(self.serve(reader, stdin)));
                    return Ok(task);
                }
                None => {
                    drop(task);
                    sleep(Duration::from_millis(100)).await;
                }
                _ => return Err(Error::Bridge),
            }
        }
    }

    async fn serve(
        self,
        requests: FramedRead<impl AsyncRead + Unpin, LinesCodec>,
        mut response: impl AsyncWrite + Unpin,
    ) -> io::Result<()> {
        let (frames, mut output) = mpsc::channel::<Vec<u8>>(2);
        tokio::try_join!(self.serve_requests(requests, frames), async {
            while let Some(frame) = output.recv().await {
                response.write_all(&frame).await?;
                response.flush().await?;
            }
            Ok(())
        })?;
        Ok(())
    }

    async fn serve_requests(
        self,
        mut requests: FramedRead<impl AsyncRead + Unpin, LinesCodec>,
        output: mpsc::Sender<Vec<u8>>,
    ) -> io::Result<()> {
        let mut remaining = REQUESTS;
        while let Some(frame) = receive(&mut requests).await? {
            let Frame::Request(request) = frame else {
                continue;
            };
            if remaining == 0 {
                return send_error(&output, 429, "provider request budget exhausted").await;
            }
            remaining -= 1;
            let id = request.id;
            let cancelled = tokio::select! {
                biased;
                result = self.exchange(request, &output) => {
                    result?;
                    false
                }
                result = wait_for_cancel(&mut requests, id) => {
                    if !result? {
                        return Ok(());
                    }
                    true
                }
            };
            if cancelled {
                send_frame(&output, &End { end: true }).await?;
            }
        }
        Ok(())
    }

    async fn exchange(&self, request: Request, response: &mpsc::Sender<Vec<u8>>) -> io::Result<()> {
        if !self.provider.allows(&request.method, &request.path)
            || request.body.len() > REQUEST_BYTES
        {
            return send_error(response, 403, "provider request denied").await;
        }
        let url = format!(
            "{}{}{}",
            self.origin,
            self.provider.base_path(),
            request.path
        );
        let upstream = match request.method.as_str() {
            "GET" if request.body.is_empty() => self.client.request(Method::GET, url),
            "POST" => {
                let Some(payload) = allowed_payload(&request.body, &self.model, self.provider)
                else {
                    return send_error(response, 403, "provider request denied").await;
                };
                self.client
                    .request(Method::POST, url)
                    .header("content-type", "application/json")
                    .body(payload)
            }
            _ => return send_error(response, 403, "provider request denied").await,
        }
        .bearer_auth(&*self.key);
        let upstream = match &self.session {
            Some(session) => upstream.header("x-opencode-session", session),
            None => upstream,
        };
        let Ok(upstream) = upstream.send().await else {
            return send_error(response, 502, "provider unavailable").await;
        };
        let status = upstream.status();
        if !status.is_success() {
            let status = if status.is_client_error() || status.is_server_error() {
                status.as_u16()
            } else {
                502
            };
            return send_error(response, status, "provider rejected the request").await;
        }
        let content_type = match upstream
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
        {
            Some(value) if value.split(';').next() == Some("text/event-stream") => {
                "text/event-stream"
            }
            _ => "application/json",
        };
        send_frame(
            response,
            &Reply {
                status: status.as_u16(),
                content_type,
            },
        )
        .await?;
        let mut total = 0;
        let mut body = upstream.bytes_stream();
        while let Some(chunk) = body.next().await {
            let bytes = chunk.map_err(|_| io::Error::other("provider stream interrupted"))?;
            total += bytes.len();
            if total > RESPONSE_BYTES {
                return Err(io::Error::other("provider response exceeds limit"));
            }
            for chunk in bytes.chunks(16 * 1024) {
                send_frame(
                    response,
                    &Chunk {
                        chunk: STANDARD.encode(chunk),
                    },
                )
                .await?;
            }
        }
        send_frame(response, &End { end: true }).await
    }
}

fn allowed_payload(body: &str, model: &str, provider: Provider) -> Option<String> {
    let Ok(serde_json::Value::Object(mut request)) = serde_json::from_str(body) else {
        return None;
    };
    request.remove("client_metadata");
    if request.get("model").and_then(serde_json::Value::as_str) != Some(model)
        || !request.keys().all(|key| allowed_field(provider, key))
        || request
            .get("store")
            .is_some_and(|value| value != false && !value.is_null())
        || ["input", "messages"]
            .iter()
            .any(|key| request.get(*key).is_some_and(has_remote_input))
        || request.get("tools").is_some_and(|tools| {
            !tools
                .as_array()
                .is_some_and(|tools| tools.iter().all(allowed_tool))
        })
    {
        return None;
    }
    request.remove("service_tier");
    let output_field = match provider {
        Provider::ChatGptPlan => {
            normalize_plan_payload(&mut request)?;
            return Some(serde_json::Value::Object(request).to_string());
        }
        Provider::OpenAi => {
            request.insert("store".to_owned(), false.into());
            "max_output_tokens"
        }
        Provider::XAi | Provider::OpenCodeGo => {
            request.insert("n".to_owned(), 1.into());
            if let Some(value) = request.remove("max_completion_tokens") {
                request.entry("max_tokens").or_insert(value);
            }
            "max_tokens"
        }
    };
    let output_tokens = request
        .get(output_field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(OUTPUT_TOKENS)
        .min(OUTPUT_TOKENS);
    request.insert(output_field.to_owned(), output_tokens.into());
    Some(serde_json::Value::Object(request).to_string())
}

fn allowed_field(provider: Provider, field: &str) -> bool {
    matches!(
        field,
        "model"
            | "stream"
            | "tools"
            | "tool_choice"
            | "parallel_tool_calls"
            | "temperature"
            | "top_p"
            | "service_tier"
    ) || match provider {
        Provider::OpenAi | Provider::ChatGptPlan => matches!(
            field,
            "input"
                | "instructions"
                | "store"
                | "reasoning"
                | "text"
                | "include"
                | "max_output_tokens"
                | "metadata"
                | "prompt_cache_key"
                | "prompt_cache_retention"
                | "safety_identifier"
                | "truncation"
                | "stream_options"
        ),
        Provider::XAi | Provider::OpenCodeGo => matches!(
            field,
            "messages"
                | "n"
                | "max_tokens"
                | "max_completion_tokens"
                | "reasoning_effort"
                | "response_format"
                | "stream_options"
                | "stop"
                | "presence_penalty"
                | "frequency_penalty"
                | "seed"
                | "logprobs"
                | "top_logprobs"
                | "user"
        ),
    }
}

fn normalize_plan_payload(request: &mut serde_json::Map<String, serde_json::Value>) -> Option<()> {
    use serde_json::{Value, json};

    for field in [
        "max_output_tokens",
        "metadata",
        "prompt_cache_retention",
        "safety_identifier",
        "temperature",
        "top_p",
        "truncation",
    ] {
        request.remove(field);
    }
    if request
        .get("tool_choice")
        .is_some_and(|choice| !allowed_plan_tool_choice(choice))
    {
        return None;
    }
    let tools = request.remove("tools");
    let input = request.get_mut("input")?;
    if let Value::String(text) = input {
        *input = json!([{ "role": "user", "content": std::mem::take(text) }]);
    }
    let items = input.as_array_mut()?;
    for item in items.iter_mut() {
        let fields = item.as_object_mut()?;
        match fields.get("type").and_then(Value::as_str) {
            None | Some("message") => match fields.get("role").and_then(Value::as_str)? {
                "developer" | "user" | "assistant" => {}
                "system" => {
                    fields.insert("role".to_owned(), "developer".into());
                }
                _ => return None,
            },
            Some("additional_tools") => {
                if fields.get("role").and_then(Value::as_str) != Some("developer")
                    || !fields
                        .get("tools")
                        .and_then(Value::as_array)
                        .is_some_and(|tools| tools.iter().all(allowed_tool))
                {
                    return None;
                }
            }
            Some(
                "reasoning"
                | "function_call"
                | "function_call_output"
                | "custom_tool_call"
                | "custom_tool_call_output",
            ) => {}
            _ => return None,
        }
    }
    if let Some(tools) = tools {
        let Value::Array(tools) = tools else {
            return None;
        };
        let (flat, namespaces): (Vec<_>, Vec<_>) = tools.into_iter().partition(is_local_tool);
        if !flat.is_empty() {
            items.insert(
                0,
                json!({"type": "additional_tools", "role": "developer", "tools": flat}),
            );
        }
        if !namespaces.is_empty() {
            request.insert("tools".to_owned(), Value::Array(namespaces));
        }
    }
    request.insert("store".to_owned(), false.into());
    request.insert("stream".to_owned(), true.into());
    Some(())
}

fn allowed_plan_tool_choice(choice: &serde_json::Value) -> bool {
    if let Some(mode) = choice.as_str() {
        return matches!(mode, "auto" | "none" | "required");
    }
    match choice.get("type").and_then(serde_json::Value::as_str) {
        Some("function" | "custom") => choice.get("name").is_some_and(serde_json::Value::is_string),
        Some("allowed_tools") => choice
            .get("tools")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|tools| tools.iter().all(is_local_tool)),
        _ => false,
    }
}

fn has_remote_input(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(has_remote_input),
        serde_json::Value::Object(fields) => {
            matches!(
                fields.get("type").and_then(serde_json::Value::as_str),
                Some(
                    "item_reference"
                        | "input_file"
                        | "input_image"
                        | "image_url"
                        | "input_audio"
                        | "file"
                )
            ) || ["file_id", "file_url", "image_url"]
                .iter()
                .any(|key| fields.contains_key(*key))
                || fields.values().any(has_remote_input)
        }
        _ => false,
    }
}

fn allowed_tool(tool: &serde_json::Value) -> bool {
    is_local_tool(tool)
        || (tool.get("type").and_then(serde_json::Value::as_str) == Some("namespace")
            && tool
                .get("tools")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|tools| tools.iter().all(is_local_tool)))
}

fn is_local_tool(tool: &serde_json::Value) -> bool {
    matches!(
        tool.get("type").and_then(serde_json::Value::as_str),
        Some("function" | "custom")
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    method: String,
    path: String,
    body: String,
}

#[derive(Serialize)]
struct Reply<'a> {
    status: u16,
    content_type: &'a str,
}

#[derive(Serialize)]
struct Chunk {
    chunk: String,
}

#[derive(Serialize)]
struct End {
    end: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancellation {
    cancel: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Frame {
    Request(Request),
    Cancellation(Cancellation),
}

async fn receive(
    reader: &mut FramedRead<impl AsyncRead + Unpin, LinesCodec>,
) -> io::Result<Option<Frame>> {
    reader
        .next()
        .await
        .map(|line| {
            let line = line.map_err(io::Error::other)?;
            serde_json::from_str(&line)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid provider frame"))
        })
        .transpose()
}

async fn wait_for_cancel(
    reader: &mut FramedRead<impl AsyncRead + Unpin, LinesCodec>,
    id: u64,
) -> io::Result<bool> {
    while let Some(frame) = receive(reader).await? {
        match frame {
            Frame::Cancellation(message) if message.cancel == id => return Ok(true),
            Frame::Cancellation(_) => {}
            Frame::Request(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "provider requests are serialized",
                ));
            }
        }
    }
    Ok(false)
}

async fn send_frame(output: &mpsc::Sender<Vec<u8>>, value: &impl Serialize) -> io::Result<()> {
    let frame = encode_frame(value)?;
    output
        .send(frame)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "provider bridge disconnected"))
}

fn encode_frame(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut frame = serde_json::to_vec(value)?;
    frame.push(b'\n');
    Ok(frame)
}

async fn send_error(output: &mpsc::Sender<Vec<u8>>, status: u16, message: &str) -> io::Result<()> {
    send_frame(
        output,
        &Reply {
            status,
            content_type: "application/json",
        },
    )
    .await?;
    let body = serde_json::json!({"error":{"message":message}}).to_string();
    send_frame(
        output,
        &Chunk {
            chunk: STANDARD.encode(body),
        },
    )
    .await?;
    send_frame(output, &End { end: true }).await
}

pub(crate) struct BrokerTask {
    child: Child,
    job: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for BrokerTask {
    fn drop(&mut self) {
        if let Some(job) = &self.job {
            job.abort();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use tokio::io::{AsyncBufReadExt, BufReader as AsyncBufReader, duplex, split};

    #[test]
    fn opencode_go_only_allows_subscription_chat_for_the_selected_model() {
        let provider = Provider::OpenCodeGo;
        assert_eq!(provider.origin(), "https://opencode.ai");
        assert_eq!(provider.base_path(), "/inference/go/openai");
        assert!(provider.allows("POST", "/v1/chat/completions"));
        assert!(!provider.allows("GET", "/v1/models"));
        assert!(!provider.allows("POST", "/v1/responses"));
        assert!(!provider.allows("POST", "/v1/chat/completions?extra=1"));
        assert!(allowed_payload(r#"{"model":"other"}"#, "selected", provider).is_none());
        assert!(
            allowed_payload(
                r#"{"model":"selected","tools":[{"type":"web_search"}]}"#,
                "selected",
                provider,
            )
            .is_none()
        );
        let allowed = allowed_payload(
            r#"{"model":"selected","max_tokens":100000,"n":3}"#,
            "selected",
            provider,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&allowed).unwrap(),
            serde_json::json!({"model":"selected","max_tokens":8192,"n":1})
        );
    }

    #[test]
    fn denies_unconfigured_models_and_provider_tools() {
        let allowed_payload = |body, model| super::allowed_payload(body, model, Provider::OpenAi);
        assert!(Provider::OpenAi.allows("POST", "/v1/responses"));
        assert!(!Provider::OpenAi.allows("POST", "/v1/chat/completions"));
        assert!(!Provider::XAi.allows("POST", "/v1/responses"));
        assert!(!Provider::XAi.allows("GET", "https://api.x.ai/v1/models"));
        assert!(!Provider::XAi.allows("GET", "/v1/models?extra=1"));
        assert!(
            super::allowed_payload(
                r#"{"model":"selected","search_parameters":{"mode":"on"}}"#,
                "selected",
                Provider::XAi
            )
            .is_none()
        );

        assert!(
            allowed_payload(
                r#"{"model":"selected","tools":[{"type":"function"}]}"#,
                "selected"
            )
            .is_some()
        );
        assert!(allowed_payload(r#"{"model":"selected","tools":[{"type":"namespace","tools":[{"type":"function"}]}]}"#, "selected").is_some());
        assert!(allowed_payload(r#"{"model":"selected","tools":[{"type":"namespace","tools":[{"type":"web_search"}]}]}"#, "selected").is_none());
        assert!(allowed_payload(r#"{"model":"other"}"#, "selected").is_none());
        assert!(
            allowed_payload(
                r#"{"model":"selected","tools":[{"type":"web_search"}]}"#,
                "selected"
            )
            .is_none()
        );
        assert!(
            allowed_payload(
                r#"{"model":"selected","previous_response_id":"other"}"#,
                "selected"
            )
            .is_none()
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &allowed_payload(
                    r#"{"model":"other","model":"selected","client_metadata":{"fixture":true}}"#,
                    "selected"
                )
                .unwrap()
            )
            .unwrap(),
            serde_json::json!({"max_output_tokens":8192,"model":"selected","store":false})
        );
    }

    #[test]
    fn codex_plan_preserves_local_tools_and_uses_stateless_streaming() {
        use serde_json::{Value, json};

        let request = json!({
            "model": "selected",
            "stream": false,
            "max_output_tokens": 30,
            "temperature": 1,
            "top_p": 1,
            "service_tier": "priority",
            "metadata": {"source": "fixture"},
            "safety_identifier": "fixture",
            "input": [
                {"type": "message", "role": "system", "content": "fixture"},
                {"role": "user", "content": "hello"},
                {"type": "function_call_output", "call_id": "fixture", "output": "done"}
            ],
            "tools": [
                {"type": "function", "name": "read"},
                {"type": "namespace", "name": "repo", "tools": [{"type": "custom", "name": "read"}]}
            ]
        });
        let outgoing = allowed_payload(&request.to_string(), "selected", Provider::ChatGptPlan);
        assert_eq!(
            serde_json::from_str::<Value>(&outgoing.unwrap()).unwrap(),
            json!({
                "model": "selected",
                "store": false,
                "stream": true,
                "input": [
                    {"type": "additional_tools", "role": "developer", "tools": [{"type": "function", "name": "read"}]},
                    {"type": "message", "role": "developer", "content": "fixture"},
                    {"role": "user", "content": "hello"},
                    {"type": "function_call_output", "call_id": "fixture", "output": "done"}
                ],
                "tools": [{"type": "namespace", "name": "repo", "tools": [{"type": "custom", "name": "read"}]}]
            })
        );
        let outgoing = allowed_payload(
            r#"{"model":"selected","input":"hello"}"#,
            "selected",
            Provider::ChatGptPlan,
        );
        assert_eq!(
            serde_json::from_str::<Value>(&outgoing.unwrap()).unwrap()["input"],
            json!([{"role": "user", "content": "hello"}])
        );
    }

    #[test]
    fn codex_plan_requires_explicit_host_oauth_and_denies_hosted_requests() {
        assert!(matches!(
            Broker::from_environment(Provider::ChatGptPlan, "selected"),
            Err(Error::MissingPlan),
        ));
        let broker =
            Broker::from_chatgpt_plan("selected", Zeroizing::new("a".repeat(16 * 1024))).unwrap();
        assert_eq!(broker.origin, "https://api.openai.com");
        assert!(broker.provider.allows("POST", "/v1/responses"));
        assert!(!broker.provider.allows("POST", "/v1/chat/completions"));
        assert!(matches!(
            Broker::from_chatgpt_plan("selected", Zeroizing::new("invalid\nvalue".into())),
            Err(Error::InvalidKey)
        ));
        for request in [
            r#"{"model":"other","input":"hello"}"#,
            r#"{"model":"selected","input":[],"store":true}"#,
            r#"{"model":"selected","input":[],"previous_response_id":"resp_other"}"#,
            r#"{"model":"selected","input":[{"type":"item_reference","id":"resp_other"}]}"#,
            r#"{"model":"selected","input":[],"tools":[{"type":"tool_search","execution":"client"}]}"#,
            r#"{"model":"selected","input":[],"tool_choice":{"type":"web_search"}}"#,
            r#"{"model":"selected","input":[{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","tools":[{"type":"web_search"}]}]}]}"#,
            r#"{"model":"selected","input":[{"type":"tool_search_output","tools":[{"type":"web_search"}]}]}"#,
        ] {
            assert!(
                allowed_payload(request, "selected", Provider::ChatGptPlan).is_none(),
                "{request}"
            );
        }
    }

    #[tokio::test]
    async fn streams_the_fixed_upstream_and_cancels_an_open_request() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", upstream.local_addr().unwrap());
        let (opened, opening) = tokio::sync::oneshot::channel();
        let upstream = std::thread::spawn(move || {
            let mut first = accept(&upstream);
            write!(
                first,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\n\r\ndata: first\n\n"
            )
            .unwrap();
            opened.send(()).unwrap();
            let mut remaining = [0];
            assert_eq!(first.read(&mut remaining).unwrap(), 0);
            let mut second = accept(&upstream);
            write!(
                second,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
        });
        let broker = Broker {
            provider: Provider::OpenAi,
            client: Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .build()
                .unwrap(),
            key: Zeroizing::new("fixture-host-key".to_owned()),
            origin,
            model: "selected".to_owned(),
            session: None,
        };
        let (guest, host) = duplex(32 * 1024);
        let (host_read, host_write) = split(host);
        let (guest_read, mut guest_write) = split(guest);
        let requests = FramedRead::new(host_read, LinesCodec::new_with_max_length(WIRE_BYTES));
        let mut replies = AsyncBufReader::new(guest_read).lines();
        let check = async move {
            let request = |id| {
                serde_json::json!({
                    "id": id,
                    "method": "POST",
                    "path": "/v1/responses",
                    "body": "{\"model\":\"selected\"}"
                })
            };
            guest_write
                .write_all(&encode_frame(&request(1)).unwrap())
                .await
                .unwrap();
            opening.await.unwrap();
            let head = replies.next_line().await.unwrap().unwrap();
            assert!(head.contains("text/event-stream"));
            let frame = replies.next_line().await.unwrap().unwrap();
            assert!(frame.contains(&STANDARD.encode("data: first\n\n")));
            guest_write
                .write_all(&encode_frame(&serde_json::json!({"cancel":1})).unwrap())
                .await
                .unwrap();
            assert_eq!(
                replies.next_line().await.unwrap().unwrap(),
                r#"{"end":true}"#
            );
            guest_write
                .write_all(&encode_frame(&request(2)).unwrap())
                .await
                .unwrap();
            assert!(replies.next_line().await.unwrap().unwrap().contains("502"));
            assert!(
                replies
                    .next_line()
                    .await
                    .unwrap()
                    .unwrap()
                    .contains("chunk")
            );
            assert_eq!(
                replies.next_line().await.unwrap().unwrap(),
                r#"{"end":true}"#
            );
            guest_write.shutdown().await.unwrap();
        };
        let (served, ()) = timeout(Duration::from_secs(10), async {
            tokio::join!(broker.serve(requests, host_write), check)
        })
        .await
        .unwrap();
        served.unwrap();
        upstream.join().unwrap();
    }

    fn accept(listener: &TcpListener) -> std::net::TcpStream {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "POST /v1/responses HTTP/1.1");
        let mut length = 0;
        let mut authenticated = false;
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("content-length: ") {
                length = value.trim().parse().unwrap();
            }
            authenticated |= line.trim_end() == "authorization: Bearer fixture-host-key";
        }
        assert!(authenticated);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"max_output_tokens":8192,"model":"selected","store":false})
        );
        reader.into_inner()
    }
}
