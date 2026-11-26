mod mcp;

use agent_client_protocol::{
    Agent, ByteStreams, Client,
    schema::ProtocolVersion,
    v1::{
        ConnectionTo, SentRequest,
        schema::{
            AuthMethod, AuthenticateRequest, CancelNotification, CloseSessionRequest,
            InitializeRequest, LoadSessionRequest, McpServer, McpServerStdio, NewSessionRequest,
            PermissionOptionKind, PromptRequest, RequestPermissionOutcome,
            RequestPermissionRequest, RequestPermissionResponse, ResumeSessionRequest,
            SelectedPermissionOutcome, SessionNotification, SessionUpdate, StopReason,
        },
    },
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{
    env,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::tempdir;
use tokio::{
    process::Command,
    time::{sleep, timeout},
};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

struct Probe {
    cwd: PathBuf,
    marker: PathBuf,
    mcp: McpServer,
    exercise: bool,
    authenticate: Option<String>,
    chunks: Arc<AtomicUsize>,
    decisions: Arc<AtomicUsize>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if let [mode, marker] = args.as_slice()
        && mode == "mcp"
    {
        return mcp::serve(marker.into()).await;
    }

    let separator = args.iter().position(|arg| arg == "--").context(USAGE)?;
    let mut flags = args[..separator].iter();
    let mut exercise = false;
    let mut authenticate = None;
    while let Some(flag) = flags.next() {
        match flag.as_str() {
            "--exercise" => exercise = true,
            "--authenticate" => authenticate = Some(flags.next().context(USAGE)?.clone()),
            _ => anyhow::bail!(USAGE),
        }
    }
    let (program, arguments) = args[separator + 1..].split_first().context(USAGE)?;

    let workspace = tempdir()?;
    let cwd = workspace.path().canonicalize()?;
    let marker = cwd.join("mcp-events");
    let mcp = McpServer::Stdio(
        McpServerStdio::new("howl_probe", env::current_exe()?).args(vec![
            "mcp".into(),
            marker.to_str().context("UTF-8 marker path")?.into(),
        ]),
    );
    let chunks = Arc::new(AtomicUsize::new(0));
    let decisions = Arc::new(AtomicUsize::new(0));
    let probe = Probe {
        cwd,
        marker,
        mcp,
        exercise,
        authenticate,
        chunks: chunks.clone(),
        decisions: decisions.clone(),
    };
    let mut child = Command::new(program)
        .args(arguments)
        .current_dir(&probe.cwd)
        .env("NO_BROWSER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("launch ACP agent")?;
    let transport = ByteStreams::new(
        child.stdin.take().context("agent stdin")?.compat_write(),
        child.stdout.take().context("agent stdout")?.compat(),
    );

    let run = Client
        .v1()
        .on_receive_notification(
            async move |notification: SessionNotification, _| {
                if matches!(notification.update, SessionUpdate::AgentMessageChunk(_)) {
                    chunks.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .on_receive_request(
            async move |request: RequestPermissionRequest, responder, _| {
                decisions.fetch_add(1, Ordering::Relaxed);
                let decision = request
                    .options
                    .iter()
                    .find(|option| option.kind == PermissionOptionKind::RejectOnce)
                    .map(|option| {
                        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                            option.option_id.clone(),
                        ))
                    })
                    .unwrap_or(RequestPermissionOutcome::Cancelled);
                event("permission", json!({
                    "offered": request.options.iter().map(|option| &option.kind).collect::<Vec<_>>(),
                    "decision": if matches!(decision, RequestPermissionOutcome::Selected(_)) {
                        "reject_once"
                    } else {
                        "cancelled"
                    },
                }));
                responder.respond(RequestPermissionResponse::new(decision))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .connect_with(transport, async move |connection| {
            probe.run(connection).await;
            Ok(())
        });

    timeout(Duration::from_secs(190), run)
        .await
        .context("ACP run timed out")?
        .map_err(|error| anyhow::anyhow!("ACP connection failed (code {})", error.code.value()))?;
    Ok(())
}

const USAGE: &str =
    "usage: howl-harness-spike [--exercise] [--authenticate METHOD] -- AGENT [ARG ...]";

impl Probe {
    async fn run(self, connection: ConnectionTo<Agent>) {
        let Some(init) = request(
            "initialize",
            connection.send_request(InitializeRequest::new(ProtocolVersion::V1)),
        )
        .await
        else {
            return;
        };
        let capabilities = init.agent_capabilities;
        let supports_v1 = init.protocol_version == ProtocolVersion::V1;
        event(
            "capabilities",
            json!({
                "acp_v1": supports_v1,
                "agent": init.agent_info,
                "authentication": init.auth_methods.iter().map(|method| method.id()).collect::<Vec<_>>(),
                "load": capabilities.load_session,
                "resume": capabilities.session_capabilities.resume.is_some(),
                "close": capabilities.session_capabilities.close.is_some(),
            }),
        );
        if !supports_v1 {
            return;
        }

        if let Some(method_id) = self.authenticate.as_deref() {
            if !init.auth_methods.iter().any(|method| {
                matches!(method, AuthMethod::Agent(_)) && method.id().0.as_ref() == method_id
            }) {
                event("authenticate", json!({"status":"unavailable"}));
                return;
            }
            if request(
                "authenticate",
                connection.send_request(AuthenticateRequest::new(method_id.to_owned())),
            )
            .await
            .is_none()
            {
                return;
            }
        }

        let Some(session) = request(
            "session/new",
            connection.send_request(
                NewSessionRequest::new(&self.cwd).mcp_servers(vec![self.mcp.clone()]),
            ),
        )
        .await
        else {
            return;
        };
        let id = session.session_id;
        if self.exercise {
            let prompt = PromptRequest::new(id.clone(), vec![
                "Call the MCP tool named howl_probe on the howl_probe MCP server exactly once and report its result. Its fully qualified name may be mcp__howl_probe__howl_probe. Use no other tools."
                    .into(),
            ]);
            if let Some(response) = request("session/prompt", connection.send_request(prompt)).await
            {
                event(
                    "prompt_result",
                    json!({
                        "stop_reason": response.stop_reason,
                        "message_chunks": self.chunks.load(Ordering::Relaxed),
                    }),
                );
            }

            let prompt = PromptRequest::new(
                id.clone(),
                vec![
                "Count from one to one hundred, spelling out each number in sequence. Use no tools."
                    .into(),
            ],
            );
            let turn = connection.send_request(prompt).block_task();
            tokio::pin!(turn);
            tokio::select! {
                result = &mut turn => {
                    event("session/cancel", json!({"status":"prompt_finished_before_cancel"}));
                    if let Err(error) = result {
                        event("cancel_prompt", json!({"status":"error","code":error.code.value()}));
                    }
                }
                _ = sleep(Duration::from_millis(250)) => {
                    let sent = connection.send_notification(CancelNotification::new(id.clone()));
                    event("session/cancel", json!({"status":if sent.is_ok() {"sent"} else {"error"}}));
                    match timeout(Duration::from_secs(25), turn).await {
                        Ok(Ok(response)) => event("cancel_prompt", json!({
                            "status": if response.stop_reason == StopReason::Cancelled {"cancelled"} else {"finished"},
                            "stop_reason":response.stop_reason,
                        })),
                        Ok(Err(error)) => event("cancel_prompt", json!({"status":"error","code":error.code.value()})),
                        Err(_) => event("cancel_prompt", json!({"status":"timed_out"})),
                    }
                }
            }
        }
        record_mcp_events(&self.marker);
        event(
            "permissions",
            json!({"requests": self.decisions.load(Ordering::Relaxed)}),
        );

        if capabilities.load_session {
            request(
                "session/load",
                connection.send_request(
                    LoadSessionRequest::new(id.clone(), &self.cwd)
                        .mcp_servers(vec![self.mcp.clone()]),
                ),
            )
            .await;
        }
        if capabilities.session_capabilities.resume.is_some() {
            request(
                "session/resume",
                connection.send_request(
                    ResumeSessionRequest::new(id.clone(), &self.cwd).mcp_servers(vec![self.mcp]),
                ),
            )
            .await;
        }
        if capabilities.session_capabilities.close.is_some() {
            request(
                "session/close",
                connection.send_request(CloseSessionRequest::new(id)),
            )
            .await;
        }
    }
}

async fn request<T: Send + 'static>(stage: &str, request: SentRequest<T>) -> Option<T> {
    match timeout(Duration::from_secs(25), request.block_task()).await {
        Ok(Ok(response)) => {
            event(stage, json!({"status":"ok"}));
            Some(response)
        }
        Ok(Err(error)) => {
            event(stage, json!({"status":"error","code":error.code.value()}));
            None
        }
        Err(_) => {
            event(stage, json!({"status":"timed_out"}));
            None
        }
    }
}

fn record_mcp_events(path: &Path) {
    let events = std::fs::read_to_string(path).unwrap_or_default();
    event(
        "mcp",
        json!({
            "starts": events.lines().filter(|line| *line == "start").count(),
        "initialized": events.lines().filter(|line| *line == "initialized").count(),
            "calls": events.lines().filter(|line| *line == "call").count(),
        }),
    );
}

fn event(stage: &str, data: Value) {
    println!("{}", json!({"stage":stage,"data":data}));
}
