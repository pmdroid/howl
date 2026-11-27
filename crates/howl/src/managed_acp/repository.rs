use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use agent_client_protocol::v1::schema::{McpServer, McpServerStdio};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncWriteExt, copy},
    net::{UnixListener, UnixStream},
    process::{ChildStdin, ChildStdout, Command},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec};

use crate::{observer::ObserverProcess, ongoing::WorkTools};

use super::{Error, Phase, Result, SessionState};

const CONNECT_RELAY: &str = r#"
const socket = require("node:net").createConnection(process.argv[1]);
socket.on("error", () => { process.exitCode = 1; process.stdin.destroy(); });
socket.pipe(process.stdout);
process.stdin.pipe(socket);
"#;

pub(super) struct RepositoryEndpoint {
    directory: tempfile::TempDir,
    task: JoinHandle<()>,
}

impl RepositoryEndpoint {
    pub(super) fn start(
        observer: &ObserverProcess,
        editable: bool,
        work: Option<(Arc<WorkTools>, watch::Receiver<SessionState>)>,
    ) -> Result<Self> {
        let directory = tempfile::Builder::new().prefix("howl-r-").tempdir()?;
        let listener = UnixListener::bind(directory.path().join("tools.sock"))?;
        let command = observer.broker_command(
            Path::new("/usr/local/bin/node"),
            &[
                "-e",
                include_str!("../repository_tools.cjs"),
                if editable { "edit" } else { "read" },
                if work.is_some() { "work" } else { "repository" },
            ],
        )?;
        let mut command = Command::from(command);
        command.stderr(Stdio::null()).kill_on_drop(true);
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let Ok(mut child) = command.spawn() else {
                    continue;
                };
                let Some(mut input) = child.stdin.take() else {
                    continue;
                };
                let Some(mut output) = child.stdout.take() else {
                    continue;
                };
                if let Some((tools, phase)) = &work {
                    let _ = timeout(
                        Duration::from_secs(3600),
                        bridge(socket, input, output, tools, phase),
                    )
                    .await;
                } else {
                    let (mut reader, mut writer) = socket.into_split();
                    let _ = timeout(Duration::from_secs(3600), async {
                        tokio::try_join!(
                            async {
                                copy(&mut reader, &mut input).await?;
                                input.shutdown().await
                            },
                            async {
                                copy(&mut output, &mut writer).await?;
                                writer.shutdown().await
                            }
                        )
                    })
                    .await;
                }
                let _ = child.kill().await;
            }
        });
        Ok(Self { directory, task })
    }

    pub(super) fn socket(&self) -> PathBuf {
        self.directory.path().join("tools.sock")
    }

    pub(super) fn mcp_server(&self, node: &Path) -> Result<McpServer> {
        let socket = self.socket().into_os_string().into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository IPC path is not UTF-8",
            )
        })?;
        if !node.is_absolute() {
            return Err(Error::State);
        }
        Ok(McpServer::Stdio(
            McpServerStdio::new("howl_repository", node).args(vec![
                "-e".into(),
                CONNECT_RELAY.into(),
                socket,
            ]),
        ))
    }
}

async fn bridge(
    socket: UnixStream,
    input: ChildStdin,
    output: ChildStdout,
    tools: &WorkTools,
    phase: &watch::Receiver<SessionState>,
) -> io::Result<()> {
    let (read, write) = socket.into_split();
    let mut requests = FramedRead::new(read, LinesCodec::new_with_max_length(16 * 1024));
    let mut replies = FramedRead::new(output, LinesCodec::new_with_max_length(400_000));
    let mut to_repo = FramedWrite::new(input, LinesCodec::new());
    let mut to_agent = FramedWrite::new(write, LinesCodec::new());
    loop {
        tokio::select! {
            message = requests.next() => {
                let Some(line) = message else { return Ok(()); };
                let line = line.map_err(io::Error::other)?;
                let parsed = serde_json::from_str::<Value>(&line).ok();
                if let Some(request) = parsed.filter(|request| {
                    request["jsonrpc"] == "2.0" && request["method"] == "tools/call"
                        && matches!(request["params"]["name"].as_str(), Some("start_work" | "send_peer")) && !request["id"].is_null()
                }) {
                    let active = phase.borrow().phase == Phase::Active;
                    let answer = if active {
                        tools.call(request["params"]["name"].as_str().unwrap_or_default(), request["params"]["arguments"].clone()).await.ok()
                    } else { None };
                    let (text, error) = answer.map_or_else(|| ("Request is unavailable under this conversation policy.".into(), true), |text| (text, false));
                    let response = json!({ "jsonrpc": "2.0", "id": request["id"], "result": {
                        "content": [{ "type": "text", "text": text }], "isError": error
                    }});
                    to_agent.send(response.to_string()).await.map_err(io::Error::other)?;
                } else {
                    to_repo.send(line).await.map_err(io::Error::other)?;
                }
            }
            reply = replies.next() => {
                let Some(line) = reply else { return Ok(()); };
                to_agent.send(line.map_err(io::Error::other)?).await.map_err(io::Error::other)?;
            }
        }
    }
}

impl Drop for RepositoryEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}
