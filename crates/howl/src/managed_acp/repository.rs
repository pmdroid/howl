use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use agent_client_protocol::v1::schema::{McpServer, McpServerStdio};
use tokio::{
    io::{AsyncWriteExt, copy},
    net::UnixListener,
    process::Command,
    task::JoinHandle,
    time::timeout,
};

use crate::observer::ObserverProcess;

use super::{Error, Result};

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
    pub(super) fn start(observer: &ObserverProcess, editable: bool) -> Result<Self> {
        let directory = tempfile::Builder::new().prefix("howl-r-").tempdir()?;
        let listener = UnixListener::bind(directory.path().join("tools.sock"))?;
        let command = observer.broker_command(
            Path::new("/usr/local/bin/node"),
            &[
                "-e",
                include_str!("../repository_tools.cjs"),
                if editable { "edit" } else { "read" },
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

impl Drop for RepositoryEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}
