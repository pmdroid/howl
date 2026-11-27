use std::{io, path::Path, process::Stdio, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::timeout,
};
use zeroize::Zeroizing;

use super::{Error, Result};

pub(super) struct RepositoryHttp {
    url: String,
    token: Zeroizing<String>,
    _process: Child,
}

impl RepositoryHttp {
    pub(super) async fn start(node: &Path, socket: &Path, editable: bool) -> Result<Self> {
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let token = Zeroizing::new(hex::encode(random));
        let mut process = Command::new(node)
            .arg("-e")
            .arg(include_str!("../host_agents/repository-http.cjs"))
            .arg(socket)
            .arg(if editable { "edit" } else { "read" })
            .env_clear()
            .env("HOWL_REPOSITORY_MCP_TOKEN", &*token)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let stdout = process.stdout.take().ok_or(Error::HostAgent)?;
        let mut line = String::new();
        timeout(
            Duration::from_secs(5),
            BufReader::new(stdout).read_line(&mut line),
        )
        .await
        .map_err(|_| Error::TimedOut)??;
        let port: u16 = line.trim().parse().map_err(|_| Error::HostAgent)?;
        if port == 0 {
            return Err(Error::HostAgent);
        }
        Ok(Self {
            url: format!("http://127.0.0.1:{port}/mcp"),
            token,
            _process: process,
        })
    }

    pub(super) fn url(&self) -> &str {
        &self.url
    }

    pub(super) fn token(&self) -> &str {
        &self.token
    }
}
