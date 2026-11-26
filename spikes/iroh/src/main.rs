use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayUrl, SecretKey,
    endpoint::{Connection, RelayMode, presets},
};
use tokio::time::timeout;

const ALPN: &[u8] = b"howl/transport-spike/1";
const PROBE: &[u8] = b"howl transport probe";
const DEADLINE: Duration = Duration::from_secs(45);

const USAGE: &str = "Usage:
  howl-iroh-spike keygen KEY
  howl-iroh-spike id KEY
  howl-iroh-spike listen KEY MODE PEER [BIND_ADDR]
  howl-iroh-spike dial KEY MODE PEER [PEER_ADDR]

MODE is direct, auto=RELAY_URL, or relay=RELAY_URL.
Direct dial requires PEER_ADDR. Auto dial optionally takes PEER_ADDR.
BIND_ADDR and PEER_ADDR are IP:port addresses.";

enum Mode {
    Direct,
    Auto(RelayUrl),
    Relay(RelayUrl),
}

impl Mode {
    fn parse(value: &str) -> Result<Self> {
        match value.split_once('=') {
            None if value == "direct" => Ok(Self::Direct),
            Some(("auto", url)) => Ok(Self::Auto(url.parse().context("invalid relay URL")?)),
            Some(("relay", url)) => Ok(Self::Relay(url.parse().context("invalid relay URL")?)),
            _ => anyhow::bail!("{USAGE}"),
        }
    }

    fn relay_url(&self) -> Option<&RelayUrl> {
        match self {
            Self::Direct => None,
            Self::Auto(url) | Self::Relay(url) => Some(url),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--help" => println!("{USAGE}"),
        [command, key] if command == "keygen" => {
            println!("{}", create_key(Path::new(key))?.public());
        }
        [command, key] if command == "id" => {
            println!("{}", read_key(Path::new(key))?.public());
        }
        [command, key, mode, peer, rest @ ..]
            if matches!(command.as_str(), "listen" | "dial") && rest.len() <= 1 =>
        {
            let key = read_key(Path::new(key))?;
            let mode = Mode::parse(mode)?;
            let peer = peer.parse().context("invalid peer endpoint ID")?;
            let addr = rest.first().map(|value| value.parse()).transpose()?;
            let listener = command == "listen";
            let endpoint = bind(key, &mode, if listener { addr } else { None }).await?;
            let result = timeout(DEADLINE, async {
                if mode.relay_url().is_some() {
                    endpoint.online().await;
                }
                if listener {
                    listen(&endpoint, peer).await
                } else {
                    dial(&endpoint, &mode, peer, addr).await
                }
            })
            .await
            .context("transport probe deadline exceeded");
            endpoint.close().await;
            result??;
        }
        _ => anyhow::bail!("{USAGE}"),
    }
    Ok(())
}

fn create_key(path: &Path) -> Result<SecretKey> {
    let key = SecretKey::generate();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create endpoint key at {}", path.display()))?;
    file.write_all(&key.to_bytes())?;
    file.sync_all()?;
    Ok(key)
}

fn read_key(path: &Path) -> Result<SecretKey> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open endpoint key at {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() == 32,
        "endpoint key must be a private regular file containing 32 bytes"
    );
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    ensure!(file.read(&mut [0u8; 1])? == 0, "endpoint key changed size");
    Ok(SecretKey::from_bytes(&bytes))
}

async fn bind(key: SecretKey, mode: &Mode, addr: Option<SocketAddr>) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()]);
    match mode {
        Mode::Direct => {}
        Mode::Auto(url) => builder = builder.relay_mode(RelayMode::custom([url.clone()])),
        Mode::Relay(url) => {
            ensure!(addr.is_none(), "relay mode cannot bind a direct address");
            let relay = RelayConfig::new(url.clone(), None);
            builder = builder
                .relay_mode(RelayMode::Custom([relay].into_iter().collect()))
                .clear_ip_transports();
        }
    }
    if let Some(addr) = addr {
        builder = builder.clear_ip_transports().bind_addr(addr)?;
    }
    Ok(builder.bind().await?)
}

async fn listen(endpoint: &Endpoint, peer: EndpointId) -> Result<()> {
    println!(
        "listening id={} alpn={}",
        endpoint.id(),
        String::from_utf8_lossy(ALPN)
    );
    for addr in endpoint.bound_sockets() {
        println!("udp={addr}");
    }
    for url in endpoint.addr().relay_urls() {
        println!("relay={url}");
    }
    let connection = loop {
        let incoming = endpoint.accept().await.context("endpoint closed")?;
        let connection = match incoming.await {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("handshake rejected: {error}");
                continue;
            }
        };
        if connection.remote_id() == peer {
            break connection;
        }
        connection.close(1u32.into(), b"unexpected peer");
    };
    let (mut send, mut recv) = connection.accept_bi().await?;
    ensure!(
        recv.read_to_end(PROBE.len()).await? == PROBE,
        "unexpected probe"
    );
    send.write_all(PROBE).await?;
    send.finish()?;
    print_paths(&connection, "echo-sent");
    connection.closed().await;
    Ok(())
}

async fn dial(
    endpoint: &Endpoint,
    mode: &Mode,
    peer: EndpointId,
    addr: Option<SocketAddr>,
) -> Result<()> {
    ensure!(
        !matches!(mode, Mode::Direct) || addr.is_some(),
        "direct mode requires a peer address"
    );
    ensure!(
        !matches!(mode, Mode::Relay(_)) || addr.is_none(),
        "relay mode cannot dial a direct address"
    );
    let mut target = EndpointAddr::new(peer);
    if let Some(url) = mode.relay_url() {
        target = target.with_relay_url(url.clone());
    }
    if let Some(addr) = addr {
        target = target.with_ip_addr(addr);
    }
    let connection = endpoint.connect(target, ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(PROBE).await?;
    send.finish()?;
    ensure!(
        recv.read_to_end(PROBE.len()).await? == PROBE,
        "unexpected echo"
    );
    print_paths(&connection, "echo-confirmed");
    connection.close(0u32.into(), b"probe complete");
    Ok(())
}

fn print_paths(connection: &Connection, outcome: &str) {
    let paths = connection.paths();
    println!(
        "{outcome} peer={} alpn={} direct={} relay={} selected={}",
        connection.remote_id(),
        String::from_utf8_lossy(connection.alpn()),
        paths.iter().any(|path| path.is_ip()),
        paths.iter().any(|path| path.is_relay()),
        paths
            .iter()
            .find(|path| path.is_selected())
            .map_or("none", |path| if path.is_ip() { "direct" } else { "relay" })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_another_alpn() -> Result<()> {
        let server = bind(
            SecretKey::generate(),
            &Mode::Direct,
            Some("127.0.0.1:0".parse()?),
        )
        .await?;
        let target = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
        let client = bind(SecretKey::generate(), &Mode::Direct, None).await?;
        let accepting = tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await;
            }
            server.close().await;
        });
        let result = timeout(
            Duration::from_secs(5),
            client.connect(target, b"howl/transport-spike/wrong-version"),
        )
        .await;
        client.close().await;
        accepting.abort();
        assert!(result?.is_err());
        Ok(())
    }
}
