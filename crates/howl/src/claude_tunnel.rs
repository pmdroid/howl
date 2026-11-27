use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    path::Path,
    process::Child,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    process::{ChildStdin, ChildStdout},
    sync::mpsc,
    task::{AbortHandle, JoinHandle, JoinSet},
    time::{sleep, timeout},
};

use crate::observer::ObserverProcess;

pub(crate) const CLAUDE_PROXY: &str = "http://127.0.0.1:17862";
const CONNECTIONS: usize = 8;
const CONNECTION_BUDGET: u32 = 128;
const CHUNK: usize = 16 * 1024;
const BYTE_BUDGET: usize = 32 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_TIMEOUT: Duration = Duration::from_secs(300);
const OPEN: u8 = 1;
const DATA: u8 = 2;
const END: u8 = 3;
const CLOSE: u8 = 4;
const OPENED: u8 = 5;
const FAILED: u8 = 6;

pub(crate) struct ClaudeTunnel {
    child: Child,
    relay: Option<JoinHandle<io::Result<()>>>,
}

impl ClaudeTunnel {
    pub(crate) async fn attach(observer: &ObserverProcess) -> io::Result<Self> {
        timeout(HELLO_TIMEOUT, Self::start(observer))
            .await
            .map_err(|_| io::Error::other("Claude proxy did not start"))?
    }

    async fn start(observer: &ObserverProcess) -> io::Result<Self> {
        loop {
            let child = observer
                .start_broker(
                    Path::new("/usr/local/bin/node"),
                    &["-e", include_str!("claude_tunnel.cjs")],
                )
                .map_err(io::Error::other)?;
            let mut tunnel = Self { child, relay: None };
            let output = tunnel.child.stdout.take().ok_or_else(broken_pipe)?;
            let input = tunnel.child.stdin.take().ok_or_else(broken_pipe)?;
            let mut output = ChildStdout::from_std(output)?;
            let input = ChildStdin::from_std(input)?;
            match output.read_u8().await {
                Ok(b'+') => {
                    tunnel.relay = Some(tokio::spawn(serve(output, input)));
                    return Ok(tunnel);
                }
                Ok(_) => return Err(io::Error::other("invalid Claude proxy greeting")),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(error) => return Err(error),
            }
            drop(tunnel);
            sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for ClaudeTunnel {
    fn drop(&mut self) {
        if let Some(relay) = self.relay.take() {
            relay.abort();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn broken_pipe() -> io::Error {
    io::Error::from(io::ErrorKind::BrokenPipe)
}

struct Frame {
    kind: u8,
    id: u32,
    data: Vec<u8>,
}

impl Frame {
    fn signal(kind: u8, id: u32) -> Self {
        Self {
            kind,
            id,
            data: Vec::new(),
        }
    }

    async fn read(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Self>> {
        let kind = match reader.read_u8().await {
            Ok(kind) => kind,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error),
        };
        let id = reader.read_u32().await?;
        let size = reader.read_u32().await? as usize;
        let valid = match kind {
            OPEN => size > 0 && size <= 64,
            DATA => size > 0 && size <= CHUNK,
            END | CLOSE => size == 0,
            _ => false,
        };
        if !valid || id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Claude proxy frame",
            ));
        }
        let mut data = vec![0; size];
        reader.read_exact(&mut data).await?;
        Ok(Some(Self { kind, id, data }))
    }

    async fn write(self, writer: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        writer.write_u8(self.kind).await?;
        writer.write_u32(self.id).await?;
        writer.write_u32(self.data.len() as u32).await?;
        writer.write_all(&self.data).await?;
        writer.flush().await
    }
}

async fn serve(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let (send, mut frames) = mpsc::channel::<Frame>(32);
    tokio::try_join!(serve_connections(&mut input, send), async {
        while let Some(frame) = frames.recv().await {
            timeout(HELLO_TIMEOUT, frame.write(&mut output)).await??;
        }
        Ok(())
    })?;
    Ok(())
}

type Active = HashMap<u32, (mpsc::Sender<Frame>, AbortHandle)>;

async fn serve_connections(
    input: &mut (impl AsyncRead + Unpin),
    output: mpsc::Sender<Frame>,
) -> io::Result<()> {
    let mut active = Active::new();
    let mut tasks = JoinSet::new();
    let mut latest = 0;
    let mut attempts = 0;
    while let Some(frame) = Frame::read(input).await? {
        while let Some(done) = tasks.try_join_next() {
            if let Ok(id) = done {
                active.remove(&id);
            }
        }
        let id = frame.id;
        if frame.kind == OPEN {
            if id <= latest {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reused Claude proxy stream",
                ));
            }
            latest = id;
            attempts += 1;
            if attempts > CONNECTION_BUDGET {
                return Err(io::Error::other("Claude proxy connection budget exhausted"));
            }
            let Some(host) = allowed_host(&frame.data).filter(|_| active.len() < CONNECTIONS)
            else {
                output
                    .send(Frame::signal(FAILED, id))
                    .await
                    .map_err(|_| broken_pipe())?;
                continue;
            };
            let (tx, rx) = mpsc::channel(32);
            let notify = output.clone();
            let task = tasks.spawn(async move {
                proxy_connection(host, id, rx, notify).await;
                id
            });
            active.insert(id, (tx, task));
        } else if frame.kind == CLOSE {
            if let Some((_, task)) = active.remove(&id) {
                task.abort();
            }
        } else if let Some((tx, _)) = active.get(&id)
            && tx.try_send(frame).is_err()
        {
            if let Some((_, task)) = active.remove(&id) {
                task.abort();
            }
            output
                .send(Frame::signal(CLOSE, id))
                .await
                .map_err(|_| broken_pipe())?;
        }
    }
    Ok(())
}

fn allowed_host(target: &[u8]) -> Option<&'static str> {
    match target {
        b"api.anthropic.com:443" => Some("api.anthropic.com"),
        b"platform.claude.com:443" => Some("platform.claude.com"),
        b"claude.com:443" => Some("claude.com"),
        b"claude.ai:443" => Some("claude.ai"),
        b"sso.claude.com:443" => Some("sso.claude.com"),
        _ => None,
    }
}

async fn connect(host: &str) -> io::Result<TcpStream> {
    let addresses = lookup_host((host, 443))
        .await?
        .filter(|address| is_public(address.ip()))
        .take(8)
        .collect::<Vec<SocketAddr>>();
    TcpStream::connect(addresses.as_slice()).await
}

fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => !matches!(
            address.octets(),
            [0 | 10 | 127 | 224..=255, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0, 0 | 2, _]
                | [192, 168, ..]
                | [198, 18 | 19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
        ),
        IpAddr::V6(address) => {
            let [prefix, subnet, ..] = address.segments();
            prefix & 0xe000 == 0x2000 && prefix != 0x2002 && (prefix, subnet) != (0x2001, 0x0db8)
        }
    }
}

async fn proxy_connection(
    host: &'static str,
    id: u32,
    mut input: mpsc::Receiver<Frame>,
    output: mpsc::Sender<Frame>,
) {
    let Ok(Ok(socket)) = timeout(CONNECT_TIMEOUT, connect(host)).await else {
        let _ = output.send(Frame::signal(FAILED, id)).await;
        return;
    };
    if output.send(Frame::signal(OPENED, id)).await.is_err() {
        return;
    }
    let Ok(Ok(hello)) = timeout(HELLO_TIMEOUT, receive_hello(&mut input, host)).await else {
        let _ = output.send(Frame::signal(CLOSE, id)).await;
        return;
    };
    let _ = timeout(
        STREAM_TIMEOUT,
        transfer(socket, hello, id, &mut input, &output),
    )
    .await;
    let _ = output.send(Frame::signal(CLOSE, id)).await;
}

async fn receive_hello(input: &mut mpsc::Receiver<Frame>, host: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let frame = input
            .recv()
            .await
            .filter(|frame| frame.kind == DATA)
            .ok_or_else(broken_pipe)?;
        bytes.extend_from_slice(&frame.data);
        if let Some(header) = bytes.get(..5) {
            let size = u16::from_be_bytes([header[3], header[4]]) as usize;
            if header[0] != 22 || header[1] != 3 || size > CHUNK {
                break;
            }
            if let Some(record) = bytes.get(5..5 + size) {
                if server_name(record)
                    .is_some_and(|name| name.eq_ignore_ascii_case(host.as_bytes()))
                {
                    return Ok(bytes);
                }
                break;
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Claude proxy TLS destination denied",
    ))
}

fn server_name(record: &[u8]) -> Option<&[u8]> {
    fn take<'a>(input: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
        let (first, rest) = input.split_at_checked(len)?;
        *input = rest;
        Some(first)
    }

    fn take_field<'a>(input: &mut &'a [u8], len_size: usize) -> Option<&'a [u8]> {
        let len = take(input, len_size)?
            .iter()
            .fold(0, |n, &byte| n * 256 + byte as usize);
        take(input, len)
    }

    let (1, mut body) = record.split_first().map(|(kind, body)| (*kind, body))? else {
        return None;
    };
    let mut hello = take_field(&mut body, 3)?;
    take(&mut hello, 34)?;
    take_field(&mut hello, 1)?;
    take_field(&mut hello, 2)?;
    take_field(&mut hello, 1)?;
    let mut extensions = take_field(&mut hello, 2)?;
    if !hello.is_empty() {
        return None;
    }
    let mut name = None;
    while !extensions.is_empty() {
        let kind = take(&mut extensions, 2)?;
        let mut extension = take_field(&mut extensions, 2)?;
        if kind == [0xfe, 0x0d] {
            return None;
        }
        if kind == [0, 0] {
            if name.is_some() {
                return None;
            }
            let mut names = take_field(&mut extension, 2)?;
            if !extension.is_empty() || take(&mut names, 1)? != [0] {
                return None;
            }
            name = Some(take_field(&mut names, 2)?);
            if !names.is_empty() {
                return None;
            }
        }
    }
    name
}

async fn transfer(
    socket: TcpStream,
    hello: Vec<u8>,
    id: u32,
    input: &mut mpsc::Receiver<Frame>,
    output: &mpsc::Sender<Frame>,
) -> io::Result<()> {
    let (mut incoming, mut outgoing) = socket.into_split();
    tokio::try_join!(
        async {
            let mut sent = hello.len();
            outgoing.write_all(&hello).await?;
            while let Some(frame) = input.recv().await {
                if frame.kind == END {
                    break;
                }
                sent += frame.data.len();
                if sent > BYTE_BUDGET {
                    return Err(io::Error::other("Claude proxy transmit budget exceeded"));
                }
                outgoing.write_all(&frame.data).await?;
            }
            outgoing.shutdown().await
        },
        async {
            let mut received = 0;
            let mut chunk = [0; CHUNK];
            loop {
                let size = incoming.read(&mut chunk).await?;
                if size == 0 {
                    output
                        .send(Frame::signal(END, id))
                        .await
                        .map_err(|_| broken_pipe())?;
                    break;
                }
                received += size;
                if received > BYTE_BUDGET {
                    return Err(io::Error::other("Claude proxy receive budget exceeded"));
                }
                output
                    .send(Frame {
                        kind: DATA,
                        id,
                        data: chunk[..size].to_vec(),
                    })
                    .await
                    .map_err(|_| broken_pipe())?;
            }
            Ok(())
        }
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(host: &str) -> Vec<u8> {
        let mut names = vec![0, 0, host.len() as u8];
        names.extend_from_slice(host.as_bytes());
        let mut extension = vec![0, 0, 0, (names.len() + 2) as u8, 0, names.len() as u8];
        extension.extend_from_slice(&names);
        let mut body = vec![3, 3];
        body.resize(34, 0);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, extension.len() as u8]);
        body.extend_from_slice(&extension);
        let mut result = vec![
            22,
            3,
            1,
            0,
            (body.len() + 4) as u8,
            1,
            0,
            0,
            body.len() as u8,
        ];
        result.extend_from_slice(&body);
        result
    }

    #[test]
    fn only_allows_fixed_anthropic_https_and_public_addresses() {
        assert_eq!(
            allowed_host(b"api.anthropic.com:443"),
            Some("api.anthropic.com")
        );
        assert_eq!(
            allowed_host(b"platform.claude.com:443"),
            Some("platform.claude.com")
        );
        for target in [
            "api.anthropic.com:80",
            "api.anthropic.com.attacker:443",
            "127.0.0.1:443",
        ] {
            assert_eq!(allowed_host(target.as_bytes()), None);
        }
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "172.16.1.1",
            "192.0.2.1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "::1",
        ] {
            assert!(!is_public(address.parse().unwrap()), "{address}");
        }
        assert!(is_public("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn accepts_fragmented_hello_only_for_requested_tls_name() {
        for (name, accepted) in [("api.anthropic.com", true), ("other.example", false)] {
            let bytes = hello(name);
            let (tx, mut rx) = mpsc::channel(2);
            for part in [&bytes[..2], &bytes[2..]] {
                tx.send(Frame {
                    kind: DATA,
                    id: 1,
                    data: part.to_vec(),
                })
                .await
                .unwrap();
            }
            assert_eq!(
                receive_hello(&mut rx, "api.anthropic.com").await.is_ok(),
                accepted
            );
        }
    }

    #[tokio::test]
    async fn rejects_unapproved_target_over_full_duplex_transport() {
        let (guest, host) = tokio::io::duplex(256);
        let (input, output) = tokio::io::split(host);
        let proxy = tokio::spawn(serve(input, output));
        let (mut reply, mut request) = tokio::io::split(guest);
        Frame {
            kind: OPEN,
            id: 1,
            data: b"localhost:443".to_vec(),
        }
        .write(&mut request)
        .await
        .unwrap();
        assert_eq!(reply.read_u8().await.unwrap(), FAILED);
        assert_eq!(reply.read_u32().await.unwrap(), 1);
        assert_eq!(reply.read_u32().await.unwrap(), 0);
        request.shutdown().await.unwrap();
        proxy.await.unwrap().unwrap();
    }
}
