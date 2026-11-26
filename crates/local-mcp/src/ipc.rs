use std::{
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rustix::process::geteuid;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::JoinSet,
    time::timeout,
};
use zeroize::Zeroizing;

use crate::{
    Authority, Call, Communications, Credential, Failure, Reply,
    policy::{check_acl, permission},
};

const VERSION: u8 = 1;
const MAX_REQUEST: usize = 128 * 1024;
const MAX_REPLY: usize = 1024 * 1024;
const MAX_CLIENTS: usize = 16;
const DEADLINE: Duration = Duration::from_secs(5);

pub struct Daemon {
    listener: UnixListener,
    socket: PathBuf,
    identity: (u64, u64),
    authority: Authority,
    uid: u32,
}

impl Daemon {
    pub fn bind(socket: &Path, backend: impl Communications) -> io::Result<(Self, Authority)> {
        let parent = socket
            .parent()
            .ok_or_else(|| permission("socket needs a private directory"))?;
        let uid = geteuid().as_raw();
        let directory = parent.symlink_metadata()?;
        if !directory.is_dir() || directory.uid() != uid || directory.mode() & 0o077 != 0 {
            return Err(permission(
                "socket directory must be private and owned by this user",
            ));
        }
        check_acl(parent)?;
        let listener = UnixListener::bind(socket)?;
        let metadata = match socket.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == uid => metadata,
            _ => return Err(permission("invalid local socket")),
        };
        let authority = Authority::new(backend);
        let daemon = Self {
            listener,
            socket: socket.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
            authority: authority.clone(),
            uid,
        };
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        Ok((daemon, authority))
    }

    pub async fn serve(self) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                connection = self.listener.accept(), if tasks.len() < MAX_CLIENTS => {
                    let (stream, _) = connection?;
                    let authority = self.authority.clone();
                    let uid = self.uid;
                    tasks.spawn(handle(stream, authority, uid));
                }
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.socket.symlink_metadata().is_ok_and(|metadata| {
            metadata.file_type().is_socket() && self.identity == (metadata.dev(), metadata.ino())
        }) {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}

#[derive(Clone)]
pub struct Client {
    socket: PathBuf,
    credential: Credential,
}

impl Client {
    pub fn new(socket: impl Into<PathBuf>, credential: Credential) -> Self {
        Self {
            socket: socket.into(),
            credential,
        }
    }

    pub async fn call(&self, call: Call) -> Result<Reply, Failure> {
        call.validate()?;
        timeout(DEADLINE, self.exchange(call))
            .await
            .map_err(|_| Failure::Unavailable)?
            .map_err(|error| match error.kind() {
                io::ErrorKind::PermissionDenied => Failure::Denied,
                _ => Failure::Unavailable,
            })?
    }

    async fn exchange(&self, call: Call) -> io::Result<Result<Reply, Failure>> {
        let mut stream = UnixStream::connect(&self.socket).await?;
        verify_peer(&stream, geteuid().as_raw())?;
        stream.write_u8(VERSION).await?;
        stream.write_all(self.credential.bytes()).await?;
        write_frame(&mut stream, &call, MAX_REQUEST).await?;
        stream.shutdown().await?;
        if stream.read_u8().await? != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported IPC version",
            ));
        }
        read_frame(&mut stream, MAX_REPLY).await
    }
}

async fn handle(mut stream: UnixStream, authority: Authority, uid: u32) {
    let deadline = Instant::now() + DEADLINE;
    let _ = timeout(DEADLINE, async {
        verify_peer(&stream, uid)?;
        if stream.read_u8().await? != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported IPC version",
            ));
        }
        let mut credential = Zeroizing::new([0; 32]);
        stream.read_exact(&mut *credential).await?;
        let call = read_frame(&mut stream, MAX_REQUEST).await;
        let reply = match call {
            Ok(call) => {
                tokio::task::spawn_blocking(move || authority.dispatch(&credential, call, deadline))
                    .await
                    .unwrap_or(Err(Failure::Unavailable))
            }
            Err(_) => Err(Failure::Invalid),
        };
        stream.write_u8(VERSION).await?;
        write_frame(&mut stream, &reply, MAX_REPLY).await?;
        stream.shutdown().await
    })
    .await;
}

fn verify_peer(stream: &UnixStream, uid: u32) -> io::Result<()> {
    if stream.peer_cred()?.uid() != uid {
        return Err(permission("unexpected IPC peer user"));
    }
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream, maximum: usize) -> io::Result<T> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPC frame length",
        ));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    if stream.read(&mut [0]).await? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing IPC data",
        ));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

async fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    maximum: usize,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IPC frame too large",
        ));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}
