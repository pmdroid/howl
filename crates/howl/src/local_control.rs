use std::{
    fs::File,
    io,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rustix::{
    fs::{FlockOperation, Mode, OFlags, flock, open},
    process::geteuid,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};

const CONTROL_SOCKET: &str = "mesh.sock";
const CONTROL_LOCK: &str = "mesh.lock";
const MAX_REQUEST: usize = 66_000;
const DEADLINE: Duration = Duration::from_secs(5);

pub struct ControlServer {
    pub listener: UnixListener,
    socket_path: PathBuf,
    lock: File,
}

impl ControlServer {
    pub fn bind(state: &Path) -> io::Result<Self> {
        let lock_path = state.join(CONTROL_LOCK);
        let lock = File::from(open(
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        let metadata = lock.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid mesh lock",
            ));
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        let socket_path = state.join(CONTROL_SOCKET);
        match socket_path.symlink_metadata() {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == geteuid().as_raw() => {
                std::fs::remove_file(&socket_path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "invalid mesh socket",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&socket_path)?;
        Ok(Self {
            listener,
            socket_path,
            lock,
        })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = flock(&self.lock, FlockOperation::Unlock);
    }
}

pub async fn request(state: &Path, bytes: &[u8]) -> io::Result<String> {
    timeout(DEADLINE, async {
        let mut link = UnixStream::connect(state.join(CONTROL_SOCKET)).await?;
        authorize(&link)?;
        link.write_all(bytes).await?;
        link.shutdown().await?;
        let mut reply = String::new();
        link.take(1024).read_to_string(&mut reply).await?;
        if !reply.ends_with('\n') || reply.len() == 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated mesh control reply",
            ));
        }
        if let Some(error) = reply.strip_prefix("ERROR ") {
            return Err(io::Error::other(error.trim_end().to_owned()));
        }
        if let Some(text) = reply.strip_prefix("OK ") {
            return Ok(text.trim_end().to_owned());
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mesh control reply",
        ))
    })
    .await?
}

pub async fn read_request(link: &mut UnixStream) -> io::Result<Vec<u8>> {
    authorize(link)?;
    let mut request = Vec::new();
    timeout(
        DEADLINE,
        link.take((MAX_REQUEST + 1) as u64)
            .read_to_end(&mut request),
    )
    .await??;
    if request.len() > MAX_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mesh control request is too large",
        ));
    }
    Ok(request)
}

pub async fn reply(link: &mut UnixStream, result: io::Result<String>) -> io::Result<()> {
    let text = match result {
        Ok(value) => format!("OK {value}\n"),
        Err(error) => format!("ERROR {error}\n"),
    };
    timeout(DEADLINE, link.write_all(text.as_bytes())).await??;
    link.shutdown().await
}

fn authorize(link: &UnixStream) -> io::Result<()> {
    if link.peer_cred()?.uid() != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mesh control user does not match",
        ));
    }
    Ok(())
}
