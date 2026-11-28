use std::{
    fs::OpenOptions, future::Future, io, os::unix::fs::FileTypeExt, path::Path, process::Stdio,
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::{UnixListener, UnixStream},
    process::{Child, ChildStdin, Command},
    time::timeout,
};

const BOOT: Duration = Duration::from_secs(60);
const WATCH_OWNER: &str = r#"
exec 3<&0
"$@" </dev/null >/dev/null 3<&- &
machine=$!
printf '%s\n' "$machine"
(
    IFS= read -r unused <&3 || :
    kill -KILL "$machine" 2>/dev/null
) &
watcher=$!
wait "$machine"
status=$?
kill "$watcher" 2>/dev/null || :
wait "$watcher" 2>/dev/null || :
/bin/rm -f ./repo.tar ./acp ./patch ./provider ./config.json ./guest ./guest_7821 ./guest_7822 ./guest_7823
if [ . -ef "$PWD" ]; then /bin/rmdir "$PWD" 2>/dev/null || :; fi
exit "$status"
"#;

pub(super) struct SandboxProcess {
    owner: Option<ChildStdin>,
    child: Child,
}

impl SandboxProcess {
    pub(super) async fn stop(&mut self) -> io::Result<()> {
        drop(self.owner.take());
        timeout(Duration::from_secs(5), self.child.wait())
            .await
            .map_err(io::Error::other)??;
        Ok(())
    }
}

pub(super) fn command(binary: &Path, directory: &Path) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", WATCH_OWNER, "howl-microvm"])
        .arg(binary)
        .env_clear()
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

pub(super) async fn boot<T, F: Future<Output = io::Result<T>>>(
    command: &mut Command,
    connect: impl FnOnce(i32) -> F,
) -> io::Result<(SandboxProcess, T)> {
    let mut child = command.spawn()?;
    let owner = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("microVM owner pipe unavailable"))?;
    let mut process = SandboxProcess {
        owner: Some(owner),
        child,
    };
    let launcher = process
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing microVM PID pipe"))?;
    let ready = async {
        let mut pid = String::new();
        BufReader::new(launcher.take(32))
            .read_line(&mut pid)
            .await?;
        let pid = pid.trim_end().parse::<i32>().map_err(io::Error::other)?;
        if pid <= 1 {
            return Err(io::Error::other("invalid microVM PID"));
        }
        connect(pid).await
    };
    let ports = tokio::select! {
        result = timeout(BOOT, ready) => result.map_err(io::Error::other)??,
        _ = process.child.wait() => return Err(io::Error::other("microVM exited during startup")),
    };
    Ok((process, ports))
}

pub(super) async fn guest_ports(
    acp: UnixListener,
    patch: UnixListener,
    inference: Option<UnixListener>,
    pid: i32,
) -> io::Result<(UnixStream, UnixStream, Option<UnixStream>)> {
    let mut acp = accept_vm(&acp, pid).await?;
    let patch = accept_vm(&patch, pid).await?;
    let inference = if let Some(port) = inference {
        Some(accept_vm(&port, pid).await?)
    } else {
        None
    };
    let mut ready = [0; 15];
    acp.read_exact(&mut ready).await?;
    if &ready != b"HOWL_ACP_READY\n" {
        return Err(io::Error::other("invalid microVM ACP greeting"));
    }
    Ok((acp, patch, inference))
}

pub(super) fn check_kvm(path: &Path) -> io::Result<()> {
    let check = || {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        if !file.metadata()?.file_type().is_char_device() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a character device",
            ));
        }
        Ok::<_, io::Error>(())
    };
    check().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Linux microVM workers need read/write access to /dev/kvm: {error}"),
        )
    })
}

async fn accept_vm(listener: &UnixListener, pid: i32) -> io::Result<UnixStream> {
    loop {
        let (link, _) = listener.accept().await?;
        if link.peer_cred()?.pid() == Some(pid) {
            return Ok(link);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_preflight_rejects_missing_and_regular_files() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("kvm");
        assert_eq!(
            check_kvm(&file).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        std::fs::write(&file, []).unwrap();
        assert_eq!(
            check_kvm(&file).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn serial_connections_require_the_expected_process() {
        let pair = tempfile::tempdir().unwrap();
        let socket = pair.path().join("acp");
        let listener = UnixListener::bind(&socket).unwrap();
        let pid = i32::try_from(std::process::id()).unwrap();
        let _other = UnixStream::connect(&socket).await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), accept_vm(&listener, pid + 1))
                .await
                .is_err()
        );
        let _expected = UnixStream::connect(&socket).await.unwrap();
        accept_vm(&listener, pid).await.unwrap();
    }

    #[tokio::test]
    async fn owner_pipe_outlives_startup_polling_and_stops_the_guest_on_close() {
        let parent = tempfile::tempdir().unwrap();
        let runtime = parent.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::write(runtime.join("repo.tar"), "synthetic snapshot").unwrap();
        let mut process = Command::new("/bin/sh")
            .current_dir(&runtime)
            .args(["-c", WATCH_OWNER, "howl-watchdog-test", "/bin/sleep", "20"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let owner = process.stdin.take().unwrap();
        assert!(
            timeout(Duration::from_millis(150), process.wait())
                .await
                .is_err()
        );
        drop(owner);
        let status = timeout(Duration::from_secs(3), process.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
        assert!(!runtime.exists());
    }

    #[tokio::test]
    async fn cancelling_during_boot_cleans_up_the_launch_directory() {
        let parent = tempfile::tempdir().unwrap();
        let runtime = parent.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::write(runtime.join("config.json"), "{}").unwrap();
        let mut launcher = command(Path::new("/bin/sleep"), &runtime);
        launcher.arg("20");
        let (notice, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            boot(&mut launcher, |_| async move {
                notice.send(()).unwrap();
                std::future::pending::<io::Result<()>>().await
            })
            .await
        });
        timeout(Duration::from_secs(3), started)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        timeout(Duration::from_secs(3), async {
            while runtime.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
}
