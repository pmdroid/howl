use std::{
    fs::{OpenOptions, Permissions},
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    process::Stdio,
    time::Duration,
};

use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Command,
    time::timeout,
};

use super::{BootedSandbox, Profile, SandboxProcess, SandboxProvider};
use crate::observer::Snapshot;

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
/bin/rm -f ./repo.tar ./acp ./patch ./provider
if [ . -ef "$PWD" ]; then /bin/rmdir "$PWD" 2>/dev/null || :; fi
exit "$status"
"#;

pub(super) struct Qemu<'a> {
    profile: &'a Profile,
    accelerator: &'static str,
}

impl<'a> Qemu<'a> {
    pub(super) fn new(profile: &'a Profile) -> io::Result<Self> {
        let accelerator = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => "hvf",
            ("linux", "aarch64") => {
                check_kvm(Path::new("/dev/kvm"))?;
                "kvm"
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "microVM workers require ARM64 with HVF or KVM",
                ));
            }
        };
        Ok(Self {
            profile,
            accelerator,
        })
    }

    pub(super) fn accelerator(&self) -> &'static str {
        self.accelerator
    }
}

fn check_kvm(path: &Path) -> io::Result<()> {
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

impl SandboxProvider for Qemu<'_> {
    async fn boot(&self, snapshot: Snapshot, inference: bool) -> io::Result<BootedSandbox> {
        let directory = tempfile::Builder::new()
            .prefix("howl-vm-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let archive = directory.path().join("repo.tar");
        snapshot.archive(&archive)?;
        drop(snapshot);
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", WATCH_OWNER, "howl-microvm"])
            .arg(&self.profile.qemu);
        command
            .env_clear()
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .args([
                "-no-user-config",
                "-nodefaults",
                "-no-reboot",
                "-display",
                "none",
                "-monitor",
                "none",
                "-serial",
                "none",
                "-nic",
                "none",
            ])
            .args([
                "-machine",
                "virt",
                "-accel",
                self.accelerator,
                "-cpu",
                "host",
            ])
            .arg("-m")
            .arg(self.profile.memory_mib.to_string())
            .arg("-smp")
            .arg(self.profile.vcpus.to_string())
            .arg("-kernel")
            .arg(&self.profile.kernel)
            .arg("-initrd")
            .arg(&self.profile.initramfs)
            .args([
                "-append",
                "rdinit=/init quiet panic=1",
                "-device",
                "virtio-serial-device,id=howl",
            ])
            .arg("-blockdev")
            .arg(
                json!({ "driver": "raw", "node-name": "repository", "read-only": true,
                "file": { "driver": "file", "filename": archive } })
                .to_string(),
            )
            .args(["-device", "virtio-blk-device,drive=repository"]);
        let acp = port(&mut command, directory.path(), "acp", 1)?;
        let patch = port(&mut command, directory.path(), "patch", 2)?;
        let inference = inference
            .then(|| port(&mut command, directory.path(), "provider", 3))
            .transpose()?;
        let mut process = command.spawn()?;
        let owner = process
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("microVM owner pipe unavailable"))?;
        let launcher = process
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing QEMU PID pipe"))?;
        let connect = async {
            let mut pid = String::new();
            BufReader::new(launcher.take(32))
                .read_line(&mut pid)
                .await?;
            let pid = pid.trim_end().parse::<i32>().map_err(io::Error::other)?;
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
        };
        let (acp, patch, inference) = tokio::select! {
            result = timeout(BOOT, connect) => result.map_err(io::Error::other)??,
            _ = process.wait() => return Err(io::Error::other("microVM exited during startup")),
        };
        directory.close()?;
        Ok(BootedSandbox {
            acp,
            patch,
            inference,
            process: SandboxProcess {
                process,
                owner: Some(owner),
            },
        })
    }
}

async fn accept_vm(listener: &UnixListener, pid: i32) -> io::Result<UnixStream> {
    loop {
        let (link, _) = listener.accept().await?;
        if link.peer_cred()?.pid() == Some(pid) {
            return Ok(link);
        }
    }
}

fn port(
    command: &mut Command,
    directory: &Path,
    name: &str,
    number: u8,
) -> io::Result<UnixListener> {
    let socket = directory.join(name);
    let listener = UnixListener::bind(&socket)?;
    command
        .arg("-chardev")
        .arg(format!(
            "socket,id={name},path={},server=off",
            socket.display()
        ))
        .arg("-device")
        .arg(format!(
            "virtserialport,bus=howl.0,nr={number},chardev={name},name=howl.{name}"
        ));
    Ok(listener)
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
}
