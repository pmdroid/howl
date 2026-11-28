use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use serde::Deserialize;
use serde_json::json;
use tokio::{
    io::AsyncReadExt,
    net::{UnixListener, UnixStream},
    process::{Child, ChildStdin, Command},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    identity::StateDirectory,
    managed_acp::ManagedSession,
    observer::Snapshot,
    provider_broker::{Broker, Provider},
};

const BOOT: Duration = Duration::from_secs(60);
const RUN_LIMIT: Duration = Duration::from_secs(900);
pub(crate) const PATCH_LIMIT: usize = 4 * 1024 * 1024;
const WATCH_OWNER: &str = r#"
exec 3<&0
"$@" </dev/null 3<&- &
machine=$!
(
    IFS= read -r unused <&3 || :
    kill -KILL "$machine" 2>/dev/null
) &
watcher=$!
wait "$machine"
status=$?
kill "$watcher" 2>/dev/null || :
wait "$watcher" 2>/dev/null || :
exit "$status"
"#;

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profile {
    qemu: PathBuf,
    kernel: PathBuf,
    initramfs: PathBuf,
    memory_mib: u16,
    vcpus: u8,
    provider: Option<Inference>,
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Inference {
    provider: String,
    model: String,
}

impl Profile {
    pub(crate) fn load(state: &Path) -> io::Result<Self> {
        let bytes = StateDirectory::open(state)?.read_bounded("microvm.json", 16_384)?;
        let profile: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        for path in [&profile.qemu, &profile.kernel, &profile.initramfs] {
            if !path.is_absolute() || !path.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "microVM assets must be absolute file paths",
                ));
            }
        }
        if !(256..=8192).contains(&profile.memory_mib) || !(1..=4).contains(&profile.vcpus) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid microVM resources",
            ));
        }
        Ok(profile)
    }
}

pub(crate) struct Guest {
    snapshot: Snapshot,
    pub session: ManagedSession,
    patch: UnixStream,
    process: Child,
    owner: Option<ChildStdin>,
    _directory: tempfile::TempDir,
    broker: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for Guest {
    fn drop(&mut self) {
        if let Some(broker) = &self.broker {
            broker.abort();
        }
        drop(self.owner.take());
        let _ = self.process.start_kill();
    }
}

impl Guest {
    pub(crate) async fn start(
        state: &Path,
        profile: &Profile,
        snapshot: Snapshot,
    ) -> io::Result<Self> {
        let accelerator = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => "hvf",
            ("linux", "aarch64") => "kvm",
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "microVM workers require ARM64 with HVF or KVM",
                ));
            }
        };
        let broker = match &profile.provider {
            Some(inference) => {
                if inference.provider == "chatgpt_plan" {
                    let configured = |name| {
                        std::env::var_os(name).map(PathBuf::from).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("set {name} for the ChatGPT plan broker"),
                            )
                        })
                    };
                    let auth = crate::managed_acp::ChatGptPlanAuth::new(
                        configured("HOWL_CHATGPT_NODE")?,
                        configured("HOWL_CHATGPT_HELPER")?,
                        configured("HOWL_CHATGPT_STORE")?,
                    )
                    .map_err(io::Error::other)?;
                    let token = auth.access_token().await.map_err(io::Error::other)?;
                    Some(
                        Broker::from_chatgpt_plan(&inference.model, token)
                            .map_err(io::Error::other)?,
                    )
                } else {
                    let provider = match inference.provider.as_str() {
                        "openai" => Provider::OpenAi,
                        "xai" => Provider::XAi,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "unsupported microVM inference provider",
                            ));
                        }
                    };
                    Some(
                        Broker::from_environment(provider, &inference.model)
                            .map_err(io::Error::other)?,
                    )
                }
            }
            None => None,
        };
        let directory = tempfile::Builder::new()
            .prefix("howl-vm-")
            .tempdir_in("/tmp")?;
        let archive = directory.path().join("repo.tar");
        snapshot.archive(&archive)?;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", WATCH_OWNER, "howl-microvm"])
            .arg(&profile.qemu);
        command
            .env_clear()
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
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
            .args(["-machine", "virt", "-accel", accelerator, "-cpu", "host"])
            .arg("-m")
            .arg(profile.memory_mib.to_string())
            .arg("-smp")
            .arg(profile.vcpus.to_string())
            .arg("-kernel")
            .arg(&profile.kernel)
            .arg("-initrd")
            .arg(&profile.initramfs)
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
        let inference = broker
            .map(|broker| {
                port(&mut command, directory.path(), "provider", 3).map(|port| (broker, port))
            })
            .transpose()?;
        let mut process = command.spawn()?;
        let owner = process
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("microVM owner pipe unavailable"))?;
        let connect = async {
            let (mut acp, _) = acp.accept().await?;
            let (patch, _) = patch.accept().await?;
            let broker = if let Some((broker, port)) = inference {
                let (link, _) = port.accept().await?;
                Some(tokio::spawn(broker.serve_guest(link)))
            } else {
                None
            };
            let mut ready = [0; 15];
            acp.read_exact(&mut ready).await?;
            if &ready != b"HOWL_ACP_READY\n" {
                return Err(io::Error::other("invalid microVM ACP greeting"));
            }
            Ok((acp, patch, broker))
        };
        let (link, patch, broker) = tokio::select! {
            result = timeout(BOOT, connect) => result.map_err(io::Error::other)??,
            _ = process.wait() => return Err(io::Error::other("microVM exited during startup")),
        };
        let session = ManagedSession::guest(&state.join("worker-acp"), &snapshot, link)
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            snapshot,
            session,
            patch,
            process,
            owner: Some(owner),
            _directory: directory,
            broker,
        })
    }

    pub(crate) async fn finish(mut self, run: &str) -> io::Result<Vec<u8>> {
        timeout(Duration::from_secs(10), self.session.close())
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        let patch = timeout(Duration::from_secs(10), read_patch(&mut self.patch))
            .await
            .map_err(io::Error::other)??;
        self.snapshot
            .verify_worker_patch(run, &patch)
            .map_err(io::Error::other)
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

async fn read_patch(patch: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut size = [0; 8];
    patch.read_exact(&mut size).await?;
    let size = usize::try_from(u64::from_be_bytes(size)).map_err(io::Error::other)?;
    if size > PATCH_LIMIT {
        return Err(io::Error::other(
            "microVM patch exceeds the configured limit",
        ));
    }
    let mut bytes = vec![0; size];
    patch.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub async fn run(state: &Path, repo: &Path, revision: &str, text: String) -> io::Result<()> {
    let profile = Profile::load(state)?;
    let snapshot = Snapshot::from_repository(repo, revision).map_err(io::Error::other)?;
    let guest = Guest::start(state, &profile, snapshot).await?;
    let id = guest.session.status().id;
    let result = crate::ongoing::prompt(&guest.session, text, RUN_LIMIT).await?;
    let patch = guest.finish(&id).await?;
    if !patch.is_empty() {
        let name = format!("{id}.patch");
        if !StateDirectory::open(&state.join("worker-patches"))?.write(&name, &patch)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "worker patch already exists",
            ));
        }
        println!("Patch {name}");
    }
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn rejects_a_patch_length_beyond_the_limit_before_reading_a_body() {
        let (mut guest, mut host) = UnixStream::pair().unwrap();
        guest
            .write_all(&((PATCH_LIMIT as u64) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(read_patch(&mut host).await.is_err());
    }

    #[tokio::test]
    async fn owner_pipe_outlives_startup_polling_and_stops_the_guest_on_close() {
        let mut process = Command::new("/bin/sh")
            .args(["-c", WATCH_OWNER, "howl-watchdog-test", "/bin/sleep", "20"])
            .stdin(Stdio::piped())
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
    }
}
