use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::Deserialize;
use tokio::{
    io::AsyncReadExt,
    net::UnixStream,
    process::{Child, ChildStdin},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    identity::StateDirectory,
    managed_acp::ManagedSession,
    observer::Snapshot,
    provider_broker::{Broker, Provider},
};

mod qemu;

const RUN_LIMIT: Duration = Duration::from_secs(900);
pub(crate) const PATCH_LIMIT: usize = 4 * 1024 * 1024;
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
    repository: PathBuf,
    pub session: ManagedSession,
    patch: UnixStream,
    _process: SandboxProcess,
    broker: Option<JoinHandle<io::Result<()>>>,
    rejected_subagent: Option<Arc<AtomicBool>>,
}

impl Drop for Guest {
    fn drop(&mut self) {
        if let Some(broker) = &self.broker {
            broker.abort();
        }
    }
}

struct BootedSandbox {
    acp: UnixStream,
    patch: UnixStream,
    inference: Option<UnixStream>,
    process: SandboxProcess,
}

struct SandboxProcess {
    process: Child,
    owner: Option<ChildStdin>,
}

impl Drop for SandboxProcess {
    fn drop(&mut self) {
        drop(self.owner.take());
        let _ = self.process.start_kill();
    }
}

trait SandboxProvider {
    async fn boot(&self, snapshot: Snapshot, inference: bool) -> io::Result<BootedSandbox>;
}

impl Guest {
    pub(crate) async fn start(
        state: &Path,
        profile: &Profile,
        snapshot: Snapshot,
    ) -> io::Result<Self> {
        let sandbox = qemu::Qemu::new(profile)?;
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
        let repository = snapshot.repository().to_owned();
        let commit = snapshot.commit().to_owned();
        let selection = snapshot.selection();
        let BootedSandbox {
            acp,
            patch,
            inference,
            process,
        } = sandbox.boot(snapshot, broker.is_some()).await?;
        let broker = broker.zip(inference);
        let rejected_subagent = broker
            .as_ref()
            .map(|(broker, _)| broker.rejected_subagent.clone());
        let broker = broker.map(|(broker, link)| tokio::spawn(broker.serve_guest(link)));
        let session = ManagedSession::guest(&state.join("worker-acp"), commit, selection, acp)
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            repository,
            session,
            patch,
            _process: process,
            rejected_subagent,
            broker,
        })
    }

    pub(crate) async fn prompt(&self, text: String, limit: Duration) -> io::Result<String> {
        let reply = self.session.prompt_text(text, limit).await;
        self.check_handoff()?;
        reply
    }

    fn check_handoff(&self) -> io::Result<()> {
        if self
            .rejected_subagent
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(io::Error::other(
                crate::provider_broker::Error::NativeSubagent,
            ));
        }
        Ok(())
    }

    pub(crate) async fn finish(mut self, run: &str) -> io::Result<Vec<u8>> {
        timeout(Duration::from_secs(10), self.session.close())
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        self.check_handoff()?;
        let patch = timeout(Duration::from_secs(10), read_patch(&mut self.patch))
            .await
            .map_err(io::Error::other)??;
        if patch.is_empty() {
            return Ok(patch);
        }
        let original = self.session.status();
        let snapshot = Snapshot::from_repository(&self.repository, &original.commit)
            .map_err(io::Error::other)?;
        if snapshot.selection() != original.snapshot {
            return Err(io::Error::other(
                "worker snapshot no longer matches its selection",
            ));
        }
        snapshot
            .verify_worker_patch(run, &patch)
            .map_err(io::Error::other)
    }
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

pub fn check(state: &Path) -> io::Result<()> {
    let profile = Profile::load(state)?;
    let provider = qemu::Qemu::new(&profile)?;
    println!("Configured QEMU accelerator: {}", provider.accelerator());
    println!(
        "Guest resources: {} MiB, {} vCPU",
        profile.memory_mib, profile.vcpus
    );
    Ok(())
}

pub async fn run(state: &Path, repo: &Path, revision: &str, text: String) -> io::Result<()> {
    let profile = Profile::load(state)?;
    let snapshot = Snapshot::from_repository(repo, revision).map_err(io::Error::other)?;
    let guest = Guest::start(state, &profile, snapshot).await?;
    let id = guest.session.status().id;
    let result = guest.prompt(text, RUN_LIMIT).await?;
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
}
