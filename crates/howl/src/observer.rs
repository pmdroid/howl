mod snapshot;

use std::{
    fs, io,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::Arc,
};

use serde_json::Value;
use tempfile::TempDir;

pub use snapshot::Snapshot;

const TOOL_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";
pub const WORKSPACE: &str = "/workspace";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("observer could not access required resources")]
    Io(#[from] io::Error),
    #[error("a local Linux Docker engine with seccomp, cgroup v2 and resource limits is required")]
    UnsupportedEngine,
    #[error("a pinned Linux harness image with approved environment and no volumes is required")]
    UnsupportedImage,
    #[error("the harness executable must be an absolute container path")]
    InvalidExecutable,
    #[error("invalid commit or selection of tracked files")]
    InvalidSnapshot,
    #[error("snapshot path is outside policy: {}", .0.display())]
    UnsafePath(PathBuf),
    #[error("snapshot file is outside content policy: {}", .0.display())]
    UnsafeContent(PathBuf),
    #[error("{operation} failed ({status})")]
    Process {
        operation: &'static str,
        status: ExitStatus,
    },
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct ObserverProvider {
    socket: PathBuf,
    config: Arc<TempDir>,
}

impl ObserverProvider {
    pub fn connect(socket: &Path) -> Result<Self> {
        if !socket.is_absolute()
            || !fs::metadata(socket).is_ok_and(|info| info.file_type().is_socket())
        {
            return Err(Error::UnsupportedEngine);
        }
        let provider = Self {
            socket: socket.to_path_buf(),
            config: Arc::new(
                tempfile::Builder::new()
                    .prefix("howl-engine-config-")
                    .tempdir()?,
            ),
        };
        let info = provider.run(
            provider.command().args([
                "info", "--format",
                r#"{"os":{{json .OSType}},"cgroup":{{json .CgroupVersion}},"memory":{{json .MemoryLimit}},"swap":{{json .SwapLimit}},"cpu":{{json .CPUCfsQuota}},"pids":{{json .PidsLimit}},"security":{{json .SecurityOptions}}}"#,
            ]),
            "check Linux isolation",
        )?;
        let info: Value = serde_json::from_slice(&info).map_err(|_| Error::UnsupportedEngine)?;
        if info["os"] != "linux"
            || info["cgroup"] != "2"
            || ["memory", "swap", "cpu", "pids"]
                .iter()
                .any(|field| info[field] != true)
            || !info["security"].as_array().is_some_and(|options| {
                options
                    .iter()
                    .any(|option| option == "name=seccomp,profile=builtin")
            })
        {
            return Err(Error::UnsupportedEngine);
        }
        Ok(provider)
    }

    pub fn launch(
        &self,
        snapshot: &Snapshot,
        image: &str,
        executable: &Path,
        args: &[&str],
    ) -> Result<ObserverProcess> {
        if !executable.is_absolute() {
            return Err(Error::InvalidExecutable);
        }
        self.verify_image(image)?;
        let volume = self.create_volume()?;
        let mount = format!(
            "type=volume,src={},dst={WORKSPACE},volume-nocopy",
            volume.name
        );

        {
            let mut stage = self.command();
            stage.args([
                "create",
                "--pull=never",
                "--network=none",
                "--no-healthcheck",
                "--mount",
                &mount,
                "--entrypoint=/bin/false",
                image,
            ]);
            let stage = self.create_container(&mut stage)?;
            self.run(
                self.command()
                    .arg("cp")
                    .arg(snapshot.directory.path().join("tree/."))
                    .arg(format!("{}:{WORKSPACE}", stage.id)),
                "copy selected snapshot",
            )?;
            stage.remove()?;
        }

        let readonly = format!("{mount},readonly");
        let mut create = self.command();
        create
            .args([
                "create",
                "--pull=never",
                "--interactive",
                "--init",
                "--no-healthcheck",
                "--network=none",
                "--cgroupns=private",
                "--read-only",
                "--log-driver=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--user=65532:65532",
                "--pids-limit=128",
                "--memory=768m",
                "--memory-swap=768m",
                "--cpus=1",
                "--shm-size=16m",
                "--ulimit=nofile=256:256",
                "--stop-timeout=1",
                "--tmpfs=/scratch:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700",
                "--env=HOME=/scratch",
                "--env=TMPDIR=/scratch",
                "--env=XDG_CONFIG_HOME=/scratch/config",
                "--env=XDG_DATA_HOME=/scratch/data",
                "--env=XDG_CACHE_HOME=/scratch/cache",
                "--env=XDG_STATE_HOME=/scratch/state",
                "--mount",
                &readonly,
                "--workdir",
                WORKSPACE,
                "--entrypoint",
            ])
            .arg(executable)
            .arg(image)
            .args(args);

        let container = self.create_container(&mut create)?;
        let child = self
            .command()
            .args(["start", "--attach", "--interactive", &container.id])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok(ObserverProcess {
            child,
            container: Some(container),
            _volume: volume,
        })
    }

    fn verify_image(&self, image: &str) -> Result<()> {
        if !image
            .strip_prefix("sha256:")
            .is_some_and(|hash| digest(hash, &[64]))
        {
            return Err(Error::UnsupportedImage);
        }
        let output = self.run(
            self.command().args([
                "image", "inspect", "--format",
                r#"{"os":{{json .Os}},"volumes":{{json .Config.Volumes}},"env":{{json .Config.Env}}}"#,
                image,
            ]),
            "inspect trusted harness image",
        )?;
        let image: Value = serde_json::from_slice(&output).map_err(|_| Error::UnsupportedImage)?;
        let common_env = [
            "PATH",
            "HOME",
            "LANG",
            "LANGUAGE",
            "LC_ALL",
            "NODE_VERSION",
            "NODE_ENV",
            "YARN_VERSION",
        ];
        let environment = image["env"].is_null()
            || image["env"].as_array().is_some_and(|env| {
                env.iter().all(|value| {
                    value
                        .as_str()
                        .and_then(|value| value.split_once('='))
                        .is_some_and(|(name, _)| common_env.contains(&name))
                })
            });
        if image["os"] != "linux" || !image["volumes"].is_null() || !environment {
            return Err(Error::UnsupportedImage);
        }
        Ok(())
    }

    fn create_volume(&self) -> Result<Volume> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let name = format!("howl-observer-{}", hex::encode(random));
        self.run(
            self.command()
                .args(["volume", "create", "--driver", "local", "--name", &name]),
            "create disposable snapshot volume",
        )?;
        Ok(Volume {
            provider: self.clone(),
            name,
        })
    }

    fn create_container(&self, command: &mut Command) -> Result<Container> {
        let output = self.run(command, "prepare isolated container")?;
        let id = str::from_utf8(&output)
            .map_err(|_| Error::UnsupportedEngine)?
            .trim();
        if !digest(id, &[64]) {
            return Err(Error::UnsupportedEngine);
        }
        Ok(Container {
            provider: self.clone(),
            id: id.to_owned(),
        })
    }

    fn command(&self) -> Command {
        let mut socket = std::ffi::OsString::from("unix://");
        socket.push(&self.socket);
        let mut command = Command::new("docker");
        command
            .env_clear()
            .env("PATH", TOOL_PATH)
            .arg("--config")
            .arg(self.config.path())
            .arg("--host")
            .arg(socket);
        command
    }

    fn run(&self, command: &mut Command, operation: &'static str) -> Result<Vec<u8>> {
        let output = command
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(process_error(operation, output.status));
        }
        Ok(output.stdout)
    }
}

pub struct ObserverProcess {
    child: Child,
    container: Option<Container>,
    _volume: Volume,
}

impl ObserverProcess {
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    pub fn start_broker(&self, executable: &Path, args: &[&str]) -> Result<Child> {
        if !executable.is_absolute() {
            return Err(Error::InvalidExecutable);
        }
        let container = self.container.as_ref().ok_or(Error::UnsupportedEngine)?;
        Ok(container
            .provider
            .command()
            .args([
                "exec",
                "--interactive",
                "--user=65532:65532",
                "--workdir=/scratch",
                &container.id,
            ])
            .arg(executable)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }
}

impl Drop for ObserverProcess {
    fn drop(&mut self) {
        drop(self.container.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Container {
    provider: ObserverProvider,
    id: String,
}

impl Container {
    fn remove(mut self) -> Result<()> {
        self.remove_owned()?;
        self.id.clear();
        Ok(())
    }

    fn remove_owned(&self) -> Result<()> {
        self.provider.run(
            self.provider.command().args(["rm", "--force", &self.id]),
            "remove isolated container",
        )?;
        Ok(())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        if !self.id.is_empty() {
            let _ = self.remove_owned();
        }
    }
}

struct Volume {
    provider: ObserverProvider,
    name: String,
}

impl Drop for Volume {
    fn drop(&mut self) {
        let _ = self.provider.run(
            self.provider.command().args(["volume", "rm", &self.name]),
            "remove disposable snapshot volume",
        );
    }
}

fn digest(text: &str, sizes: &[usize]) -> bool {
    sizes.contains(&text.len())
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn process_error(operation: &'static str, status: ExitStatus) -> Error {
    Error::Process { operation, status }
}
