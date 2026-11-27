use std::{
    env, fs, io,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use rustix::process::{Pid, Signal, kill_process_group};
use sha2::{Digest, Sha256};

use super::{Error, Result};

pub struct HostClaude {
    node: PathBuf,
    adapter: PathBuf,
    claude: PathBuf,
    home: PathBuf,
}

impl HostClaude {
    pub fn new(node: PathBuf, adapter: PathBuf, claude: PathBuf, home: PathBuf) -> Result<Self> {
        if ![&node, &adapter, &claude, &home]
            .into_iter()
            .all(|path| path.is_absolute())
        {
            return Err(Error::HostAgent);
        }
        Ok(Self {
            node,
            adapter,
            claude,
            home,
        })
    }

    pub(super) fn fingerprint(&self, hash: &mut Sha256) {
        hash.update(b"howl/host-claude/v1\0");
        for path in [&self.node, &self.adapter, &self.claude, &self.home] {
            let value = path.as_os_str().as_encoded_bytes();
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
    }

    pub(super) fn start(&self) -> Result<HostProcess> {
        let scratch = tempfile::Builder::new().prefix("howl-host-").tempdir()?;
        let scratch_path = fs::canonicalize(scratch.path())?;
        let cwd = scratch_path.join("workspace");
        let home = scratch_path.join("home");
        fs::create_dir(&cwd)?;
        fs::create_dir(&home)?;
        let wrapper = scratch.path().join("claude-wrapper.mjs");
        fs::write(&wrapper, include_str!("../host_agents/claude-wrapper.mjs"))?;
        let executable = scratch.path().join("claude");
        fs::write(
            &executable,
            "#!/bin/sh\nexec \"$HOWL_CLAUDE_NODE\" \"$HOWL_CLAUDE_WRAPPER\" \"$@\"\n",
        )?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        let node_directory = self.node.parent().ok_or(Error::HostAgent)?;
        let path = env::join_paths([
            node_directory,
            Path::new("/opt/homebrew/bin"),
            Path::new("/usr/local/bin"),
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .map_err(|_| Error::HostAgent)?;
        let child = Command::new(&self.adapter)
            .current_dir(&cwd)
            .env_clear()
            .env("HOME", &home)
            .env("TMPDIR", &scratch_path)
            .env("PATH", path)
            .env("CLAUDE_AGENT_ACP_PROTOCOL", "v1")
            .env("CLAUDE_CODE_EXECUTABLE", executable)
            .env("HOWL_AGENT_CWD", &cwd)
            .env("HOWL_CLAUDE_NODE", &self.node)
            .env("HOWL_CLAUDE_WRAPPER", wrapper)
            .env("HOWL_CLAUDE_EXECUTABLE", &self.claude)
            .env("HOWL_CLAUDE_HOME", &self.home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?;
        Ok(HostProcess {
            child,
            cwd,
            _scratch: scratch,
        })
    }

    pub(super) fn node(&self) -> &Path {
        &self.node
    }
}

pub(super) struct HostProcess {
    pub(super) child: Child,
    pub(super) cwd: PathBuf,
    _scratch: tempfile::TempDir,
}

impl HostProcess {
    pub(super) fn stop(&mut self) -> io::Result<()> {
        if let Some(pid) = Pid::from_raw(self.child.id() as i32) {
            let _ = kill_process_group(pid, Signal::KILL);
        }
        self.child.wait().map(|_| ())
    }
}

impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
