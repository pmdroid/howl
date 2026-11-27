use std::{
    env, fs, io,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use rustix::process::{Pid, Signal, kill_process_group};
use sha2::{Digest, Sha256};

use super::{Error, RepositoryHttp, Result};

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

    pub(super) fn start(&self, editable: bool, work: bool) -> Result<HostProcess> {
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
        launch(&self.adapter, &self.node, scratch, cwd, &home, |command| {
            command
                .env("HOWL_EDITABLE_WORKSPACE", if editable { "1" } else { "0" })
                .env("HOWL_WORK_TOOLS", if work { "1" } else { "0" })
                .env("CLAUDE_AGENT_ACP_PROTOCOL", "v1")
                .env("CLAUDE_CODE_EXECUTABLE", executable)
                .env("HOWL_CLAUDE_NODE", &self.node)
                .env("HOWL_CLAUDE_WRAPPER", wrapper)
                .env("HOWL_CLAUDE_EXECUTABLE", &self.claude)
                .env("HOWL_CLAUDE_HOME", &self.home);
        })
    }

    pub(super) fn node(&self) -> &Path {
        &self.node
    }
}

pub struct HostGrok {
    node: PathBuf,
    grok: PathBuf,
    auth: PathBuf,
}

impl HostGrok {
    pub fn new(node: PathBuf, grok: PathBuf, auth: PathBuf) -> Result<Self> {
        if ![&node, &grok, &auth]
            .into_iter()
            .all(|path| path.is_absolute())
        {
            return Err(Error::HostAgent);
        }
        Ok(Self { node, grok, auth })
    }

    fn fingerprint(&self, hash: &mut Sha256) {
        hash.update(b"howl/host-grok/v1\0");
        for path in [&self.node, &self.grok, &self.auth] {
            let value = path.as_os_str().as_encoded_bytes();
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
    }

    fn start(&self, editable: bool, work: bool) -> Result<HostProcess> {
        let scratch = tempfile::Builder::new().prefix("howl-host-").tempdir()?;
        let scratch_path = fs::canonicalize(scratch.path())?;
        let cwd = scratch_path.join("workspace");
        let home = scratch_path.join("home");
        fs::create_dir(&cwd)?;
        fs::create_dir(&home)?;
        let wrapper = scratch_path.join("grok-wrapper.mjs");
        fs::write(&wrapper, include_str!("../host_agents/grok-wrapper.mjs"))?;
        launch(&self.node, &self.node, scratch, cwd, &home, |command| {
            command
                .arg(wrapper)
                .env("HOWL_EDITABLE_WORKSPACE", if editable { "1" } else { "0" })
                .env("HOWL_WORK_TOOLS", if work { "1" } else { "0" })
                .env("HOWL_GROK_EXECUTABLE", &self.grok)
                .env("HOWL_GROK_AUTH_PATH", &self.auth);
        })
    }
}

pub struct HostCodex {
    node: PathBuf,
    codex: PathBuf,
    home: PathBuf,
    state_home: Option<PathBuf>,
}

impl HostCodex {
    pub fn new(node: PathBuf, codex: PathBuf, home: PathBuf) -> Result<Self> {
        if ![&node, &codex, &home]
            .into_iter()
            .all(|path| path.is_absolute())
        {
            return Err(Error::HostAgent);
        }
        Ok(Self {
            node,
            codex,
            home,
            state_home: None,
        })
    }

    pub fn with_state_home(mut self, state_home: PathBuf) -> Result<Self> {
        if !state_home.is_absolute() {
            return Err(Error::HostAgent);
        }
        self.state_home = Some(state_home);
        Ok(self)
    }

    fn fingerprint(&self, hash: &mut Sha256) {
        hash.update(b"howl/host-codex/v1\0");
        for path in [&self.node, &self.codex, &self.home]
            .into_iter()
            .chain(self.state_home.iter())
        {
            let value = path.as_os_str().as_encoded_bytes();
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
    }

    fn start(
        &self,
        repository: &RepositoryHttp,
        editable: bool,
        work: bool,
    ) -> Result<HostProcess> {
        let scratch = tempfile::Builder::new().prefix("howl-host-").tempdir()?;
        let scratch_path = fs::canonicalize(scratch.path())?;
        let cwd = scratch_path.join("workspace");
        let home = scratch_path.join("home");
        fs::create_dir(&cwd)?;
        fs::create_dir(&home)?;
        let wrapper = scratch_path.join("codex-wrapper.mjs");
        fs::write(&wrapper, include_str!("../host_agents/codex-wrapper.mjs"))?;
        launch(&self.node, &self.node, scratch, cwd, &home, |command| {
            command
                .arg(wrapper)
                .env("HOWL_EDITABLE_WORKSPACE", if editable { "1" } else { "0" })
                .env("HOWL_WORK_TOOLS", if work { "1" } else { "0" })
                .env("HOWL_CODEX_EXECUTABLE", &self.codex)
                .env("HOWL_CODEX_HOME", &self.home)
                .env("HOWL_REPOSITORY_MCP_URL", repository.url())
                .env("HOWL_REPOSITORY_MCP_TOKEN", repository.token());
            if let Some(state_home) = &self.state_home {
                command.env("HOWL_CODEX_STATE_HOME", state_home);
            }
        })
    }
}

pub struct HostOpenCode {
    node: PathBuf,
    opencode: PathBuf,
    data: PathBuf,
    model: String,
}

impl HostOpenCode {
    pub fn new(node: PathBuf, opencode: PathBuf, data: PathBuf, model: String) -> Result<Self> {
        if ![&node, &opencode, &data]
            .into_iter()
            .all(|path| path.is_absolute())
            || model.is_empty()
            || !model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        {
            return Err(Error::HostAgent);
        }
        Ok(Self {
            node,
            opencode,
            data,
            model,
        })
    }

    fn fingerprint(&self, hash: &mut Sha256) {
        hash.update(b"howl/host-opencode/v1\0");
        for value in [
            self.node.as_os_str().as_encoded_bytes(),
            self.opencode.as_os_str().as_encoded_bytes(),
            self.data.as_os_str().as_encoded_bytes(),
            self.model.as_bytes(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
    }

    fn start(&self, editable: bool, work: bool) -> Result<HostProcess> {
        let scratch = tempfile::Builder::new().prefix("howl-host-").tempdir()?;
        let scratch_path = fs::canonicalize(scratch.path())?;
        let cwd = scratch_path.join("workspace");
        let home = scratch_path.join("home");
        fs::create_dir(&cwd)?;
        fs::create_dir(&home)?;
        let configure = |command: &mut Command| {
            command
                .env("XDG_DATA_HOME", &self.data)
                .env("XDG_CONFIG_HOME", scratch_path.join("config"))
                .env("XDG_STATE_HOME", scratch_path.join("state"))
                .env("XDG_CACHE_HOME", scratch_path.join("cache"))
                .env("OPENCODE_DISABLE_PROJECT_CONFIG", "true")
                .env("OPENCODE_DISABLE_CLAUDE_CODE", "true")
                .env("OPENCODE_DISABLE_FREE_MODELS", "true")
                .env("OPENCODE_DISABLE_AUTOUPDATE", "true");
        };
        let mut version = Command::new(&self.opencode);
        version
            .env_clear()
            .env("HOME", &home)
            .current_dir(&cwd)
            .arg("--version");
        configure(&mut version);
        let version = version.output()?;
        if !version.status.success() || version.stdout.trim_ascii() != b"opencode v2.4.2" {
            return Err(Error::HostAgent);
        }
        let model = format!("opencode-go/{}", self.model);
        let rule = |action, resource, effect| {
            serde_json::json!({
                "action": action, "resource": resource, "effect": effect
            })
        };
        let mut tools = vec![
            "howl_repository_read_file",
            "howl_repository_list_directory",
        ];
        if editable {
            tools.extend([
                "howl_repository_write_file",
                "howl_repository_delete_file",
                "howl_repository_run_tests",
            ]);
        }
        if work {
            tools.extend(["howl_repository_start_work", "howl_repository_send_peer"]);
        }
        let mut permissions = vec![rule("*", "*", "deny")];
        permissions.extend(tools.iter().map(|name| rule(name, "*", "allow")));
        let mut policies = vec![
            rule("provider.use", "*", "deny"),
            rule("provider.use", "opencode-go", "allow"),
            rule("mcp.use", "*", "deny"),
            rule("mcp.use", "howl_repository", "allow"),
            rule("plugin.use", "*", "deny"),
            rule("skill.use", "*", "deny"),
            rule("websearch.use", "*", "deny"),
            rule("tool.use", "*", "deny"),
        ];
        policies.extend(tools.iter().map(|name| {
            let resource = format!("{name}:*");
            serde_json::json!({"action":"tool.use","resource":resource,"effect":"allow"})
        }));
        let config = serde_json::json!({
            "model": model,
            "small_model": model,
            "update": "disable",
            "automations": false,
            "share": "disabled",
            "default_agent": "howl_repository",
            "agent": {
                "howl_repository": {
                    "description": "Reviews the repository through Howl's Docker tools",
                    "mode": "primary",
                    "permissions": permissions
                }
            },
            "permissions": permissions,
            "policies": policies
        });
        launch(&self.opencode, &self.node, scratch, cwd, &home, |command| {
            configure(command);
            command
                .arg("acp")
                .env("OPENCODE_CONFIG_CONTENT", config.to_string());
        })
    }
}

pub(super) enum HostAgent {
    Claude(HostClaude),
    Grok(HostGrok),
    Codex(HostCodex),
    OpenCode(HostOpenCode),
}

impl HostAgent {
    pub(super) fn node(&self) -> &Path {
        match self {
            Self::Claude(agent) => agent.node(),
            Self::Grok(agent) => &agent.node,
            Self::Codex(agent) => &agent.node,
            Self::OpenCode(agent) => &agent.node,
        }
    }

    pub(super) fn fingerprint(&self, hash: &mut Sha256) {
        match self {
            Self::Claude(agent) => agent.fingerprint(hash),
            Self::Grok(agent) => agent.fingerprint(hash),
            Self::Codex(agent) => agent.fingerprint(hash),
            Self::OpenCode(agent) => agent.fingerprint(hash),
        }
    }

    pub(super) fn uses_http(&self) -> bool {
        matches!(self, Self::Codex(_))
    }

    pub(super) fn start(
        self,
        repository: Option<&RepositoryHttp>,
        editable: bool,
        work: bool,
    ) -> Result<HostProcess> {
        match self {
            Self::Claude(agent) => agent.start(editable, work),
            Self::Grok(agent) => agent.start(editable, work),
            Self::Codex(agent) => agent.start(repository.ok_or(Error::HostAgent)?, editable, work),
            Self::OpenCode(agent) => agent.start(editable, work),
        }
    }
}

fn launch(
    program: &Path,
    node: &Path,
    scratch: tempfile::TempDir,
    cwd: PathBuf,
    home: &Path,
    configure: impl FnOnce(&mut Command),
) -> Result<HostProcess> {
    let node_directory = node.parent().ok_or(Error::HostAgent)?;
    let path = env::join_paths([
        node_directory,
        Path::new("/opt/homebrew/bin"),
        Path::new("/usr/local/bin"),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .map_err(|_| Error::HostAgent)?;
    let mut command = Command::new(program);
    command
        .current_dir(&cwd)
        .env_clear()
        .env("HOME", home)
        .env("TMPDIR", fs::canonicalize(scratch.path())?)
        .env("PATH", path)
        .env("HOWL_AGENT_CWD", &cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    configure(&mut command);
    let child = command.spawn()?;
    Ok(HostProcess {
        child,
        cwd,
        _scratch: scratch,
    })
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
