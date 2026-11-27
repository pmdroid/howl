use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{Error, Result, digest, process_error};

const MAX_PATHS: usize = 256;
const MAX_FILE: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOT: usize = 16 * 1024 * 1024;

pub struct Snapshot {
    pub(super) directory: TempDir,
    commit: String,
    selection: [u8; 32],
}

impl Snapshot {
    pub fn from_commit(repository: &Path, revision: &str, paths: &[PathBuf]) -> Result<Self> {
        if paths.is_empty() || paths.len() > MAX_PATHS || revision.len() > 1024 {
            return Err(Error::InvalidSnapshot);
        }

        let mut entries = BTreeMap::new();
        for path in paths {
            let path = selected_path(path)?;
            if entries.insert(path, String::new()).is_some() {
                return Err(Error::InvalidSnapshot);
            }
        }

        let repository = repository_root(repository)?;
        let revision = format!("{revision}^{{commit}}");
        let mut resolve = git(&repository);
        resolve.args(["rev-parse", "--verify", "--end-of-options", &revision]);
        let commit = run_git(resolve)?;
        let commit = str::from_utf8(&commit)
            .map_err(|_| Error::InvalidSnapshot)?
            .trim()
            .to_owned();
        if !digest(&commit, &[40, 64]) {
            return Err(Error::InvalidSnapshot);
        }

        let mut list = git(&repository);
        list.args(["ls-tree", "-z", "--full-tree", &commit, "--"])
            .args(entries.keys());
        let output = run_git(list)?;
        if output.last() != Some(&0) {
            return Err(Error::InvalidSnapshot);
        }
        for entry in output[..output.len() - 1].split(|byte| *byte == 0) {
            let record = str::from_utf8(entry).map_err(|_| Error::InvalidSnapshot)?;
            let (object, path) = record.split_once('\t').ok_or(Error::InvalidSnapshot)?;
            let mut fields = object.split(' ');
            let (Some("100644" | "100755"), Some("blob"), Some(hash), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(Error::UnsafePath(PathBuf::from(path)));
            };
            let slot = entries.get_mut(path).ok_or(Error::InvalidSnapshot)?;
            if !digest(hash, &[commit.len()]) || !slot.is_empty() {
                return Err(Error::InvalidSnapshot);
            }
            *slot = hash.to_owned();
        }
        if entries.values().any(String::is_empty) {
            return Err(Error::InvalidSnapshot);
        }

        let mut selection = Sha256::new();
        selection.update(b"howl/snapshot/v1\0");
        selection.update([commit.len() as u8]);
        selection.update(commit.as_bytes());
        for (path, hash) in &entries {
            selection.update((path.len() as u16).to_be_bytes());
            selection.update(path.as_bytes());
            selection.update(hash.as_bytes());
        }
        let selection = selection.finalize().into();
        let directory = tempfile::Builder::new()
            .prefix("howl-snapshot-")
            .tempdir()?;
        let tree = directory.path().join("tree");
        fs::create_dir(&tree)?;
        fs::set_permissions(&tree, fs::Permissions::from_mode(0o755))?;
        materialize(&repository, &tree, entries)?;
        Ok(Self {
            directory,
            commit,
            selection,
        })
    }

    pub fn selection(&self) -> [u8; 32] {
        self.selection
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }
}

fn repository_root(path: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(path)?;
    let mut kind = git(&root);
    kind.args(["rev-parse", "--is-bare-repository"]);
    let flag = match run_git(kind)?.as_slice() {
        b"true\n" => "--absolute-git-dir",
        b"false\n" => "--show-toplevel",
        _ => return Err(Error::InvalidSnapshot),
    };
    let mut location = git(&root);
    location.args(["rev-parse", flag]);
    let output = run_git(location)?;
    let output = output.strip_suffix(b"\n").ok_or(Error::InvalidSnapshot)?;
    let reported = Path::new(std::ffi::OsStr::from_bytes(output));
    if fs::canonicalize(reported)? != root {
        return Err(Error::InvalidSnapshot);
    }
    Ok(root)
}

fn selected_path(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| Error::UnsafePath(path.into()))?;
    if text.is_empty()
        || text.len() > 512
        || text.contains(['\\', ':'])
        || text.chars().any(char::is_control)
        || text
            .split('/')
            .any(|segment| segment.is_empty() || segment.starts_with('.'))
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(Error::UnsafePath(path.into()));
    }

    for segment in text.split('/') {
        let lower = segment.to_ascii_lowercase();
        let stem = lower.split('.').next().unwrap_or_default();
        if matches!(
            stem,
            "secret"
                | "secrets"
                | "credential"
                | "credentials"
                | "token"
                | "tokens"
                | "passwords"
                | "kubeconfig"
                | "known_hosts"
                | "id_rsa"
                | "id_dsa"
                | "id_ed25519"
        ) || [".pem", ".key", ".pfx", ".p12", ".jks", ".keystore"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        {
            return Err(Error::UnsafePath(path.into()));
        }
    }
    Ok(text)
}

fn materialize(repository: &Path, target: &Path, entries: BTreeMap<&str, String>) -> Result<()> {
    let mut child = git(repository)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut input = child.stdin.take().ok_or(Error::InvalidSnapshot)?;
    let mut output = BufReader::new(child.stdout.take().ok_or(Error::InvalidSnapshot)?);
    let result = (|| -> Result<()> {
        let mut total = 0;
        let mut header = String::new();
        for (path, hash) in entries {
            writeln!(input, "{hash}")?;
            input.flush()?;
            header.clear();
            output.read_line(&mut header)?;
            let mut fields = header.trim_end().split(' ');
            let (Some(returned), Some("blob"), Some(size), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(Error::InvalidSnapshot);
            };
            let size = size.parse::<usize>().map_err(|_| Error::InvalidSnapshot)?;
            if returned != hash || size > MAX_FILE || total + size > MAX_SNAPSHOT {
                return Err(Error::InvalidSnapshot);
            }
            total += size;

            let mut body = vec![0; size];
            output.read_exact(&mut body)?;
            let mut delimiter = [0];
            output.read_exact(&mut delimiter)?;
            if delimiter != *b"\n" {
                return Err(Error::InvalidSnapshot);
            }
            let text =
                str::from_utf8(&body).map_err(|_| Error::UnsafeContent(PathBuf::from(path)))?;
            if text.contains('\0') || contains_secret(text) {
                return Err(Error::UnsafeContent(PathBuf::from(path)));
            }
            write_file(target, path, &body)?;
        }
        Ok(())
    })();
    drop(input);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    result?;
    if !status.success() {
        return Err(process_error("read snapshot blobs", status));
    }
    Ok(())
}

fn write_file(target: &Path, path: &str, body: &[u8]) -> Result<()> {
    let mut parts = path.split('/').peekable();
    let mut parent = target.to_path_buf();
    while let Some(part) = parts.next() {
        let child = parent.join(part);
        if parts.peek().is_none() {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&child)?;
            file.write_all(body)?;
            file.set_permissions(fs::Permissions::from_mode(0o444))?;
            return Ok(());
        }
        match fs::create_dir(&child) {
            Ok(()) => fs::set_permissions(&child, fs::Permissions::from_mode(0o755))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !fs::read_dir(&parent)?
                    .any(|entry| entry.is_ok_and(|entry| entry.file_name() == part))
                {
                    return Err(Error::UnsafePath(path.into()));
                }
            }
            Err(error) => return Err(error.into()),
        }
        parent = child;
    }
    Err(Error::InvalidSnapshot)
}

fn contains_secret(text: &str) -> bool {
    if text
        .lines()
        .any(|line| line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----"))
    {
        return true;
    }

    if text.lines().any(|line| {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once(['=', ':']) else {
            return false;
        };
        let name = name.trim().trim_matches(['"', '\'']);
        let value = value.trim().trim_matches(['"', '\'', ',', ';']);
        matches!(
            name,
            "AWS_SECRET_ACCESS_KEY"
                | "AWS_SESSION_TOKEN"
                | "OPENAI_API_KEY"
                | "ANTHROPIC_API_KEY"
                | "GITHUB_TOKEN"
                | "GITLAB_TOKEN"
        ) && value.len() >= 12
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/' | b'+')
            })
    }) {
        return true;
    }

    let prefixes = [
        "ghp_",
        "gho_",
        "ghs_",
        "github_pat_",
        "sk-proj-",
        "sk-ant-",
        "xoxb-",
        "xoxp-",
    ];
    prefixes.iter().any(|prefix| {
        text.match_indices(prefix).any(|(position, _)| {
            text.as_bytes()[position + prefix.len()..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                .take(24)
                .count()
                == 24
        })
    })
}

fn git(repository: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", super::TOOL_PATH)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("--literal-pathspecs")
        .arg("-C")
        .arg(repository);
    command
}

fn run_git(mut command: Command) -> Result<Vec<u8>> {
    let output = command.stderr(Stdio::null()).output()?;
    if !output.status.success() {
        return Err(process_error("select tracked snapshot", output.status));
    }
    Ok(output.stdout)
}
