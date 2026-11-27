use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use howl_envelope::Id;
use serde::{Deserialize, Serialize};

use crate::{identity::StateDirectory, observer::Snapshot};

pub const PREFIX: &str = "howl-repo:";

#[derive(Clone, Deserialize, Serialize)]
pub struct Project {
    pub root: PathBuf,
    pub commit: String,
    pub selection: String,
}

impl Project {
    pub fn select(state: &Path, channel: Id, root: &Path) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        let snapshot = Snapshot::from_repository(&root, "HEAD").map_err(io::Error::other)?;
        let project = Self {
            root,
            commit: snapshot.commit().to_owned(),
            selection: hex::encode(snapshot.selection()),
        };
        let directory = StateDirectory::open(state)?;
        let data = serde_json::to_vec(&project)?;
        directory.replace(
            &format!(
                "project-{}-{}.json",
                hex::encode(channel),
                project.selection
            ),
            &data,
        )?;
        directory.replace(&format!("project-{}.json", hex::encode(channel)), &data)?;
        Ok(project)
    }

    pub fn instruction(&self, text: &str) -> String {
        format!("{PREFIX}{}\n{text}", self.selection)
    }

    pub fn clear(state: &Path, channel: Id) -> io::Result<()> {
        StateDirectory::open(state)?
            .replace(&format!("project-{}.json", hex::encode(channel)), b"null")
    }

    pub fn load(state: &Path, channel: Id) -> io::Result<Self> {
        let bytes = StateDirectory::open(state)?
            .read_bounded(&format!("project-{}.json", hex::encode(channel)), 8192)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

pub fn wake(text: &str) -> Option<(&str, &str)> {
    let (header, prompt) = text.split_once('\n')?;
    let selection = header.strip_prefix(PREFIX)?;
    (selection.len() == 64
        && selection.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !prompt.trim().is_empty())
    .then_some((selection, prompt))
}

#[derive(Deserialize)]
struct Change {
    path: PathBuf,
    before: Option<Version>,
    after: Option<Version>,
}

#[derive(Deserialize)]
struct Version {
    content: String,
    executable: bool,
}

pub fn patch(changes: serde_json::Value) -> io::Result<(usize, Vec<u8>)> {
    let changes: Vec<Change> = serde_json::from_value(changes)?;
    let directory = tempfile::tempdir()?;
    let before = directory.path().join("a");
    let after = directory.path().join("b");
    fs::create_dir(&before)?;
    fs::create_dir(&after)?;
    for change in &changes {
        if change.path.as_os_str().is_empty()
            || change.path.components().any(|part| {
                let std::path::Component::Normal(name) = part else {
                    return true;
                };
                name.to_str().is_none_or(|name| {
                    name.starts_with('.')
                        || name.contains([':', '\\'])
                        || name.chars().any(char::is_control)
                })
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Docker change path",
            ));
        }
        for (root, version) in [(&before, &change.before), (&after, &change.after)] {
            if let Some(version) = version {
                let path = root.join(&change.path);
                fs::create_dir_all(
                    path.parent()
                        .ok_or_else(|| io::Error::other("Missing change parent"))?,
                )?;
                fs::write(&path, &version.content)?;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if version.executable { 0o755 } else { 0o644 }),
                )?;
            }
        }
    }
    let diff = Command::new("git")
        .env_clear()
        .env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CEILING_DIRECTORIES", directory.path())
        .current_dir(directory.path())
        .args([
            "-c",
            "core.fileMode=true",
            "diff",
            "--no-index",
            "--no-prefix",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--",
            "a",
            "b",
        ])
        .output()?;
    if !matches!(diff.status.code(), Some(0 | 1)) {
        return Err(io::Error::other(
            "Could not generate the Docker workspace patch",
        ));
    }
    Ok((changes.len(), diff.stdout))
}
