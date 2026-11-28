use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{io::AsyncReadExt, process::Command, time::timeout};
use zeroize::Zeroizing;

use super::{Error, Result};

const ACCESS_TOKEN_LIMIT: usize = 16 * 1024;

pub struct ChatGptPlanAuth {
    node: PathBuf,
    script: PathBuf,
    store: PathBuf,
}

impl ChatGptPlanAuth {
    pub fn new(node: PathBuf, script: PathBuf, store: PathBuf) -> Result<Self> {
        if !node.is_absolute() || !script.is_absolute() || !store.is_absolute() {
            return Err(Error::ChatGptAuth);
        }
        Ok(Self {
            node,
            script,
            store,
        })
    }

    pub(super) fn store(&self) -> &Path {
        &self.store
    }

    pub(crate) async fn access_token(&self) -> Result<Zeroizing<String>> {
        timeout(Duration::from_secs(25), self.read_token())
            .await
            .map_err(|_| Error::ChatGptAuth)?
    }

    async fn read_token(&self) -> Result<Zeroizing<String>> {
        let mut child = Command::new(&self.node)
            .arg(&self.script)
            .arg("token")
            .arg(&self.store)
            .current_dir("/")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Error::ChatGptAuth)?;
        let stdout = child.stdout.take().ok_or(Error::ChatGptAuth)?;
        let mut bytes = Zeroizing::new(Vec::new());
        stdout
            .take(ACCESS_TOKEN_LIMIT as u64 + 2)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Error::ChatGptAuth)?;
        let token = bytes
            .strip_suffix(b"\n")
            .filter(|token| {
                !token.is_empty()
                    && token.len() <= ACCESS_TOKEN_LIMIT
                    && token.iter().all(u8::is_ascii_graphic)
            })
            .and_then(|token| std::str::from_utf8(token).ok())
            .ok_or(Error::ChatGptAuth)?;
        let status = child.wait().await.map_err(|_| Error::ChatGptAuth)?;
        if !status.success() {
            return Err(Error::ChatGptAuth);
        }
        Ok(Zeroizing::new(token.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_only_one_token_from_a_successful_helper() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("fixture.sh");
        let auth =
            ChatGptPlanAuth::new("/bin/sh".into(), helper.clone(), dir.path().into()).unwrap();
        std::fs::write(&helper, "echo synthetic-token\n").unwrap();
        assert_eq!(&**auth.access_token().await.unwrap(), "synthetic-token");
        for script in [
            "echo synthetic-token; exit 1",
            "echo synthetic-token; echo unexpected",
            "echo 'synthetic token'",
        ] {
            std::fs::write(&helper, script).unwrap();
            assert!(matches!(auth.access_token().await, Err(Error::ChatGptAuth)));
        }
    }
}
