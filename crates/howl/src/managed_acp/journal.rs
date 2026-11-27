use std::{
    fs::{self, DirBuilder, File},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{Mode, OFlags, open, openat},
    process::geteuid,
};
use tokio::sync::watch;

use super::{Error, Result, SessionState};

pub(super) struct Journal {
    root_path: PathBuf,
    directory: File,
    lock: File,
    file_name: String,
    status: watch::Sender<SessionState>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.lock.unlock();
    }
}

impl Journal {
    pub(super) fn new(root: &Path, state: SessionState) -> Result<Self> {
        let journal = Self::open(root, state)?;
        journal.write(&journal.status.borrow(), true)?;
        Ok(journal)
    }

    pub(super) fn existing(root: &Path, expected: SessionState) -> Result<Self> {
        let mut journal = Self::open(root, expected.clone())?;
        let old = read_state(&journal.directory, &journal.file_name)?;
        if old.id != expected.id
            || old.engine != expected.engine
            || old.commit != expected.commit
            || old.snapshot != expected.snapshot
            || old.profile != expected.profile
            || old.harness != expected.harness
        {
            return Err(Error::ScopeChanged);
        }
        journal.status = watch::channel(old).0;
        Ok(journal)
    }

    pub(super) fn reap_observers(
        root: &Path,
        provider: &crate::observer::ObserverProvider,
    ) -> Result<()> {
        let directory = match open_private_directory(root) {
            Ok(directory) => directory,
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
                continue;
            };
            if !valid_id(id) {
                continue;
            }
            let state = read_state(&directory, &format!("{id}.json"))?;
            if state.id != id {
                return Err(Error::ScopeChanged);
            }
            if state.phase == super::Phase::Closed && state.container.is_none() {
                continue;
            }
            if state.engine != provider.engine_id() {
                return Err(Error::ScopeChanged);
            }
            let journal = Self::existing(root, state)?;
            provider.reap_managed(id)?;
            journal.update(|state| {
                state.container = None;
                if state.phase != super::Phase::Closed {
                    state.phase = super::Phase::Interrupted;
                }
            })?;
        }
        Ok(())
    }

    fn open(root: &Path, state: SessionState) -> Result<Self> {
        match DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {
                let parent = root
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                File::open(parent)?.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let directory = open_private_directory(root)?;
        let lock = File::from(
            openat(
                &directory,
                format!("{}.lock", state.id).as_str(),
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(io::Error::from)?,
        );
        check_private(&lock, false)?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => Error::InUse,
            std::fs::TryLockError::Error(error) => error.into(),
        })?;
        let file_name = format!("{}.json", state.id);
        let (status, _) = watch::channel(state);
        Ok(Self {
            root_path: root.to_owned(),
            directory,
            lock,
            file_name,
            status,
        })
    }

    pub(super) fn state(&self) -> SessionState {
        self.status.borrow().clone()
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<SessionState> {
        self.status.subscribe()
    }

    pub(super) fn update(&self, change: impl FnOnce(&mut SessionState)) -> Result<()> {
        let mut state = self.state();
        change(&mut state);
        self.write(&state, false)?;
        self.status.send_replace(state);
        Ok(())
    }

    fn write(&self, state: &SessionState, new: bool) -> Result<()> {
        let mut staged = tempfile::NamedTempFile::new_in(&self.root_path)?;
        serde_json::to_writer(&mut staged, state).map_err(|_| Error::State)?;
        staged.flush()?;
        staged.as_file().sync_all()?;
        let path = self.root_path.join(&self.file_name);
        if new {
            staged
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        } else {
            staged.persist(path).map_err(|error| error.error)?;
        }
        self.directory.sync_all()?;
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn open_private_directory(root: &Path) -> Result<File> {
    let directory = File::from(
        open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    check_private(&directory, true)?;
    Ok(directory)
}

fn read_state(directory: &File, name: &str) -> Result<SessionState> {
    let file = File::from(
        openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    check_private(&file, false)?;
    let mut data = Vec::new();
    file.take(16_385).read_to_end(&mut data)?;
    if data.len() > 16_384 {
        return Err(Error::State);
    }
    serde_json::from_slice(&data).map_err(|_| Error::State)
}

fn check_private(file: &File, directory: bool) -> Result<()> {
    let metadata: fs::Metadata = file.metadata()?;
    if metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || !(if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        })
    {
        return Err(Error::State);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_acp::{Capabilities, Phase};

    #[test]
    fn persists_state_and_excludes_other_writers() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("managed");
        let fixture = SessionState {
            id: "0123456789abcdef0123456789abcdef".into(),
            harness: "fixture".into(),
            commit: "fixture-commit".into(),
            snapshot: [12; 32],
            profile: [13; 32],
            engine: "fixture-engine".into(),
            remote_session: None,
            container: None,
            capabilities: Capabilities::default(),
            protocol_version: None,
            phase: Phase::Starting,
        };
        let open = Journal::new(&directory, fixture.clone()).unwrap();
        assert!(matches!(
            Journal::existing(&directory, fixture.clone()),
            Err(Error::InUse)
        ));
        open.update(|state| {
            state.remote_session = Some("fixture-session".to_owned());
            state.phase = Phase::Active;
        })
        .unwrap();
        drop(open);
        let reopened = Journal::existing(&directory, fixture.clone()).unwrap();
        assert_eq!(reopened.state().phase, Phase::Active);
        assert_eq!(
            reopened.state().remote_session.as_deref(),
            Some("fixture-session")
        );
        drop(reopened);
        let mut other = fixture;
        other.engine = "different-engine".into();
        assert!(matches!(
            Journal::existing(&directory, other),
            Err(Error::ScopeChanged)
        ));
    }
}
