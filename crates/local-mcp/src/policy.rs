use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

use rustix::{
    fs::{Mode, OFlags, open},
    process::geteuid,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{AgentPrincipal, Call, Communications, Failure, Reply, Tool, model::valid_id};

const MAX_DISCOVERY_RESULTS: usize = 128;

#[derive(Clone, Default)]
pub struct Scope {
    pub tools: BTreeSet<Tool>,
    pub channels: BTreeMap<Tool, BTreeSet<String>>,
    pub agents: BTreeMap<Tool, BTreeSet<String>>,
}

#[derive(Clone)]
pub struct Credential(Arc<Zeroizing<[u8; 32]>>);

impl Credential {
    pub fn read_file(path: &Path) -> io::Result<Self> {
        let mut file = File::from(open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() != 32
        {
            return Err(permission("credential file must be a private 32-byte file"));
        }
        check_acl(path)?;
        let named = path.symlink_metadata()?;
        if named.ino() != metadata.ino() || named.dev() != metadata.dev() {
            return Err(permission("credential file changed while opening"));
        }
        let mut bytes = Zeroizing::new([0; 32]);
        file.read_exact(&mut *bytes)?;
        if file.read(&mut [0])? != 0 {
            return Err(permission("invalid credential size"));
        }
        Ok(Self(Arc::new(bytes)))
    }

    pub fn write_new_file(&self, path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let written = check_acl(path)
            .and_then(|()| file.write_all(self.bytes()))
            .and_then(|()| file.sync_all());
        if written.is_err() {
            let _ = std::fs::remove_file(path);
        }
        written
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn check_acl(_path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    if !exacl::getfacl(_path, Some(exacl::AclOption::SYMLINK_ACL))?.is_empty() {
        return Err(permission("IPC path must not have an extended ACL"));
    }
    Ok(())
}

pub(crate) fn permission(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[derive(Clone)]
pub struct Authority(Arc<Mutex<Policy>>);

impl Authority {
    pub(crate) fn new(backend: impl Communications) -> Self {
        Self(Arc::new(Mutex::new(Policy {
            sessions: HashMap::new(),
            credentials: HashMap::new(),
            backend: Box::new(backend),
        })))
    }

    pub fn activate_session(&self, session: &str, generation: u64) -> io::Result<()> {
        let mut policy = self
            .0
            .lock()
            .map_err(|_| io::Error::other(Failure::Unavailable))?;
        if !valid_id(session)
            || generation == 0
            || policy
                .sessions
                .get(session)
                .is_some_and(|current| generation <= current.generation)
        {
            return Err(permission("invalid session generation"));
        }
        policy.sessions.insert(
            session.to_owned(),
            Session {
                generation,
                active: true,
            },
        );
        policy
            .credentials
            .retain(|_, grant| grant.principal.session != session);
        Ok(())
    }

    pub fn close_session(&self, session: &str, generation: u64) -> io::Result<()> {
        let mut policy = self
            .0
            .lock()
            .map_err(|_| io::Error::other(Failure::Unavailable))?;
        let current = policy
            .sessions
            .get_mut(session)
            .filter(|current| current.generation == generation)
            .ok_or_else(|| permission("unknown session generation"))?;
        current.active = false;
        policy
            .credentials
            .retain(|_, grant| grant.principal.session != session);
        Ok(())
    }

    pub fn issue(&self, principal: AgentPrincipal, scope: Scope) -> io::Result<Credential> {
        let mut policy = self
            .0
            .lock()
            .map_err(|_| io::Error::other(Failure::Unavailable))?;
        if !valid_id(&principal.agent)
            || !policy.is_active(&principal)
            || !scope.channels.values().flatten().all(|id| valid_id(id))
            || !scope.agents.values().flatten().all(|id| valid_id(id))
        {
            return Err(permission("invalid agent grant"));
        }

        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *bytes).map_err(io::Error::other)?;
        let key = credential_id(&bytes);
        if policy.credentials.contains_key(&key) {
            return Err(io::Error::other("credential collision"));
        }
        policy.credentials.insert(key, Grant { principal, scope });
        Ok(Credential(Arc::new(bytes)))
    }

    pub fn revoke(&self, credential: &Credential) -> io::Result<bool> {
        let mut policy = self
            .0
            .lock()
            .map_err(|_| io::Error::other(Failure::Unavailable))?;
        Ok(policy
            .credentials
            .remove(&credential_id(credential.bytes()))
            .is_some())
    }

    pub(crate) fn dispatch(
        &self,
        credential: &[u8; 32],
        call: Call,
        deadline: Instant,
    ) -> Result<Reply, Failure> {
        let mut policy = self.0.lock().map_err(|_| Failure::Unavailable)?;
        if Instant::now() >= deadline {
            return Err(Failure::Unavailable);
        }
        policy.dispatch(credential, call)
    }
}

struct Grant {
    principal: AgentPrincipal,
    scope: Scope,
}

struct Session {
    generation: u64,
    active: bool,
}

struct Policy {
    sessions: HashMap<String, Session>,
    credentials: HashMap<[u8; 32], Grant>,
    backend: Box<dyn Communications>,
}

impl Policy {
    fn is_active(&self, principal: &AgentPrincipal) -> bool {
        self.sessions
            .get(&principal.session)
            .is_some_and(|session| session.active && session.generation == principal.generation)
    }

    fn dispatch(&mut self, credential: &[u8; 32], call: Call) -> Result<Reply, Failure> {
        let grant = self
            .credentials
            .get(&credential_id(credential))
            .ok_or(Failure::Denied)?;
        let tool = call.tool();
        if !self.is_active(&grant.principal) || !grant.scope.tools.contains(&tool) {
            return Err(Failure::Denied);
        }
        call.validate()?;
        let allowed_channel = |id: &str| {
            grant
                .scope
                .channels
                .get(&tool)
                .is_some_and(|ids| ids.contains(id))
        };
        let allowed_agent = |id: &str| {
            grant
                .scope
                .agents
                .get(&tool)
                .is_some_and(|ids| ids.contains(id))
        };
        if call
            .channel()
            .is_some_and(|channel| !allowed_channel(channel))
            || matches!(&call, Call::Dm(args) if !allowed_agent(&args.agent))
        {
            return Err(Failure::Denied);
        }

        if matches!(call, Call::Status(_)) {
            return Ok(Reply::Status {
                principal: grant.principal.clone(),
            });
        }
        let reply = self.backend.invoke(&grant.principal, &call)?;
        match (call, reply) {
            (Call::ListAgents(_), Reply::Agents { mut agents }) => {
                agents.retain(|agent| allowed_agent(&agent.id));
                agents.truncate(MAX_DISCOVERY_RESULTS);
                Ok(Reply::Agents { agents })
            }
            (Call::ListChannels(_), Reply::Channels { mut channels }) => {
                channels.retain(|channel| allowed_channel(&channel.id));
                channels.truncate(MAX_DISCOVERY_RESULTS);
                Ok(Reply::Channels { channels })
            }
            (Call::Read(args), Reply::Messages { mut messages }) => {
                messages.retain(|message| message.channel == args.channel);
                messages.truncate(args.limit());
                Ok(Reply::Messages { messages })
            }
            (Call::Post(_) | Call::Dm(_), Reply::Posted { id }) if valid_id(&id) => {
                Ok(Reply::Posted { id })
            }
            (Call::Pass(_), Reply::Passed) => Ok(Reply::Passed),
            _ => Err(Failure::Unavailable),
        }
    }
}

fn credential_id(secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(secret).into()
}
