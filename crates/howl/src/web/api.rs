use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use howl_envelope::{AgentRole, Body, Id};
use serde::Deserialize;
use serde_json::{Value, json};

use super::Web;
use crate::{
    channel::{Channel, MAX_MANIFEST_LEN},
    identity::{LocalIdentity, PeerCertificate, PeerTrust, StateDirectory},
    node,
    observer::Snapshot,
    workflow,
};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Overview,
    Create {
        peers: Vec<String>,
    },
    Join {
        manifest: String,
    },
    Pair {
        certificate: String,
        fingerprint: String,
    },
    Conversation {
        channel: String,
    },
    Search {
        channel: String,
        query: String,
    },
    Delivery {
        channel: String,
        message: String,
    },
    Pause {
        channel: String,
        root: String,
    },
    Send {
        channel: String,
        peer: String,
        route: String,
        text: String,
    },
    Wake {
        channel: String,
        peer: String,
        route: String,
        text: String,
        target: String,
        lifetime: u16,
    },
    Grant {
        channel: String,
        peer: String,
        role: Role,
        generation: u64,
    },
    Repository {
        repository: PathBuf,
        commit: String,
        paths: Vec<PathBuf>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Role {
    Architect,
    Reviewer,
}

impl From<Role> for AgentRole {
    fn from(role: Role) -> Self {
        match role {
            Role::Architect => Self::Architect,
            Role::Reviewer => Self::Reviewer,
        }
    }
}

pub(super) async fn command(State(web): State<Arc<Web>>, Json(input): Json<Command>) -> Response {
    match execute(web, input).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            let status = match error.kind() {
                io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => StatusCode::BAD_REQUEST,
                io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
                io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(json!({ "error": error.to_string() }))).into_response()
        }
    }
}

async fn execute(web: Arc<Web>, input: Command) -> io::Result<Value> {
    let state = &web.directory;
    let receipt = match input {
        Command::Send {
            channel,
            peer,
            route,
            text,
        } => node::send(state, id(&channel)?, id(&peer)?, &route, &text).await?,
        Command::Wake {
            channel,
            peer,
            route,
            text,
            target,
            lifetime,
        } => {
            node::send_wake(
                state,
                id(&channel)?,
                id(&peer)?,
                &route,
                id(&target)?,
                lifetime,
                &text,
            )
            .await?
        }
        Command::Grant {
            channel,
            peer,
            role,
            generation,
        } => {
            let target = workflow::agent_id(state, role.into())?;
            node::grant_wake(state, id(&channel)?, id(&peer)?, target, generation).await?;
            return Ok(json!({ "target": hex::encode(target) }));
        }
        input => {
            return tokio::task::spawn_blocking(move || execute_local(&web.directory, input))
                .await
                .map_err(io::Error::other)?;
        }
    };
    let message = receipt
        .strip_prefix("queued ")
        .ok_or_else(|| io::Error::other("Invalid mesh receipt"))?;
    id(message)?;
    Ok(json!({ "message": message }))
}

fn execute_local(state: &Path, input: Command) -> io::Result<Value> {
    let identity = LocalIdentity::load_or_create(state)?;
    let local = identity.certificate();
    match input {
        Command::Overview => overview(state, &identity),
        Command::Create { peers } => {
            let peers = peers
                .iter()
                .map(|peer| id(peer))
                .collect::<io::Result<Vec<_>>>()?;
            Ok(channel_view(&Channel::create(state, &identity, &peers)?))
        }
        Command::Join { manifest } => {
            if manifest.len() > MAX_MANIFEST_LEN * 2 {
                return Err(invalid("Channel manifest is too large"));
            }
            let manifest =
                hex::decode(manifest.trim()).map_err(|_| invalid("Invalid channel manifest"))?;
            Ok(channel_view(&Channel::join(state, &identity, &manifest)?))
        }
        Command::Pair {
            certificate,
            fingerprint,
        } => {
            let mut bytes = [0; crate::identity::CERTIFICATE_LEN];
            hex::decode_to_slice(certificate.trim(), &mut bytes)
                .map_err(|_| invalid("Invalid peer certificate"))?;
            let peer = PeerCertificate::from_bytes(bytes)?;
            PeerTrust::open(state)?.pin(&peer, &id(&fingerprint)?)?;
            Ok(device_view(&peer))
        }
        Command::Pause { channel, root } => {
            workflow::pause(state, id(&channel)?, id(&root)?)?;
            Ok(json!({ "paused": true }))
        }
        Command::Repository {
            repository,
            commit,
            paths,
        } => {
            if !repository.is_absolute() {
                return Err(invalid("Enter an absolute repository path"));
            }
            let snapshot = Snapshot::from_commit(&repository, &commit, &paths)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            Ok(
                json!({ "commit": snapshot.commit(), "selection": hex::encode(snapshot.selection()) }),
            )
        }
        Command::Conversation { channel } => {
            let channel = *Channel::load(state, &identity, &id(&channel)?)?.id();
            let delivery = node::open_delivery(state, &StateDirectory::open(state)?, &local)?;
            let messages = delivery
                .channel_history(channel, 100)
                .map_err(io::Error::other)?
                .into_iter()
                .rev()
                .filter_map(|item| {
                    let (text, role) = match item.body {
                        Body::Chat(text) => (text, None),
                        Body::AgentReply(reply) => (reply.text, Some(reply.role.name())),
                        Body::Wake { .. } => return None,
                    };
                    Some(json!({
                        "message": hex::encode(item.message),
                        "sender": hex::encode(item.sender.device),
                        "time": item.received_at,
                        "text": text,
                        "role": role,
                    }))
                })
                .collect::<Vec<_>>();
            let work = delivery
                .workflow_status(channel, node::unix_time()?)
                .map_err(io::Error::other)?;
            Ok(json!({ "messages": messages, "work": work }))
        }
        Command::Search { channel, query } => {
            let channel = *Channel::load(state, &identity, &id(&channel)?)?.id();
            let query = query.trim();
            if query.is_empty() || query.len() > 256 || query.contains('\0') {
                return Err(invalid("Enter a search phrase up to 256 bytes"));
            }
            let delivery = node::open_delivery(state, &StateDirectory::open(state)?, &local)?;
            let phrase = format!("\"{}\"", query.replace('"', "\"\""));
            let messages = delivery
                .search_chat(channel, &phrase, 100)
                .map_err(io::Error::other)?;
            Ok(json!({ "matches": messages }))
        }
        Command::Delivery { channel, message } => {
            let channel = *Channel::load(state, &identity, &id(&channel)?)?.id();
            let delivery = node::open_delivery(state, &StateDirectory::open(state)?, &local)?;
            let items = delivery
                .delivery_status(node::local_stream(channel, &local), id(&message)?)
                .map_err(io::Error::other)?
                .into_iter()
                .map(|item| {
                    json!({
                        "device": hex::encode(item.recipient.device),
                        "attempts": item.attempts,
                        "acknowledged": item.acknowledged,
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({ "recipients": items }))
        }
        Command::Send { .. } | Command::Wake { .. } | Command::Grant { .. } => {
            Err(io::Error::other("Invalid local command"))
        }
    }
}

fn overview(state: &Path, identity: &LocalIdentity) -> io::Result<Value> {
    let local = identity.certificate();
    let trust = PeerTrust::open(state)?;
    let mut channels = Vec::new();
    let mut peers = Vec::new();
    for entry in fs::read_dir(state)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(name) = filename.to_str() else {
            continue;
        };
        if let Some(channel) = name
            .strip_prefix("channel-")
            .and_then(|value| id(value).ok())
        {
            channels.push(channel_view(&Channel::load(state, identity, &channel)?));
        } else if let Ok(device) = id(name) {
            peers.push(device_view(&trust.pinned(&device)?));
        }
    }
    channels.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    peers.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let agents = [AgentRole::Architect, AgentRole::Reviewer].map(
        |role| json!({ "role": role.name(), "id": hex::encode(role.agent_id(local.device_id())) }),
    );
    Ok(json!({
        "local": device_view(&local),
        "channels": channels,
        "peers": peers,
        "agents": agents,
    }))
}

fn channel_view(channel: &Channel) -> Value {
    let members = channel
        .members()
        .iter()
        .map(|member| hex::encode(member.device_id()))
        .collect::<Vec<_>>();
    json!({ "id": hex::encode(channel.id()), "manifest": hex::encode(channel.manifest()), "members": members })
}

fn device_view(certificate: &PeerCertificate) -> Value {
    json!({
        "id": hex::encode(certificate.device_id()),
        "certificate": hex::encode(certificate.as_bytes()),
        "fingerprint": hex::encode(certificate.fingerprint()),
    })
}

fn id(text: &str) -> io::Result<Id> {
    let mut id = [0; 32];
    hex::decode_to_slice(text.trim(), &mut id).map_err(|_| invalid("Invalid hexadecimal ID"))?;
    Ok(id)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
