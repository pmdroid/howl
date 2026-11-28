use serde_json::Value;
use std::sync::atomic::{AtomicI64, Ordering};

use super::*;
use crate::{
    delivery::{Work, WorkGrant},
    microvm::Guest,
};

const LIMIT: Duration = Duration::from_secs(900);

pub(crate) struct WorkTools {
    state: PathBuf,
    thread: OngoingThread,
    grant: Option<WorkGrant>,
    peers: Vec<AgentPeer>,
    asking_turn: AtomicI64,
    sending_peer: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartWork {
    request_key: String,
    instruction: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendPeer {
    #[serde(deserialize_with = "decode_id")]
    peer: Id,
    text: String,
    thread: Option<String>,
}

impl WorkTools {
    pub(super) fn new(
        state: PathBuf,
        thread: OngoingThread,
        conversation: &Conversation,
        snapshot: &Snapshot,
        sending_peer: Arc<tokio::sync::Mutex<()>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state,
            thread,
            grant: conversation.work_policy.map(|policy| WorkGrant {
                policy,
                commit: snapshot.commit().to_owned(),
                selection: snapshot.selection(),
            }),
            peers: conversation.peers.clone(),
            asking_turn: AtomicI64::new(0),
            sending_peer,
        })
    }

    pub(crate) fn set_source(&self, source: OngoingSource, turn: i64) {
        self.asking_turn.store(
            if matches!(
                source,
                OngoingSource::DirectMessage | OngoingSource::Schedule
            ) {
                turn
            } else {
                0
            },
            Ordering::Release,
        );
    }

    pub(crate) async fn call(&self, tool: &str, arguments: Value) -> io::Result<String> {
        let turn = self.asking_turn.load(Ordering::Acquire);
        match (tool, &self.grant) {
            ("start_work", Some(grant)) => self
                .start(arguments, grant)
                .map(|id| format!("Work {id} queued.")),
            ("send_peer", _) if turn > 0 => self.send_peer(arguments, turn).await,
            _ => Err(io::ErrorKind::PermissionDenied.into()),
        }
    }

    fn start(&self, arguments: Value, grant: &WorkGrant) -> io::Result<String> {
        let request: StartWork = serde_json::from_value(arguments).map_err(io::Error::other)?;
        if request.request_key.is_empty()
            || request.request_key.len() > 64
            || !request
                .request_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            || request.instruction.trim().is_empty()
            || request.instruction.len() > 8192
        {
            return Err(invalid("invalid work request key or instruction"));
        }
        let mut store = self.authorized_store()?;
        let id = store
            .queue_work(
                self.thread.scope,
                &request.request_key,
                &request.instruction,
                grant,
            )
            .map_err(io::Error::other)?;
        Ok(hex::encode(id))
    }

    async fn send_peer(&self, arguments: Value, turn: i64) -> io::Result<String> {
        let request: SendPeer = serde_json::from_value(arguments).map_err(io::Error::other)?;
        let peer = self
            .peers
            .iter()
            .find(|peer| peer.id == request.peer)
            .ok_or(io::ErrorKind::PermissionDenied)?;
        let text = match request.thread {
            Some(name) if super::valid_thread_name(&name) => {
                format!("/thread {name} {}", request.text)
            }
            Some(_) => return Err(invalid("invalid shared thread name")),
            None => request.text.clone(),
        };
        if request.text.trim().is_empty() || text.len() > 4096 {
            return Err(invalid("invalid peer message"));
        }
        let now = i64::try_from(node::unix_time()?).map_err(io::Error::other)?;
        let _sending = self.sending_peer.lock().await;
        let store = self.authorized_store()?;
        if store
            .peer_pending(self.thread.scope, now)
            .map_err(io::Error::other)?
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        drop(store);
        let receipt = node::send(
            &self.state,
            self.thread.channel,
            request.peer,
            peer.route.as_deref().unwrap_or("-"),
            &text,
        )
        .await?;
        let id = parse_id(
            receipt
                .strip_prefix("queued ")
                .ok_or_else(|| io::Error::other("invalid peer receipt"))?,
        )?;
        self.authorized_store()?
            .expect_peer_reply(
                self.thread.scope,
                id,
                request.peer,
                now.saturating_add(300),
                turn,
            )
            .map_err(io::Error::other)?;
        Ok(format!("Peer message {} queued.", hex::encode(id)))
    }

    fn authorized_store(&self) -> io::Result<DeliveryStore> {
        let identity = LocalIdentity::load_or_create(&self.state)?;
        let roster = Channel::load(&self.state, &identity, &self.thread.channel)?;
        let local = identity.certificate();
        let allowed = [ChannelPermission::Receive, ChannelPermission::Send]
            .into_iter()
            .all(|permission| {
                roster.allows(local.device_id(), permission)
                    && roster.allows(&self.thread.peer.device, permission)
            });
        if roster.epoch() != self.thread.epoch || !allowed {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let directory = StateDirectory::open(&self.state)?;
        node::open_delivery(&self.state, &directory, &local)
    }
}

pub(super) fn command(
    delivery: &DeliveryStore,
    scope: Id,
    text: &str,
) -> io::Result<Option<String>> {
    let mut arguments = text.trim().splitn(3, char::is_whitespace);
    let operation = match arguments.next() {
        Some(operation @ ("/work" | "/steer" | "/cancel")) => operation,
        _ => return Ok(None),
    };
    let Some((encoded, id)) = arguments
        .next()
        .and_then(|argument| parse_id(argument).ok().map(|id| (argument, id)))
    else {
        return Ok(Some(
            "Use /work RUN, /steer RUN MESSAGE or /cancel RUN.".into(),
        ));
    };
    let feedback = arguments.next().map(str::trim).unwrap_or_default();
    let answer = match operation {
        "/steer" if !feedback.is_empty() && feedback.len() <= 8192 => {
            if delivery
                .ask_work(scope, id, feedback)
                .map_err(io::Error::other)?
            {
                "received feedback".into()
            } else {
                "is unavailable for feedback right now".into()
            }
        }
        "/cancel" if feedback.is_empty() => {
            if delivery.cancel_work(scope, id).map_err(io::Error::other)? {
                "received cancellation".into()
            } else {
                "is unavailable for cancellation".into()
            }
        }
        "/work" if feedback.is_empty() => delivery
            .work_status(scope, id)
            .map_err(io::Error::other)?
            .map(|state| format!("is {state}"))
            .unwrap_or_else(|| "is unavailable".into()),
        _ => {
            return Ok(Some(
                "Use /work RUN, /steer RUN MESSAGE or /cancel RUN.".into(),
            ));
        }
    };
    Ok(Some(format!("Work {encoded} {answer}.")))
}

pub(super) async fn serve<F>(
    context: Arc<AgentContext<F>>,
    conversation: Arc<Conversation>,
    origin: Option<Id>,
    mut stopping: watch::Receiver<bool>,
) -> io::Result<()>
where
    F: Fn() -> io::Result<Harness> + Send + Sync + 'static,
{
    let profile = context
        .microvm
        .as_ref()
        .ok_or_else(|| io::Error::other("missing microVM profile"))?;
    let directory = StateDirectory::open(&context.state)?;
    let mut delivery =
        node::open_delivery(&context.state, &directory, &context.identity.certificate())?;
    let policy = conversation
        .work_policy
        .ok_or(io::ErrorKind::PermissionDenied)?;
    let mut tick = interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = stopping.changed() => return Ok(()),
            _ = tick.tick() => {},
        }
        let thread = match authorized(&context, &conversation, origin) {
            Ok(thread) => thread,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => continue,
            Err(error) => return Err(error),
        };
        let Some(work) = delivery
            .claim_work(thread.scope, policy)
            .map_err(io::Error::other)?
        else {
            continue;
        };
        let allowed = || {
            authorized(&context, &conversation, origin)
                .is_ok_and(|current| current.scope == thread.scope)
        };
        let job = execute(
            &context.state,
            profile,
            &conversation,
            &work,
            &mut delivery,
            allowed,
        );
        let result = tokio::select! {
            _ = stopping.changed() => return Ok(()),
            result = timeout(Duration::from_secs(work.remaining), job) => result.map_err(io::Error::other).and_then(|outcome| outcome),
        };
        delivery
            .finish_work(work.id, || {
                let (reply, patch) = result?;
                if !allowed() {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                if patch.is_empty() {
                    return Ok(reply);
                }
                let name = format!("{}.patch", hex::encode(work.id));
                if !StateDirectory::open(&context.state.join("worker-patches"))?
                    .write(&name, &patch)?
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "worker patch already exists",
                    ));
                }
                Ok(format!("{reply}\nPatch {name}"))
            })
            .map_err(io::Error::other)?;
    }
}

async fn execute(
    state: &Path,
    profile: &crate::microvm::Profile,
    conversation: &Conversation,
    work: &Work,
    delivery: &mut DeliveryStore,
    allowed: impl Fn() -> bool,
) -> io::Result<(String, Vec<u8>)> {
    let snapshot = Snapshot::from_repository(&conversation.repository, &work.commit)
        .map_err(io::Error::other)?;
    if snapshot.selection() != work.selection {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let boot = Guest::start(state, profile, snapshot);
    tokio::pin!(boot);
    let mut tick = interval(TICK);
    let mut feedback = None;
    let guest = loop {
        tokio::select! {
            result = &mut boot => break result?,
            _ = tick.tick() => {
                let next = control(delivery, work.id, &allowed)?;
                feedback = next.or(feedback);
            }
        }
    };
    let mut instruction = match feedback.take() {
        Some(feedback) => format!("{}\n\nOperator feedback: {feedback}", work.instruction),
        None => work.instruction.clone(),
    };
    let reply = loop {
        let turn = guest.session.prompt_text(instruction, LIMIT);
        tokio::pin!(turn);
        let result = loop {
            tokio::select! {
                result = &mut turn => break result,
                _ = tick.tick() => {
                    if let Some(update) = control(delivery, work.id, &allowed)? {
                        feedback = Some(update);
                        guest.session.cancel().await.map_err(io::Error::other)?;
                        break timeout(Duration::from_secs(5), &mut turn).await.map_err(io::Error::other)?;
                    }
                }
            }
        };
        let update = match feedback.take() {
            Some(text) => Some(text),
            None => control(delivery, work.id, &allowed)?,
        };
        if let Some(update) = update {
            instruction = format!("Continue this work with the operator's feedback: {update}");
        } else {
            break result?;
        }
    };
    Ok((reply, guest.finish(&hex::encode(work.id)).await?))
}

fn control(
    delivery: &mut DeliveryStore,
    id: Id,
    allowed: impl Fn() -> bool,
) -> io::Result<Option<String>> {
    if !allowed() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let (cancelled, feedback) = delivery.work_control(id).map_err(io::Error::other)?;
    if cancelled {
        return Err(io::ErrorKind::Interrupted.into());
    }
    Ok(feedback)
}
