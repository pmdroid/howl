use agent_client_protocol::{
    Agent, Client, ConnectTo,
    schema::ProtocolVersion,
    v2::{ConnectionTo, InitializeOutcome, schema::*},
};
use tokio::sync::watch;

use super::{
    Capabilities, Driver, Error, Event, Journal, PermissionDecision, Phase, Restore, Result,
    SessionWire, StopReason as ManagedStopReason, WORKSPACE, call, check_restore,
    record_capabilities, record_session, remote_error, serve_session,
};

pub(super) async fn drive(
    transport: impl ConnectTo<Client>,
    driver: Driver,
) -> agent_client_protocol::Result<()> {
    let Driver {
        journal,
        events,
        restore,
        channels,
        ..
    } = driver;
    let (progress, updates) = watch::channel(Foreground::default());
    let bind = progress.clone();
    let permission_state = journal.subscribe();
    let notifications = events.clone();
    Client
        .v2()
        .on_receive_notification(
            async move |notification: UpdateSessionNotification, _| {
                let mut selected = false;
                progress.send_if_modified(|foreground| {
                    selected = foreground.session.as_ref() == Some(&notification.session_id);
                    let SessionUpdate::StateUpdate(update) = &notification.update else {
                        return false;
                    };
                    if selected {
                        foreground.update(update)
                    } else {
                        foreground.observe_before_bind(&notification.session_id, update);
                        false
                    }
                });
                if selected {
                    let _ = notifications.send(Event::UpdateV2(Box::new(notification)));
                }
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .on_receive_request(
            async move |request: RequestPermissionRequest, responder, _| {
                let in_turn = {
                    let state = permission_state.borrow();
                    state.phase == Phase::Active
                        && state.remote_session.as_deref() == Some(request.session_id.0.as_ref())
                };
                let reject = in_turn
                    .then(|| {
                        request
                            .options
                            .iter()
                            .find(|option| option.kind == PermissionOptionKind::RejectOnce)
                    })
                    .flatten();
                let (decision, outcome) = if let Some(option) = reject {
                    (
                        PermissionDecision::RejectOnce,
                        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(
                            option.option_id.clone(),
                        )),
                    )
                } else {
                    (
                        PermissionDecision::Cancelled,
                        CancelledPermissionOutcome::new().into(),
                    )
                };
                let reply = responder.respond(RequestPermissionResponse::new(outcome));
                let _ = events.send(Event::PermissionV2 {
                    offered: request
                        .options
                        .into_iter()
                        .map(|option| option.kind)
                        .collect(),
                    decision,
                });
                reply
            },
            agent_client_protocol::on_receive_request!(),
        )
        .connect_with(transport, async move |connection| {
            let serve = async {
                let session = initialize(&connection, &journal, restore).await;
                let Some((requests, ready)) = channels.lock().unwrap().take() else {
                    return;
                };
                match session {
                    Ok(session) => {
                        bind.send_modify(|foreground| foreground.bind(&session));
                        if ready.send(Ok(())).is_ok() {
                            let wire = Session {
                                connection: &connection,
                                session,
                                updates,
                            };
                            serve_session(&wire, &journal, requests).await;
                        }
                    }
                    Err(error) => {
                        let _ = journal.update(|state| state.phase = Phase::Interrupted);
                        let _ = ready.send(Err(error));
                    }
                }
            };
            tokio::select! {
                biased;
                _ = connection.incoming_closed() => {}
                _ = serve => {}
            }
            Ok(())
        })
        .await
}

async fn initialize(
    connection: &ConnectionTo<Agent>,
    journal: &Journal,
    restore: Restore,
) -> Result<SessionId> {
    let request = InitializeRequest::new(
        ProtocolVersion::V2,
        Implementation::new("howl", env!("CARGO_PKG_VERSION")),
    );
    let InitializeOutcome::Initialized(response) =
        call(connection.send_initialize(request)).await?
    else {
        return Err(Error::Unsupported("ACP v2"));
    };
    if response.capabilities.session.is_none() {
        return Err(Error::Unsupported("ACP v2 sessions"));
    }
    record_capabilities(
        journal,
        ProtocolVersion::V2,
        Capabilities {
            load: false,
            resume: true,
            close: true,
        },
        restore,
    )?;

    let session = if restore == Restore::Fresh {
        call(connection.send_request(NewSessionRequest::new(WORKSPACE)))
            .await?
            .session_id
    } else {
        let state = journal.state();
        check_restore(restore, &state)?;
        let session = SessionId::new(state.remote_session.ok_or(Error::State)?);
        resume(connection, session.clone()).await?;
        session
    };
    record_session(journal, &session.0)?;
    Ok(session)
}

async fn resume(connection: &ConnectionTo<Agent>, session: SessionId) -> Result<()> {
    call(connection.send_request(ResumeSessionRequest::new(session, WORKSPACE)))
        .await
        .map(|_| ())
}

struct Session<'a> {
    connection: &'a ConnectionTo<Agent>,
    session: SessionId,
    updates: watch::Receiver<Foreground>,
}

impl SessionWire for Session<'_> {
    async fn prompt(&self, text: String) -> Result<ManagedStopReason> {
        let mut updates = self.updates.clone();
        let baseline = {
            let state = updates.borrow_and_update();
            if state.active {
                return Err(Error::Busy);
            }
            state.completions
        };
        let request = self
            .connection
            .send_request(PromptRequest::new(self.session.clone(), vec![text.into()]));
        let accepted = request.block_task().await;
        if let Err(error) = accepted {
            let code = error.code.value();
            if updates.borrow().active {
                let _ = updates
                    .wait_for(|state| !state.active)
                    .await
                    .map_err(|_| Error::Disconnected)?;
            }
            if code == -32800 {
                return Ok(ManagedStopReason::Cancelled);
            }
            return Err(remote_error(error));
        }

        let terminal = updates
            .wait_for(|state| state.completions != baseline && !state.active)
            .await
            .map_err(|_| Error::Disconnected)?;
        managed_stop(terminal.reason.as_ref())
    }

    fn cancel(&self) -> Result<()> {
        self.connection
            .send_notification(CancelSessionNotification::new(self.session.clone()))
            .map_err(|_| Error::Disconnected)
    }

    fn cancel_idle(&self) -> Result<()> {
        if self.updates.borrow().active {
            self.cancel()
        } else {
            Err(Error::Idle)
        }
    }

    async fn restore(&self, mode: Restore) -> Result<()> {
        match mode {
            Restore::Resume => resume(self.connection, self.session.clone()).await,
            Restore::Load | Restore::Fresh => Err(Error::Unsupported("ACP v2 session load")),
        }
    }

    async fn close(&self) -> Result<()> {
        call(
            self.connection
                .send_request(CloseSessionRequest::new(self.session.clone())),
        )
        .await
        .map(|_| ())
    }
}

#[derive(Default)]
struct Foreground {
    session: Option<SessionId>,
    pending_activity: Vec<SessionId>,
    active: bool,
    completions: u64,
    reason: Option<StopReason>,
}

impl Foreground {
    fn observe_before_bind(&mut self, session: &SessionId, update: &StateUpdate) {
        if self.session.is_some() {
            return;
        }
        if matches!(update, StateUpdate::Idle(_)) {
            self.pending_activity.retain(|id| id != session);
        } else if self.pending_activity.len() < 16 && !self.pending_activity.contains(session) {
            self.pending_activity.push(session.clone());
        }
    }

    fn bind(&mut self, session: &SessionId) {
        self.active = self.pending_activity.contains(session);
        self.pending_activity.clear();
        self.session = Some(session.clone());
    }

    fn update(&mut self, update: &StateUpdate) -> bool {
        if let StateUpdate::Idle(idle) = update {
            if !self.active {
                return false;
            }
            self.active = false;
            self.completions = self.completions.wrapping_add(1);
            self.reason.clone_from(&idle.stop_reason);
            true
        } else {
            let changed = !self.active;
            self.active = true;
            changed
        }
    }
}

fn managed_stop(reason: Option<&StopReason>) -> Result<ManagedStopReason> {
    Ok(match reason {
        Some(StopReason::EndTurn) => ManagedStopReason::EndTurn,
        Some(StopReason::MaxTokens) => ManagedStopReason::MaxTokens,
        Some(StopReason::MaxTurnRequests) => ManagedStopReason::MaxTurnRequests,
        Some(StopReason::Refusal) => ManagedStopReason::Refusal,
        Some(StopReason::Cancelled) => ManagedStopReason::Cancelled,
        Some(StopReason::Error(error)) => {
            return Err(error
                .error
                .as_ref()
                .map_or(Error::TurnFailed, |error| Error::Remote(error.code.into())));
        }
        _ => return Err(Error::UnreportedStop),
    })
}
