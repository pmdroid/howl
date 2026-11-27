use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::http::request::Parts;
use howl_envelope::Id;
use rmcp::{
    ErrorData, RoleServer,
    model::{
        CallToolResult, ProgressNotificationParam, ResourceUpdatedNotificationParam,
        SubscriptionFilter,
    },
    service::{RequestContext, SubscriptionContext},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    time::{Instant, MissedTickBehavior, interval, sleep_until, timeout},
};

use crate::interaction::LocalInteraction;

use super::{IntegrationPermission, IntegrationPrincipal, authenticated, resources};

const MAX_SUBSCRIPTIONS: usize = 32;
const MAX_RESOURCES: usize = 8;
const MAX_EVENTS: usize = 32;
const MAX_WAIT: Duration = Duration::from_secs(20);
const TICK: Duration = Duration::from_millis(200);
const SEND_TIMEOUT: Duration = Duration::from_millis(750);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

static EVENT_WAITS: Semaphore = Semaphore::const_new(32);

pub(crate) struct EventQuery {
    pub channel: Id,
    pub peer: Option<Id>,
    pub after: u64,
    pub limit: usize,
    pub wait: Duration,
}

type LegacyKey = (String, String);

struct LegacySubscription {
    generation: Arc<()>,
    _stop: oneshot::Sender<()>,
}

#[derive(Clone)]
pub(crate) struct Subscriptions {
    slots: Arc<Semaphore>,
    legacy: Arc<Mutex<HashMap<LegacyKey, LegacySubscription>>>,
}

impl Default for Subscriptions {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(MAX_SUBSCRIPTIONS)),
            legacy: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Subscriptions {
    pub(crate) fn accepted_filter(requested: &SubscriptionFilter) -> Option<SubscriptionFilter> {
        let mut distinct = HashSet::new();
        let uris = requested
            .resource_subscriptions
            .iter()
            .flatten()
            .filter(|uri| supported_uri(uri) && distinct.insert(uri.as_str()))
            .take(MAX_RESOURCES)
            .cloned();
        Some(
            SubscriptionFilter::builder()
                .resource_subscriptions(uris)
                .build(),
        )
    }

    pub(crate) async fn listen(
        &self,
        state: Arc<PathBuf>,
        context: SubscriptionContext,
    ) -> Result<(), ErrorData> {
        let principal = authenticated(context.request_context())?.clone();
        let _slot = self.slot()?;
        let uris = context
            .accepted()
            .resource_subscriptions
            .clone()
            .filter(|uris| !uris.is_empty())
            .ok_or_else(inaccessible)?;
        let mut snapshot = None;
        let mut ticks = interval(TICK);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut idle = Instant::now() + IDLE_TIMEOUT;
        loop {
            tokio::select! {
                _ = context.cancelled() => return Ok(()),
                _ = sleep_until(idle) => return Ok(()),
                _ = ticks.tick() => {}
            }
            for uri in changed(&state, &principal, &uris, &mut snapshot).await? {
                require_current(&principal).await?;
                let sent = timeout(SEND_TIMEOUT, context.sink().notify_resource_updated(uri)).await;
                if !matches!(sent, Ok(Ok(()))) {
                    return Ok(());
                }
                idle = Instant::now() + IDLE_TIMEOUT;
            }
        }
    }

    pub(crate) async fn subscribe(
        &self,
        state: Arc<PathBuf>,
        uri: String,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let principal = authenticated(&context)?.clone();
        let key = (legacy_session(&context)?, uri.clone());
        let uris = [uri];
        let mut snapshot = Some(snapshot(&state, &principal, &uris).await?);
        let (stop, mut stopped) = oneshot::channel();
        let generation = Arc::new(());
        let slot = {
            let mut legacy = self.legacy.lock().map_err(|_| interrupted())?;
            if legacy.contains_key(&key) {
                return Ok(());
            }
            if legacy
                .keys()
                .filter(|candidate| candidate.0 == key.0)
                .count()
                >= MAX_RESOURCES
            {
                return Err(at_capacity());
            }
            let slot = self.slot()?;
            legacy.insert(
                key.clone(),
                LegacySubscription {
                    generation: Arc::clone(&generation),
                    _stop: stop,
                },
            );
            slot
        };
        let legacy = Arc::clone(&self.legacy);
        tokio::spawn(async move {
            let _slot = slot;
            let mut ticks = interval(TICK);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut idle = Instant::now() + IDLE_TIMEOUT;
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = sleep_until(idle) => break,
                    _ = ticks.tick() => {}
                }
                if context.peer.is_transport_closed() {
                    break;
                }
                let Ok(updates) = changed(&state, &principal, &uris, &mut snapshot).await else {
                    break;
                };
                if let Some(uri) = updates.into_iter().next() {
                    if require_current(&principal).await.is_err() {
                        break;
                    }
                    let sent = tokio::select! {
                        biased;
                        _ = &mut stopped => break,
                        sent = timeout(
                            SEND_TIMEOUT,
                            context.peer.notify_resource_updated(ResourceUpdatedNotificationParam::new(uri)),
                        ) => sent
                    };
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                    idle = Instant::now() + IDLE_TIMEOUT;
                }
            }
            if let Ok(mut legacy) = legacy.lock()
                && legacy
                    .get(&key)
                    .is_some_and(|active| Arc::ptr_eq(&active.generation, &generation))
            {
                legacy.remove(&key);
            }
        });
        Ok(())
    }

    pub(crate) async fn unsubscribe(
        &self,
        _state: Arc<PathBuf>,
        uri: String,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        require_current(authenticated(&context)?).await?;
        let key = (legacy_session(&context)?, uri);
        self.legacy.lock().map_err(|_| interrupted())?.remove(&key);
        Ok(())
    }

    fn slot(&self) -> Result<OwnedSemaphorePermit, ErrorData> {
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| at_capacity())
    }
}

pub(crate) async fn events(
    state: Arc<PathBuf>,
    context: &RequestContext<RoleServer>,
    query: EventQuery,
) -> Result<CallToolResult, ErrorData> {
    let principal = authenticated(context)?;
    if !principal.permits(&query.channel, IntegrationPermission::Read) {
        return Err(inaccessible());
    }
    let wait = query.wait.min(MAX_WAIT);
    let _slot = if wait.is_zero() {
        None
    } else {
        Some(EVENT_WAITS.try_acquire().map_err(|_| at_capacity())?)
    };
    let start = Instant::now();
    let deadline = start + wait;
    let mut progress_at = start + Duration::from_secs(2);
    loop {
        require_current(principal).await?;
        let local = Arc::clone(&state);
        let EventQuery {
            channel,
            peer,
            after,
            limit,
            ..
        } = query;
        let page = tokio::task::spawn_blocking(move || {
            LocalInteraction::new(&local).event_page(
                channel,
                peer,
                after,
                limit.clamp(1, MAX_EVENTS),
            )
        })
        .await
        .map_err(|_| interrupted())?
        .map_err(|_| inaccessible())?;
        require_current(principal).await?;
        if page.gap || !page.events.is_empty() || Instant::now() >= deadline {
            return Ok(CallToolResult::structured(json!(page)));
        }
        if Instant::now() >= progress_at {
            progress(
                context,
                start.elapsed().as_secs_f64(),
                "Waiting for channel events",
            )
            .await;
            progress_at = Instant::now() + Duration::from_secs(2);
        }
        tokio::select! {
            _ = context.ct.cancelled() => return Err(interrupted()),
            _ = sleep_until((Instant::now() + TICK).min(deadline)) => {}
        }
    }
}

pub(crate) async fn progress(
    context: &RequestContext<RoleServer>,
    done: f64,
    message: &'static str,
) {
    if let Some(token) = context.meta.get_progress_token() {
        let _ = timeout(
            SEND_TIMEOUT,
            context
                .peer
                .notify_progress(ProgressNotificationParam::new(token, done).with_message(message)),
        )
        .await;
    }
}

async fn snapshot(
    state: &Arc<PathBuf>,
    principal: &IntegrationPrincipal,
    uris: &[String],
) -> Result<Vec<[u8; 32]>, ErrorData> {
    require_current(principal).await?;
    let state = Arc::clone(state);
    let principal = principal.clone();
    let uris = uris.to_owned();
    tokio::task::spawn_blocking(move || {
        uris.iter()
            .map(|uri| {
                resources::resource_value(&state, &principal, uri)
                    .map(|value| Sha256::digest(value.to_string()).into())
            })
            .collect()
    })
    .await
    .map_err(|_| interrupted())?
}

async fn changed(
    state: &Arc<PathBuf>,
    principal: &IntegrationPrincipal,
    uris: &[String],
    previous: &mut Option<Vec<[u8; 32]>>,
) -> Result<Vec<String>, ErrorData> {
    let next = snapshot(state, principal, uris).await?;
    let changed = previous.as_ref().map_or_else(
        || uris.to_owned(),
        |before| {
            uris.iter()
                .zip(before.iter().zip(&next))
                .filter(|(_, (before, after))| before != after)
                .map(|(uri, _)| uri.clone())
                .collect()
        },
    );
    *previous = Some(next);
    Ok(changed)
}

fn supported_uri(uri: &str) -> bool {
    let Some(path) = uri.strip_prefix("howl://channels/") else {
        return false;
    };
    let mut parts = path.split('/');
    let valid_id = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if !parts.next().is_some_and(valid_id) {
        return false;
    }
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("history" | "agents" | "status"), None, None, None) => true,
        (Some("runs"), Some(run), None | Some("result"), None) => valid_id(run),
        _ => false,
    }
}

async fn require_current(principal: &IntegrationPrincipal) -> Result<(), ErrorData> {
    if principal.is_current().await {
        Ok(())
    } else {
        Err(inaccessible())
    }
}

fn legacy_session(context: &RequestContext<RoleServer>) -> Result<String, ErrorData> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.headers.get("mcp-session-id"))
        .and_then(|id| id.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(inaccessible)
}

fn inaccessible() -> ErrorData {
    ErrorData::invalid_params("subscription unavailable in this scope", None)
}

fn interrupted() -> ErrorData {
    ErrorData::internal_error("subscription interrupted", None)
}

fn at_capacity() -> ErrorData {
    ErrorData::internal_error("subscription capacity reached", None)
}

#[cfg(test)]
mod tests;
