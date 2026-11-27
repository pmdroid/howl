use std::{io, path::Path};

use howl_envelope::Id;
use rmcp::{
    ErrorData, RoleServer,
    model::{
        CacheScope, GetPromptRequestParams, GetPromptResponse, GetPromptResult, ListPromptsResult,
        ListResourceTemplatesResult, ListResourcesResult, PaginatedRequestParams, Prompt,
        PromptArgument, PromptMessage, ReadResourceRequestParams, ReadResourceResponse,
        ReadResourceResult, Resource, ResourceContents, ResourceTemplate, Role,
    },
    service::RequestContext,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{enrollment::ChannelPermission, interaction::LocalInteraction, node};

use super::{IntegrationPermission, IntegrationPrincipal, authenticated};

const PAGE_SIZE: usize = 24;
const HISTORY_SIZE: usize = 16;
const MAX_TOPIC_BYTES: usize = 4096;
const JSON_MIME: &str = "application/json";
const CHANNEL_URI: &str = "howl://channels/";

const PROMPTS: [(&str, &str); 3] = [
    (
        "brainstorm",
        "Generate three distinct approaches and compare their main tradeoffs.",
    ),
    (
        "debate",
        "Present the strongest case on each side and identify what evidence would settle the disagreement.",
    ),
    (
        "review",
        "Evaluate correctness, risks, and concrete improvements. State what evidence supports each finding.",
    ),
];

#[derive(Debug, PartialEq, Eq)]
enum ResourceKind {
    History,
    Agents,
    Status,
    Run(Id),
    Result(Id),
}

const CHANNEL_RESOURCES: [(&str, &str); 3] = [
    ("history", "Recent channel history"),
    ("agents", "Channel agents"),
    ("status", "Channel workflow status"),
];

pub(crate) async fn list_resources(
    state: &Path,
    context: &RequestContext<RoleServer>,
    request: Option<PaginatedRequestParams>,
) -> Result<ListResourcesResult, ErrorData> {
    let offset = offset(request)?;
    let principal = authenticated(context)?.clone();
    let state = state.to_owned();
    let (resources, next) = tokio::task::spawn_blocking(move || {
        let local = LocalInteraction::new(&state);
        local.require_enrolled().map_err(unavailable)?;
        let mut channels = principal.channels().to_vec();
        channels.sort_unstable();
        channels.dedup();
        let resources = channels
            .into_iter()
            .filter(|channel| {
                principal.permits(channel, IntegrationPermission::Read)
                    && local
                        .authorize(*channel, ChannelPermission::Receive)
                        .is_ok()
            })
            .flat_map(|channel| {
                let channel = hex::encode(channel);
                CHANNEL_RESOURCES.map(|(path, label)| {
                    Resource::new(format!("{CHANNEL_URI}{channel}/{path}"), label)
                        .with_mime_type(JSON_MIME)
                })
            });
        Ok::<_, ErrorData>(page(resources, offset))
    })
    .await
    .map_err(interrupted)??;
    let mut response = ListResourcesResult::with_all_items(resources)
        .with_ttl_ms(0)
        .with_cache_scope(CacheScope::Private);
    response.next_cursor = next;
    Ok(response)
}

pub(crate) fn list_resource_templates(
    request: Option<PaginatedRequestParams>,
) -> Result<ListResourceTemplatesResult, ErrorData> {
    let templates = CHANNEL_RESOURCES
        .into_iter()
        .chain([
            ("runs/{run}", "Integration run status"),
            ("runs/{run}/result", "Integration run result"),
        ])
        .map(|(path, name)| {
            ResourceTemplate::new(format!("{CHANNEL_URI}{{channel}}/{path}"), name)
                .with_mime_type(JSON_MIME)
        });
    let (templates, next) = page(templates, offset(request)?);
    let mut response = ListResourceTemplatesResult::with_all_items(templates)
        .with_ttl_ms(0)
        .with_cache_scope(CacheScope::Private);
    response.next_cursor = next;
    Ok(response)
}

pub(crate) async fn read_resource(
    state: &Path,
    context: &RequestContext<RoleServer>,
    request: ReadResourceRequestParams,
) -> Result<ReadResourceResponse, ErrorData> {
    let principal = authenticated(context)?.clone();
    let state = state.to_owned();
    let uri = request.uri;
    let contents = tokio::task::spawn_blocking(move || {
        let value = resource_value(&state, &principal, &uri)?;
        Ok::<_, ErrorData>(ResourceContents::text(value.to_string(), uri).with_mime_type(JSON_MIME))
    })
    .await
    .map_err(interrupted)??;
    Ok(ReadResourceResult::new(vec![contents])
        .with_ttl_ms(0)
        .with_cache_scope(CacheScope::Private)
        .into())
}

pub(crate) fn list_prompts(
    request: Option<PaginatedRequestParams>,
) -> Result<ListPromptsResult, ErrorData> {
    let prompts = PROMPTS.into_iter().map(|(name, description)| {
        Prompt::new(
            name,
            Some(description),
            Some(vec![
                PromptArgument::new("topic")
                    .with_description("Topic or material for the discussion")
                    .with_required(true),
            ]),
        )
    });
    let (prompts, next) = page(prompts, offset(request)?);
    let mut response = ListPromptsResult::with_all_items(prompts)
        .with_ttl_ms(0)
        .with_cache_scope(CacheScope::Private);
    response.next_cursor = next;
    Ok(response)
}

pub(crate) fn get_prompt(request: GetPromptRequestParams) -> Result<GetPromptResponse, ErrorData> {
    let (_, description) = PROMPTS
        .into_iter()
        .find(|(name, _)| *name == request.name)
        .ok_or_else(|| ErrorData::invalid_params("unknown discussion prompt", None))?;
    let topic = request
        .arguments
        .as_ref()
        .filter(|arguments| arguments.len() == 1)
        .and_then(|arguments| arguments.get("topic"))
        .and_then(Value::as_str)
        .filter(|topic| !topic.trim().is_empty() && topic.len() <= MAX_TOPIC_BYTES)
        .ok_or_else(|| ErrorData::invalid_params("a bounded topic is required", None))?;
    let message = PromptMessage::new_text(Role::User, format!("{description}\n\n{topic}"));
    Ok(GetPromptResult::new(vec![message])
        .with_description(description)
        .into())
}

pub(crate) fn resource_value(
    state: &Path,
    principal: &IntegrationPrincipal,
    uri: &str,
) -> Result<Value, ErrorData> {
    let (channel, kind) = resource_path(uri).ok_or_else(not_found)?;
    if !principal.permits(&channel, IntegrationPermission::Read) {
        return Err(not_found());
    }
    let local = LocalInteraction::new(state);
    local.require_enrolled().map_err(unavailable)?;
    local
        .authorize(channel, ChannelPermission::Receive)
        .map_err(unavailable)?;
    match kind {
        ResourceKind::History => {
            let history = local.history(channel, HISTORY_SIZE).map_err(unavailable)?;
            serialized(history)
        }
        ResourceKind::Agents => {
            let agents = local.agents(channel).map_err(unavailable)?;
            serialized(agents)
        }
        ResourceKind::Status => local.status(channel).map_err(unavailable),
        ResourceKind::Run(run) | ResourceKind::Result(run) => {
            let run = node::integration_run(state, principal.id(), run)
                .map_err(unavailable)?
                .filter(|stored| stored.channel == channel)
                .ok_or_else(not_found)?;
            let status = run.value();
            if matches!(kind, ResourceKind::Result(_)) {
                Ok(json!({
                    "status": status["status"],
                    "reply": status["reply"],
                    "error": status["error"],
                }))
            } else {
                Ok(status)
            }
        }
    }
}

fn resource_path(uri: &str) -> Option<(Id, ResourceKind)> {
    let (channel, path) = uri.strip_prefix(CHANNEL_URI)?.split_once('/')?;
    let channel = decode_id(channel)?;
    let kind = match path {
        "history" => ResourceKind::History,
        "agents" => ResourceKind::Agents,
        "status" => ResourceKind::Status,
        path => {
            let run = path.strip_prefix("runs/")?;
            if let Some(run) = run.strip_suffix("/result") {
                ResourceKind::Result(decode_id(run)?)
            } else {
                ResourceKind::Run(decode_id(run)?)
            }
        }
    };
    Some((channel, kind))
}

fn decode_id(value: &str) -> Option<Id> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id).ok()?;
    Some(id)
}

fn offset(request: Option<PaginatedRequestParams>) -> Result<usize, ErrorData> {
    request
        .and_then(|params| params.cursor)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| ErrorData::invalid_params("invalid pagination cursor", None))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn page<T>(items: impl Iterator<Item = T>, offset: usize) -> (Vec<T>, Option<String>) {
    let mut items = items.skip(offset);
    let page = items.by_ref().take(PAGE_SIZE).collect();
    let next = items.next().map(|_| (offset + PAGE_SIZE).to_string());
    (page, next)
}

fn serialized(value: impl Serialize) -> Result<Value, ErrorData> {
    serde_json::to_value(value)
        .map_err(|_| ErrorData::internal_error("could not encode resource", None))
}

fn not_found() -> ErrorData {
    ErrorData::resource_not_found("resource unavailable in this integration", None)
}

fn unavailable(error: io::Error) -> ErrorData {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound | io::ErrorKind::InvalidData => {
            not_found()
        }
        _ => ErrorData::internal_error("could not read resource", None),
    }
}

fn interrupted(_: tokio::task::JoinError) -> ErrorData {
    ErrorData::internal_error("resource operation interrupted", None)
}

#[cfg(test)]
mod tests;
