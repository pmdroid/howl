use std::{
    borrow::Cow,
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use howl_envelope::{AgentRole, Id};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams,
        GetPromptRequestParams, GetPromptResponse, GetTaskParams, GetTaskResult, Implementation,
        InitializeRequestParams, InitializeResult, ListPromptsResult, ListResourceTemplatesResult,
        ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ReadResourceRequestParams, ReadResourceResponse, ServerCapabilities, ServerConfig,
        SubscribeRequestParams, SubscriptionFilter, TASKS_EXTENSION_ID, UnsubscribeRequestParams,
        UpdateTaskParams,
    },
    schemars::{self, JsonSchema},
    service::{RequestContext, SubscriptionContext},
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::remote_mcp::subscriptions::{self, EventQuery, Subscriptions};
use crate::{
    delivery::{
        IntegrationRun, IntegrationRunDetails, IntegrationRunState, IntegrationRunSummary,
        NewIntegrationRun,
    },
    enrollment::ChannelPermission,
    identity::StateDirectory,
    interaction::{AgentAddress, LocalInteraction, Receipt},
    node,
    remote_mcp::{
        self, IntegrationPermission, authenticated,
        cursors::{CursorInput, CursorKey, RemoteEventPage},
        resources, tasks,
    },
};

#[derive(Clone)]
struct GatewayTools {
    state: Arc<PathBuf>,
    tools: ToolRouter<Self>,
    subscriptions: Subscriptions,
    cursor_key: Arc<CursorKey>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ChannelArgs {
    channel: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    channel: String,
    peer: Option<String>,
    after: Option<CursorInput>,
    limit: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WaitArgs {
    channel: String,
    peer: Option<String>,
    after: Option<CursorInput>,
    limit: Option<usize>,
    wait_ms: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PostArgs {
    channel: String,
    text: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DirectArgs {
    channel: String,
    peer: String,
    text: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WakeArgs {
    channel: String,
    peer: String,
    target: Option<String>,
    key: String,
    lifetime: u16,
    text: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    channel: String,
    run: String,
}

#[derive(Serialize, JsonSchema)]
struct Channels {
    channels: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
struct Agents {
    agents: Vec<AgentAddress>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    peer_names: BTreeMap<String, String>,
}

#[tool_router(router = routes)]
impl GatewayTools {
    #[tool(
        description = "List signed channels this integration may read",
        output_schema = rmcp::handler::server::tool::schema_for_type::<Channels>(),
        annotations(read_only_hint = true, idempotent_hint = true, destructive_hint = false, open_world_hint = false)
    )]
    async fn list_channels(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let principal = authenticated(&context)?.clone();
        self.read_local(move |local| {
            let mut channels = Vec::new();
            for channel in principal.channels() {
                if principal.permits(channel, IntegrationPermission::Read)
                    && local
                        .authorize(*channel, ChannelPermission::Receive)
                        .is_ok()
                {
                    channels.push(hex::encode(channel));
                }
            }
            Ok(Channels { channels })
        })
        .await
    }

    #[tool(
        description = "List signed channel members' agent addresses and known availability",
        output_schema = rmcp::handler::server::tool::schema_for_type::<Agents>(),
        annotations(read_only_hint = true, idempotent_hint = true, destructive_hint = false, open_world_hint = false)
    )]
    async fn list_agents(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<ChannelArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let channel = permitted(&context, &args.channel, IntegrationPermission::Read)?;
        let state = self.state.clone();
        self.read_local(move |local| {
            let agents = local.agents(channel)?;
            let mut peer_names: BTreeMap<String, String> = StateDirectory::open(&state)
                .and_then(|directory| directory.read_bounded("peer-labels.json", 16 * 1024))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            peer_names.retain(|device, _| agents.iter().any(|agent| &agent.device == device));
            Ok(Agents { agents, peer_names })
        })
        .await
    }

    #[tool(
        description = "Read durable channel events after a cursor, optionally for one direct peer",
        output_schema = rmcp::handler::server::tool::schema_for_type::<RemoteEventPage>(),
        annotations(read_only_hint = true, idempotent_hint = true, destructive_hint = false, open_world_hint = false)
    )]
    async fn read(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.replay(&context, args, 0).await
    }

    #[tool(
        description = "Read a bounded page of durable conversation events with replay and gap detection",
        output_schema = rmcp::handler::server::tool::schema_for_type::<RemoteEventPage>(),
        annotations(read_only_hint = true, idempotent_hint = true, destructive_hint = false, open_world_hint = false)
    )]
    async fn read_events(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.replay(&context, args, 0).await
    }

    #[tool(
        description = "Wait for a durable conversation event after the supplied cursor",
        output_schema = rmcp::handler::server::tool::schema_for_type::<RemoteEventPage>(),
        annotations(read_only_hint = true, idempotent_hint = true, destructive_hint = false, open_world_hint = false)
    )]
    async fn wait_for_events(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<WaitArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.replay(
            &context,
            ReadArgs {
                channel: args.channel,
                peer: args.peer,
                after: args.after,
                limit: args.limit,
            },
            args.wait_ms.unwrap_or(15_000),
        )
        .await
    }

    async fn replay(
        &self,
        context: &RequestContext<RoleServer>,
        args: ReadArgs,
        wait_ms: u64,
    ) -> Result<CallToolResult, ErrorData> {
        subscriptions::events(
            Arc::clone(&self.state),
            &self.cursor_key,
            context,
            EventQuery {
                channel: permitted(context, &args.channel, IntegrationPermission::Read)?,
                peer: args.peer.as_deref().map(parse_id).transpose()?,
                after: args.after,
                limit: args.limit.unwrap_or(20),
                wait: Duration::from_millis(wait_ms),
            },
        )
        .await
    }

    #[tool(
        description = "Post one signed message to all current recipients of a granted channel",
        output_schema = rmcp::handler::server::tool::schema_for_type::<Receipt>(),
        annotations(read_only_hint = false, idempotent_hint = false, destructive_hint = false, open_world_hint = true)
    )]
    async fn post(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<PostArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.send_post(&context, &args.channel, None, &args.text)
            .await
    }

    #[tool(
        description = "Queue a private message to the named peer in a granted channel",
        output_schema = rmcp::handler::server::tool::schema_for_type::<Receipt>(),
        annotations(read_only_hint = false, idempotent_hint = false, destructive_hint = false, open_world_hint = true)
    )]
    async fn dm(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<DirectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.send_post(
            &context,
            &args.channel,
            Some(parse_id(&args.peer)?),
            &args.text,
        )
        .await
    }

    async fn send_post(
        &self,
        context: &RequestContext<RoleServer>,
        channel: &str,
        peer: Option<Id>,
        text: &str,
    ) -> Result<CallToolResult, ErrorData> {
        let channel = permitted(context, channel, IntegrationPermission::Send)?;
        let owner = authenticated(context)?.id();
        let receipt = node::send_integration_chat(&self.state, channel, peer, owner, text)
            .await
            .map_err(from_io)?;
        let message = receipt
            .strip_prefix("queued ")
            .ok_or_else(|| ErrorData::internal_error("invalid Howl delivery receipt", None))?;
        parse_id(message)?;
        Ok(CallToolResult::structured(json!({ "message": message })))
    }

    #[tool(
        description = "Assign work to a peer and return a durable run handle. The peer selects its default agent target. Reuse the same key and arguments to retry.",
        output_schema = rmcp::handler::server::tool::schema_for_type::<IntegrationRunSummary>(),
        annotations(
            read_only_hint = false,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn wake(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<WakeArgs>,
    ) -> Result<CallToolResponse, ErrorData> {
        let channel = permitted(&context, &args.channel, IntegrationPermission::Wake)?;
        let principal = authenticated(&context)?.clone();
        let peer = parse_id(&args.peer)?;
        let target = args
            .target
            .as_deref()
            .map(parse_id)
            .transpose()?
            .unwrap_or_else(|| AgentRole::default().agent_id(&peer));
        if !AgentRole::matches_agent_id(&peer, &target) {
            return Err(ErrorData::invalid_params(
                "agent address does not match peer",
                None,
            ));
        }
        if args.text.trim_start().starts_with(crate::project::PREFIX) {
            return Err(ErrorData::invalid_params(
                "Select an editable repository in the operator's terminal",
                None,
            ));
        }
        let state = Arc::clone(&self.state);
        let run = tokio::spawn(async move {
            let request = NewIntegrationRun {
                owner: principal.id(),
                key: &args.key,
                channel,
                peer,
                target,
                lifetime: args.lifetime,
                text: &args.text,
            };
            let run = node::prepare_integration_run(&state, request).map_err(from_io)?;
            if run.message.is_none() && run.state == IntegrationRunState::Working {
                if !principal.is_current().await {
                    return Err(ErrorData::invalid_params(
                        "integration grant is no longer active",
                        None,
                    ));
                }
                node::send_integration_wake(&state, run.id, request)
                    .await
                    .map_err(from_io)?;
            }
            node::integration_run(&state, principal.id(), run.id)
                .map_err(from_io)?
                .ok_or_else(run_unavailable)
        })
        .await
        .map_err(|_| ErrorData::internal_error("Howl operation interrupted", None))??;
        Ok(tasks::call_response(&run, &context))
    }

    #[tool(
        description = "Read the status and final result of a run owned by this integration",
        output_schema = rmcp::handler::server::tool::schema_for_type::<IntegrationRunDetails>(),
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_run(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<RunArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_operation(&context, args, IntegrationPermission::Read)
            .await
    }

    #[tool(
        description = "Request cancellation of a run owned by this integration and report its resulting state",
        output_schema = rmcp::handler::server::tool::schema_for_type::<IntegrationRunSummary>(),
        annotations(
            read_only_hint = false,
            idempotent_hint = true,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn cancel_run(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<RunArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.run_operation(&context, args, IntegrationPermission::Cancel)
            .await
    }

    async fn run_operation(
        &self,
        context: &RequestContext<RoleServer>,
        args: RunArgs,
        permission: IntegrationPermission,
    ) -> Result<CallToolResult, ErrorData> {
        let channel = permitted(context, &args.channel, permission)?;
        let id = parse_id(&args.run)?;
        let owner = authenticated(context)?.id().to_owned();
        let state = Arc::clone(&self.state);
        self.read_local(move |local| {
            local.authorize(channel, ChannelPermission::Receive)?;
            let run = node::integration_run(&state, &owner, id)?
                .filter(|run| run.channel == channel)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            if permission == IntegrationPermission::Cancel {
                let run = node::cancel_integration_run(&state, &owner, id)?
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
                return Ok(run_summary(&run));
            }
            Ok(run.value())
        })
        .await
    }

    async fn read_local<T: Serialize + Send + 'static>(
        &self,
        read: impl FnOnce(LocalInteraction<'_>) -> io::Result<T> + Send + 'static,
    ) -> Result<CallToolResult, ErrorData> {
        let state = Arc::clone(&self.state);
        tokio::task::spawn_blocking(move || {
            serde_json::to_value(read(LocalInteraction::new(&state))?).map_err(io::Error::other)
        })
        .await
        .map_err(|_| ErrorData::internal_error("Howl operation interrupted", None))?
        .map(CallToolResult::structured)
        .map_err(from_io)
    }

    async fn task_operation(
        &self,
        context: &RequestContext<RoleServer>,
        task_id: &str,
        permission: IntegrationPermission,
    ) -> Result<IntegrationRun, ErrorData> {
        if !tasks::is_native_protocol(context) {
            return Err(ErrorData::invalid_request(
                "native tasks require MCP 2026-07-28",
                None,
            ));
        }
        let id = parse_id(task_id)?;
        let principal = authenticated(context)?.clone();
        let state = Arc::clone(&self.state);
        tokio::task::spawn_blocking(move || {
            let run = node::integration_run(&state, principal.id(), id)
                .map_err(from_io)?
                .filter(|run| principal.permits(&run.channel, permission))
                .ok_or_else(run_unavailable)?;
            LocalInteraction::new(&state)
                .authorize(run.channel, ChannelPermission::Receive)
                .map_err(|_| run_unavailable())?;
            if permission == IntegrationPermission::Cancel {
                node::cancel_integration_run(&state, principal.id(), id)
                    .map_err(from_io)?
                    .ok_or_else(run_unavailable)
            } else {
                Ok(run)
            }
        })
        .await
        .map_err(|_| ErrorData::internal_error("Howl operation interrupted", None))?
    }
}

#[tool_handler(router = self.tools)]
impl ServerHandler for GatewayTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new("howl", env!("CARGO_PKG_VERSION")))
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        context.peer.set_peer_info(request.clone());
        let mut result = self.negotiate_initialize(&request)?;
        if let Some(extensions) = &mut result.capabilities.extensions {
            extensions.remove(TASKS_EXTENSION_ID);
            if extensions.is_empty() {
                result.capabilities.extensions = None;
            }
        }
        Ok(result)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2025_11_25, ProtocolVersion::V_2026_07_28])
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        resources::list_resources(&self.state, &context, request).await
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        authenticated(&context)?;
        resources::list_resource_templates(request)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        resources::read_resource(&self.state, &context, request).await
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        Subscriptions::accepted_filter(requested)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        self.subscriptions
            .listen(Arc::clone(&self.state), context)
            .await
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.subscriptions
            .subscribe(Arc::clone(&self.state), request.uri, context)
            .await
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.subscriptions
            .unsubscribe(Arc::clone(&self.state), request.uri, context)
            .await
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        authenticated(&context)?;
        resources::list_prompts(request)
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        authenticated(&context)?;
        resources::get_prompt(request)
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        let run = self
            .task_operation(&context, &request.task_id, IntegrationPermission::Read)
            .await?;
        Ok(GetTaskResult::new(tasks::get_task(&run)?))
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.task_operation(&context, &request.task_id, IntegrationPermission::Cancel)
            .await?;
        Ok(())
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        self.task_operation(&context, &request.task_id, IntegrationPermission::Read)
            .await?;
        Err(ErrorData::invalid_params(
            "task has no pending client inputs",
            None,
        ))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let principal = authenticated(&context)?;
        let tools = self
            .tools
            .list_all()
            .into_iter()
            .filter(|tool| tool_allowed(principal, &tool.name))
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let principal = authenticated(&context)?;
        if !tool_allowed(principal, &request.name) {
            return Err(ErrorData::invalid_params(
                "operation outside integration scope",
                None,
            ));
        }
        let owner = principal.id().to_owned();
        let operation = request.name.clone();
        let result = self
            .tools
            .call(ToolCallContext::new(self, request, context))
            .await;
        eprintln!(
            "howl_mcp tool integration={owner} operation={operation} success={}",
            result.is_ok()
        );
        result
    }
}

pub async fn serve_gateway(
    state: &Path,
    configuration: &Path,
    listener: TcpListener,
) -> io::Result<()> {
    LocalInteraction::new(state).require_enrolled()?;
    remote_mcp::serve(
        listener,
        configuration,
        GatewayTools {
            state: Arc::new(state.to_owned()),
            tools: GatewayTools::routes(),
            subscriptions: Subscriptions::default(),
            cursor_key: Arc::new(CursorKey::load(state)?),
        },
    )
    .await
}

fn permitted(
    context: &RequestContext<RoleServer>,
    channel: &str,
    permission: IntegrationPermission,
) -> Result<Id, ErrorData> {
    let channel = parse_id(channel)?;
    if !authenticated(context)?.permits(&channel, permission) {
        return Err(ErrorData::invalid_params(
            "operation outside integration scope",
            None,
        ));
    }
    Ok(channel)
}

fn tool_allowed(principal: &remote_mcp::IntegrationPrincipal, name: &str) -> bool {
    let permission = match name {
        "list_channels" | "list_agents" | "read" | "get_run" | "read_events"
        | "wait_for_events" => IntegrationPermission::Read,
        "post" | "dm" => IntegrationPermission::Send,
        "wake" => IntegrationPermission::Wake,
        "cancel_run" => IntegrationPermission::Cancel,
        _ => return false,
    };
    principal
        .channels()
        .iter()
        .any(|id| principal.permits(id, permission))
}

fn parse_id(value: &str) -> Result<Id, ErrorData> {
    let mut id = [0; 32];
    hex::decode_to_slice(value, &mut id)
        .map_err(|_| ErrorData::invalid_params("invalid Howl identifier", None))?;
    Ok(id)
}

fn run_summary(run: &IntegrationRun) -> Value {
    let mut summary = run.value();
    if let Value::Object(properties) = &mut summary {
        properties.remove("reply");
    }
    summary
}

fn run_unavailable() -> ErrorData {
    ErrorData::invalid_params("run unavailable in this channel", None)
}

fn from_io(error: io::Error) -> ErrorData {
    match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
            ErrorData::invalid_params("invalid Howl operation", None)
        }
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound => {
            ErrorData::invalid_params("operation unavailable in this channel", None)
        }
        _ => ErrorData::internal_error("Howl operation failed", None),
    }
}
