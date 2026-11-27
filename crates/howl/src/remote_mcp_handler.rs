use std::{
    borrow::Cow,
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use howl_envelope::{AgentRole, Id};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, GetTaskParams,
        GetTaskResult, Implementation, InitializeRequestParams, InitializeResult, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
        TASKS_EXTENSION_ID, UpdateTaskParams,
    },
    schemars::{self, JsonSchema},
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::{
    delivery::{IntegrationRun, IntegrationRunState, NewIntegrationRun},
    enrollment::ChannelPermission,
    interaction::LocalInteraction,
    node,
    remote_mcp::{self, IntegrationPermission, authenticated, tasks},
};

#[derive(Clone)]
struct GatewayTools {
    state: Arc<PathBuf>,
    tools: ToolRouter<Self>,
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
    after: Option<u64>,
    limit: Option<usize>,
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
    target: String,
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

#[tool_router(router = routes)]
impl GatewayTools {
    #[tool(
        description = "List signed channels this integration may read",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
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
            Ok(json!({ "channels": channels }))
        })
        .await
    }

    #[tool(
        description = "List signed channel members' agent addresses and known availability",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn list_agents(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<ChannelArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let channel = permitted(&context, &args.channel, IntegrationPermission::Read)?;
        self.read_local(move |local| Ok(json!({ "agents": local.agents(channel)? })))
            .await
    }

    #[tool(
        description = "Read durable channel events after a cursor, optionally for one direct peer",
        annotations(
            read_only_hint = true,
            idempotent_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn read(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let channel = permitted(&context, &args.channel, IntegrationPermission::Read)?;
        let peer = args.peer.as_deref().map(parse_id).transpose()?;
        let limit = args.limit.unwrap_or(20).clamp(1, 32);
        let after = args.after.unwrap_or_default();
        self.read_local(move |local| {
            serde_json::to_value(local.event_page(channel, peer, after, limit)?)
                .map_err(io::Error::other)
        })
        .await
    }

    #[tool(
        description = "Post one signed message to all current recipients of a granted channel",
        annotations(
            read_only_hint = false,
            idempotent_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
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
        annotations(
            read_only_hint = false,
            idempotent_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
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
        description = "Request a bounded agent wake and return a durable run handle. Reuse the same key and arguments to retry.",
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
        let target = parse_id(&args.target)?;
        if ![AgentRole::Architect, AgentRole::Reviewer]
            .into_iter()
            .any(|role| role.agent_id(&peer) == target)
        {
            return Err(ErrorData::invalid_params(
                "agent address does not match peer",
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

    async fn read_local(
        &self,
        read: impl FnOnce(LocalInteraction<'_>) -> io::Result<Value> + Send + 'static,
    ) -> Result<CallToolResult, ErrorData> {
        let state = Arc::clone(&self.state);
        tokio::task::spawn_blocking(move || read(LocalInteraction::new(&state)))
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
        "list_channels" | "list_agents" | "read" | "get_run" => IntegrationPermission::Read,
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
