use rmcp::{
    ErrorData, Json, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, tool::IntoCallToolResult, wrapper::Parameters},
    model::{
        CallToolResponse, CallToolResult, ContentBlock, ProtocolVersion, ServerCapabilities,
        ServerConfig,
    },
    schemars::{self, JsonSchema},
    tool, tool_handler, tool_router,
};

use serde::Serialize;

use crate::{Call, ChannelArgs, Client, DirectArgs, Empty, Failure, PostArgs, ReadArgs, Reply};

#[derive(Clone)]
struct Shim {
    client: Client,
    tools: ToolRouter<Self>,
}

#[derive(JsonSchema, Serialize)]
struct ToolReply {
    reply: Reply,
}

impl IntoCallToolResult for Failure {
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        CallToolResult::error(vec![ContentBlock::text(self.to_string())]).into_call_tool_result()
    }
}

#[tool_router(router = tools)]
impl Shim {
    #[tool(description = "List agents available to this credential")]
    async fn list_agents(
        &self,
        Parameters(args): Parameters<Empty>,
    ) -> Result<Json<ToolReply>, Failure> {
        self.invoke(Call::ListAgents(args)).await
    }

    #[tool(description = "List channels available to this credential")]
    async fn list_channels(
        &self,
        Parameters(args): Parameters<Empty>,
    ) -> Result<Json<ToolReply>, Failure> {
        self.invoke(Call::ListChannels(args)).await
    }

    #[tool(description = "Post a message to a channel")]
    async fn post(
        &self,
        Parameters(args): Parameters<PostArgs>,
    ) -> Result<Json<ToolReply>, Failure> {
        self.invoke(Call::Post(args)).await
    }

    #[tool(description = "Send a direct message to an agent")]
    async fn dm(
        &self,
        Parameters(args): Parameters<DirectArgs>,
    ) -> Result<Json<ToolReply>, Failure> {
        self.invoke(Call::Dm(args)).await
    }

    #[tool(description = "Read recent messages from a channel")]
    async fn read(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<Json<ToolReply>, Failure> {
        self.invoke(Call::Read(args)).await
    }

    #[tool(description = "Check the authenticated agent session")]
    async fn status(
        &self,
        Parameters(args): Parameters<Empty>,
    ) -> Result<Json<ToolReply>, Failure> {
        self.invoke(Call::Status(args)).await
    }

    #[tool(description = "Pass the current communication turn in a channel")]
    async fn pass(
        &self,
        Parameters(args): Parameters<ChannelArgs>,
    ) -> Result<Json<ToolReply>, Failure> {
        self.invoke(Call::Pass(args)).await
    }

    async fn invoke(&self, call: Call) -> Result<Json<ToolReply>, Failure> {
        self.client
            .call(call)
            .await
            .map(|reply| Json(ToolReply { reply }))
    }
}

#[tool_handler(router = self.tools)]
impl ServerHandler for Shim {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        std::borrow::Cow::Borrowed(ProtocolVersion::known_up_to(
            &ProtocolVersion::LATEST_WITH_INITIALIZE,
        ))
    }
}

pub async fn serve_stdio(client: Client) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Shim {
        client,
        tools: Shim::tools(),
    }
    .serve(rmcp::transport::stdio())
    .await?
    .waiting()
    .await?;
    Ok(())
}
