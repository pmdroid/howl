use rmcp::{
    RoleServer, ServerHandler, ServiceExt,
    handler::server::router::tool::ToolRouter,
    model::{ServerCapabilities, ServerConfig},
    service::NotificationContext,
    tool, tool_handler, tool_router,
};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
struct ProbeServer {
    marker: Arc<PathBuf>,
    tools: ToolRouter<Self>,
}

#[tool_router(router = tools)]
impl ProbeServer {
    #[tool(description = "Return a fixed marker for the Howl compatibility test")]
    fn howl_probe(&self) -> Result<String, String> {
        record(&self.marker, "call").map_err(|error| error.to_string())?;
        Ok("howl-probe-ok".to_owned())
    }
}

#[tool_handler(router = self.tools)]
impl ServerHandler for ProbeServer {
    async fn on_initialized(&self, _: NotificationContext<RoleServer>) {
        let _ = record(&self.marker, "initialized");
    }

    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

pub async fn serve(marker: PathBuf) -> anyhow::Result<()> {
    record(&marker, "start")?;
    ProbeServer {
        marker: Arc::new(marker),
        tools: ProbeServer::tools(),
    }
    .serve(rmcp::transport::stdio())
    .await?
    .waiting()
    .await?;
    Ok(())
}

fn record(marker: &Path, event: &str) -> io::Result<()> {
    writeln!(
        OpenOptions::new().create(true).append(true).open(marker)?,
        "{event}"
    )
}
