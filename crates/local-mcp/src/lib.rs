mod ipc;
mod model;
mod policy;
mod stdio;

pub use ipc::{Client, Daemon};
pub use model::{
    Agent, AgentKind, AgentPrincipal, Call, Channel, ChannelArgs, DirectArgs, Empty, Failure,
    Message, PostArgs, ReadArgs, Reply, Tool,
};
pub use policy::{Authority, Credential, Scope};
pub use stdio::serve_stdio;

pub trait Communications: Send + 'static {
    fn invoke(&mut self, caller: &AgentPrincipal, call: &Call) -> Result<Reply, Failure>;
}
