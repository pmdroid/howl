use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_READ: u16 = 32;
const MAX_TEXT_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Managed,
    External,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct AgentPrincipal {
    pub agent: String,
    pub session: String,
    pub generation: u64,
    pub kind: AgentKind,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Tool {
    ListAgents,
    ListChannels,
    Post,
    Dm,
    Read,
    Status,
    Pass,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelArgs {
    pub channel: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PostArgs {
    pub channel: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectArgs {
    pub agent: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    pub channel: String,
    pub limit: Option<u16>,
}

impl ReadArgs {
    pub fn limit(&self) -> usize {
        usize::from(self.limit.unwrap_or(20))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum Call {
    ListAgents(Empty),
    ListChannels(Empty),
    Post(PostArgs),
    Dm(DirectArgs),
    Read(ReadArgs),
    Status(Empty),
    Pass(ChannelArgs),
}

impl Call {
    pub fn tool(&self) -> Tool {
        match self {
            Self::ListAgents(_) => Tool::ListAgents,
            Self::ListChannels(_) => Tool::ListChannels,
            Self::Post(_) => Tool::Post,
            Self::Dm(_) => Tool::Dm,
            Self::Read(_) => Tool::Read,
            Self::Status(_) => Tool::Status,
            Self::Pass(_) => Tool::Pass,
        }
    }

    pub(crate) fn channel(&self) -> Option<&str> {
        match self {
            Self::Post(args) => Some(&args.channel),
            Self::Read(args) => Some(&args.channel),
            Self::Pass(args) => Some(&args.channel),
            _ => None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Failure> {
        let valid_text = |text: &str| !text.is_empty() && text.len() <= MAX_TEXT_BYTES;
        let valid = self.channel().is_none_or(valid_id)
            && match self {
                Self::Post(args) => valid_text(&args.text),
                Self::Dm(args) => valid_id(&args.agent) && valid_text(&args.text),
                Self::Read(args) => args
                    .limit
                    .is_none_or(|limit| (1..=MAX_READ).contains(&limit)),
                _ => true,
            };
        if valid { Ok(()) } else { Err(Failure::Invalid) }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct Agent {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct Channel {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct Message {
    pub channel: String,
    pub sender: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    Agents { agents: Vec<Agent> },
    Channels { channels: Vec<Channel> },
    Posted { id: String },
    Messages { messages: Vec<Message> },
    Status { principal: AgentPrincipal },
    Passed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Denied,
    Invalid,
    Unavailable,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::Denied => "operation denied",
            Self::Invalid => "invalid tool arguments",
            Self::Unavailable => "communications unavailable",
        })
    }
}

impl std::error::Error for Failure {}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
