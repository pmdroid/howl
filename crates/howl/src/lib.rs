//! Shared foundation for the Howl CLI and future collaboration components.

/// Help text for the Howl command-line interface.
///
/// ```
/// assert!(howl::HELP.contains("Usage: howl"));
/// ```
pub const HELP: &str = "Howl - agent collaboration\n\nUsage: howl [--help | --version]\n       howl enrollment --help\n       howl roster issue STATE CHANNEL_OR_DASH active|paused [DEVICE:PERMISSIONS ...]\n       howl roster apply STATE CHANNEL PROOF_HEX\n       howl roster show STATE CHANNEL\n       howl roster revoke STATE CHANNEL DEVICE SEQUENCE\n       howl roster apply-revocation STATE CHANNEL PROOF_HEX\n       howl identity show STATE_DIR\n       howl web STATE_DIR [PORT]\n       howl tui STATE_DIR\n       howl mcp serve STATE_DIR GRANTS_FILE [LISTEN_ADDR]\n       howl webhook run STATE_DIR CONFIG_FILE\n       howl webhook status STATE_DIR\n       howl webhook replay STATE_DIR CONFIG_FILE ENDPOINT EVENT_ID\n       howl peer trust STATE_DIR CERTIFICATE_HEX CONFIRMED_FINGERPRINT_HEX\n       howl channel create STATE_DIR [PEER_DEVICE_ID ...]\n       howl channel join STATE_DIR MANIFEST_HEX\n       howl mesh run [--client-only] STATE_DIR LISTEN_ADDR [RELAY_URL]\n       howl mesh stop STATE_DIR\n       howl control login STATE_DIR\n       howl control enroll STATE_DIR AUTHORITY_STATE_DIR DESIGNATION_FILE CERTIFICATE_FILE\n       howl mesh hint export STATE_DIR LISTEN_ADDR\n       howl mesh hint import STATE_DIR SIGNED_HINT_HEX\n       howl mesh hint publish STATE_DIR LISTEN_ADDR\n       howl mesh hint fetch STATE_DIR PEER_DEVICE_ID\n       howl mesh mailbox deposit STATE_DIR PEER_DEVICE_ID [AFTER_CURSOR]\n       howl mesh mailbox fetch STATE_DIR\n       howl send STATE_DIR CHANNEL_ID PEER_DEVICE_ID PEER_ADDR_OR_DASH < MESSAGE_FILE\n       howl read STATE_DIR CHANNEL_ID\n       howl agents STATE_DIR CHANNEL_ID\n       howl events STATE_DIR CHANNEL_ID [AFTER_CURSOR]\n       howl status STATE_DIR CHANNEL_ID MESSAGE_ID\n       howl workflow id STATE\n       howl workflow grant STATE CHANNEL PEER_DEVICE GENERATION\n       howl workflow wake STATE CHANNEL PEER_DEVICE PEER_ADDR TTL < MESSAGE_FILE\n       howl workflow next STATE CHANNEL\n       howl workflow run STATE CHANNEL EXECUTION PEER_ADDR DRIVER REPO COMMIT IMAGE [--edit|--repo-read] [--context MESSAGE] [--cause TURN] -- [PATH ...]\n       howl workflow status STATE CHANNEL\n       howl workflow cancel STATE CHANNEL ROOT\n       howl workflow recover STATE\n\nHosted login reads HOWL_CONTROL_URL and HOWL_CONTROL_AUDIENCE.\nWithout stored credentials, hosted discovery also reads HOWL_CONTROL_SESSION_ID and HOWL_CONTROL_ACCESS_TOKEN.\n\nWorkflow drivers: claude, grok, codex, opencode.\nWorkflow run reads HOWL_OBSERVER_DOCKER_SOCKET and HOWL_HOST_NODE.\nClaude: HOWL_HOST_CLAUDE and HOWL_HOST_CLAUDE_ADAPTER.\nGrok: HOWL_HOST_GROK and HOWL_HOST_GROK_AUTH_PATH.\nCodex: HOWL_HOST_CODEX, with optional CODEX_HOME.\nOpenCode Go: HOWL_HOST_OPENCODE, HOWL_HOST_OPENCODE_DATA_HOME, and optional HOWL_HOST_OPENCODE_MODEL.";

pub mod enrollment;
pub mod identity;
pub mod project;
pub mod transport;

pub mod channel;
pub mod interaction;

mod local_control;
pub mod mailbox_client;
pub mod node;

pub mod control_client;
pub mod control_proof;
pub mod delivery;
pub mod discovery;
pub mod discovery_client;
pub mod observer;
pub mod presence;

pub mod managed_acp;

pub mod provider_broker;
pub mod remote_mcp;
mod remote_mcp_handler;
pub use remote_mcp_handler::serve_gateway;

pub mod tui;
pub mod workflow;

pub mod web;
pub mod webhooks;
