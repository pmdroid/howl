//! Shared foundation for the Howl CLI and future collaboration components.

/// Help text for the Howl command-line interface.
///
/// ```
/// assert!(howl::HELP.contains("Usage: howl"));
/// ```
pub const HELP: &str = "Howl - agent collaboration\n\nUsage: howl [--help | --version]\n       howl identity show STATE_DIR\n       howl peer trust STATE_DIR CERTIFICATE_HEX CONFIRMED_FINGERPRINT_HEX\n       howl channel create STATE_DIR [PEER_DEVICE_ID ...]\n       howl channel join STATE_DIR MANIFEST_HEX\n       howl mesh run STATE_DIR LISTEN_ADDR [RELAY_URL]\n       howl mesh stop STATE_DIR\n       howl control login STATE_DIR\n       howl control enroll STATE_DIR AUTHORITY_STATE_DIR DESIGNATION_FILE CERTIFICATE_FILE\n       howl mesh hint export STATE_DIR LISTEN_ADDR\n       howl mesh hint import STATE_DIR SIGNED_HINT_HEX\n       howl mesh mailbox fetch STATE_DIR\n       howl mesh hint publish STATE_DIR LISTEN_ADDR\n       howl mesh hint fetch STATE_DIR PEER_DEVICE_ID\n       howl send STATE_DIR CHANNEL_ID PEER_DEVICE_ID PEER_ADDR_OR_DASH < MESSAGE_FILE\n       howl read STATE_DIR CHANNEL_ID\n       howl status STATE_DIR CHANNEL_ID MESSAGE_ID\n       howl workflow id STATE ROLE\n       howl workflow grant STATE CHANNEL PEER_DEVICE ROLE GENERATION\n       howl workflow wake STATE CHANNEL PEER_DEVICE PEER_ADDR TARGET TTL < MESSAGE_FILE\n       howl workflow next STATE CHANNEL ROLE\n       howl workflow run STATE CHANNEL ROLE EXECUTION PEER_ADDR DRIVER REPO COMMIT IMAGE [--context MESSAGE] [--cause TURN] -- PATH [PATH ...]\n       howl workflow recover STATE\n\nHosted login reads HOWL_CONTROL_URL and HOWL_CONTROL_AUDIENCE.\n\nWorkflow roles: architect, reviewer. Drivers: claude, grok, codex.\nWorkflow run reads HOWL_OBSERVER_DOCKER_SOCKET and HOWL_HOST_NODE.\nClaude: HOWL_HOST_CLAUDE and HOWL_HOST_CLAUDE_ADAPTER.\nGrok: HOWL_HOST_GROK and HOWL_HOST_GROK_AUTH_PATH.\nCodex: HOWL_HOST_CODEX, with optional CODEX_HOME.";

pub mod enrollment;
pub mod identity;
pub mod transport;

pub mod channel;

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

pub mod workflow;
