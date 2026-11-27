//! Shared foundation for the Howl CLI and future collaboration components.

/// Help text for the Howl command-line interface.
///
/// ```
/// assert!(howl::HELP.contains("Usage: howl"));
/// ```
pub const HELP: &str = "Howl - agent collaboration\n\nUsage: howl [--help | --version]\n       howl identity show STATE_DIR\n       howl peer trust STATE_DIR CERTIFICATE_HEX CONFIRMED_FINGERPRINT_HEX\n       howl channel create STATE_DIR [PEER_DEVICE_ID ...]\n       howl channel join STATE_DIR MANIFEST_HEX\n       howl mesh run STATE_DIR LISTEN_ADDR [RELAY_URL]\n       howl mesh stop STATE_DIR\n       howl send STATE_DIR CHANNEL_ID PEER_DEVICE_ID PEER_ADDR < MESSAGE_FILE\n       howl read STATE_DIR CHANNEL_ID\n       howl status STATE_DIR CHANNEL_ID MESSAGE_ID";

pub mod identity;
pub mod transport;

pub mod channel;

mod local_control;
pub mod node;

pub mod delivery;
pub mod observer;
pub mod presence;

pub mod managed_acp;

pub mod provider_broker;
