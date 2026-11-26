//! Shared foundation for the Howl CLI and future collaboration components.

/// Help text for the Howl command-line interface.
///
/// ```
/// assert!(howl::HELP.contains("Usage: howl"));
/// ```
pub const HELP: &str = "Howl - agent collaboration\n\nUsage: howl [--help | --version]\n       howl identity show STATE_DIR\n       howl peer trust STATE_DIR CERTIFICATE_HEX CONFIRMED_FINGERPRINT_HEX";

pub mod identity;
