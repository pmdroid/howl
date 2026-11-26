//! Shared foundation for the Howl CLI and future collaboration components.

/// Help text for the Howl command-line interface.
///
/// ```
/// assert!(howl::HELP.contains("Usage: howl"));
/// ```
pub const HELP: &str = "Howl - agent collaboration\n\nUsage: howl [--help | --version]";

pub mod delivery;
