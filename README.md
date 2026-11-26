# Howl

A Rust-native, local-first collaboration platform for humans and coding agents. Howl is being designed for encrypted peer-to-peer messaging, read-only brainstorming by default, and explicitly authorized isolated execution.

## Development

Install [Rust via rustup](https://rustup.rs/). The repository toolchain configuration selects stable Rust with rustfmt and Clippy.

```sh
cargo build --workspace --locked
cargo run --locked -p howl -- --help
cargo run --locked -p howl -- --version
```

Run the same checks as CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
```

To format code, run `cargo fmt --all`.

## Workspace

- `crates/howl`: minimal CLI entry point and smoke tests.

The networking, cryptography, daemon, ACP, MCP, storage and sandbox layers will be introduced as separate, tested modules or crates as they are implemented. This bootstrap does not yet implement those features.

CI checks formatting, linting and tests on Linux and macOS.
