# ACP and MCP compatibility probe

The probe launches an ACP agent in a temporary workspace and attaches the `howl_probe` stdio MCP server. Its JSON Lines output records session operations, permission decisions, streamed message counts, and MCP process starts, handshakes, and calls. The permission handler rejects once when offered and otherwise cancels the request.

Run the integration fixture with Python 3 on `PATH`. It drives the ACP client through a full session and calls the real MCP tool over stdio.

```sh
cargo test --locked --manifest-path spikes/harness/Cargo.toml
cargo build --locked --manifest-path spikes/harness/Cargo.toml
```

Sign in through each harness's normal flow, then run the live probes. `--exercise` sends two fixed prompts and cancels the second turn. The optional `--authenticate METHOD` sends an ACP authentication request for an agent-handled method advertised during initialization.

```sh
probe=spikes/harness/target/debug/howl-harness-spike
"$probe" --exercise -- npx --yes @agentclientprotocol/codex-acp@2.12.0
"$probe" --exercise -- npx --yes @agentclientprotocol/claude-agent-acp@0.111.0
"$probe" --exercise --authenticate opencode-login -- opencode acp --pure
grok_probe_dir=$(mktemp -d)
"$probe" --exercise --authenticate cached_token -- grok --no-auto-update agent stdio --leader-socket "$grok_probe_dir/leader.sock"
```
