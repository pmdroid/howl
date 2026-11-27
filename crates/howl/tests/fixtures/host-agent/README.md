# Host Claude Code and Docker repository tools

Use a native Claude Code installation that is already signed in. Set the paths to Node.js 24 or newer, the native Claude Code executable, and the executable from the Claude ACP adapter. The smoke test uses the v0.109.0 adapter.

```sh
export HOWL_HOST_NODE=$(command -v node)
export HOWL_HOST_CLAUDE=$(command -v claude)
export HOWL_HOST_CLAUDE_ADAPTER=/absolute/path/to/claude-agent-acp
export HOWL_OBSERVER_DOCKER_SOCKET=/absolute/path/to/docker.sock
export DOCKER_HOST="unix://$HOWL_OBSERVER_DOCKER_SOCKET"
docker pull node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
export HOWL_HOST_REPOSITORY_IMAGE=$(docker image inspect --format '{{.Id}}' node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d)
cargo test --locked -p howl --test host_agents host_acp_uses_only_the_docker_repository_mcp -- --ignored
cargo test --locked -p howl --test host_agents live_host_claude -- --ignored
```

The live test uses Claude Code's native login for inference. The repository tool reads a committed file from the selected Docker snapshot. The fixture test checks the scoped tool permission and rejects unselected paths.

## Host Grok Build

Use the native Grok Build 1.0.92 CLI with an existing login. Set the Node, Docker socket, and repository image as above. Set the absolute paths to the CLI and its existing native login profile.

```sh
export HOWL_HOST_GROK=$(command -v grok)
export HOWL_HOST_GROK_AUTH_PATH="$HOME/.grok/auth.json"
cargo test --locked -p howl --test host_agents live_host_grok -- --ignored
```
