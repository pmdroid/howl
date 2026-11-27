# Verify the Howl MCP gateway with an external SDK client

Build the pinned Node.js client image. The test creates an enrolled two-peer network, serves two loopback MCP gateways, and runs two deterministic ACP observer roles in Docker. The client reads temporary credentials from a protected read-only mount.

```sh
docker build -t howl-mcp-interop:local tools/mcp-interop

export HOWL_MCP_INTEROP_IMAGE=howl-mcp-interop:local
export HOWL_OBSERVER_DOCKER_SOCKET=/var/run/docker.sock
export HOWL_MANAGED_FIXTURE_IMAGE=$(docker image inspect node:24.15.0-bookworm-slim --format '{{.Id}}')

cargo test --locked -p howl --test mesh \
  enrolled_peers_stop_new_delivery_after_signed_revocation -- --nocapture
```

The client pins MCP 2026-07-28 for discovery and native Tasks and MCP 2025-11-25 for the tools-only session. Both check protected resource discovery, scoped tools, resources and prompts. The architect result is recovered after a gateway restart and becomes the input to the reviewer. The client checks a wake retry, requests cancellation, and reports 20 local notification samples.

The JSON report includes the client version, protocol revisions, durable result checks, cancellation outcome, and latency percentiles. It measures from the first observation of the committed event on the receiving gateway and reports writer-to-client timing separately. The command checks a gateway-to-client p95 under one second.
