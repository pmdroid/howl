# Run a self-hosted Howl MCP gateway

Run the gateway on an enrolled Howl device with an active signed roster for each channel you want to share. The gateway is a separate process from the mesh daemon. Its default listener is `127.0.0.1:8470`, and it serves MCP at `/mcp`.

Start the mesh on the enrolled device and keep its signed routes current. A client-only device can run the gateway while observer agents run on their own mesh peers.

```sh
howl mesh run --client-only "$HOWL_STATE" 127.0.0.1:0
```

## Give an integration access

Generate a bearer token and store the plaintext in a protected file. Give that token to the named MCP integration through its credential store. The gateway grant stores a SHA-256 digest of the token bytes without the trailing newline.

```sh
umask 077
openssl rand -hex 32 > integration.token
printf '%s' "$(cat integration.token)" | openssl dgst -sha256 -r
```

Create a grant file readable by the gateway service account. Set `resource` to the exact address the client will use, including the port when present. Set `expires_at` to the expiry as Unix seconds and `channels` to the signed channel identifiers this integration may access.

```json
{
  "resource": "http://127.0.0.1:8470/mcp",
  "requests_per_minute": 120,
  "grants": [
    {
      "id": "observer-reader",
      "token_sha256": "<SHA-256 digest>",
      "expires_at": 1795800000,
      "channels": ["<channel ID>"],
      "permissions": ["read"]
    }
  ]
}
```

Start the gateway with the enrolled device state and grants file.

```sh
chmod 600 grants.json
howl mcp serve "$HOWL_STATE" grants.json
```

Configure the MCP client to use the Streamable HTTP endpoint and set `Authorization: Bearer <token>` through its credential configuration. The gateway advertises its protected resource metadata in the authentication challenge. Serve both `/mcp` and `/.well-known/oauth-protected-resource/mcp` through the same public origin.

| Permission | What the integration can do |
| --- | --- |
| `read` | Discover authorized channels and agents, read channel messages and events, fetch run state and results owned by the integration |
| `send` | Send signed messages to authorized channel members |
| `wake` | Request bounded observer runs for a named peer with an existing wake grant |
| `cancel` | Request cancellation of runs owned by the integration |

Choose the smallest permission set and list each channel explicitly. Use a separate grant ID and token for each integration. Rotate a token by atomically replacing the grant file with the new digest and expiry under the same integration ID. Revoke it by removing its record. The gateway checks the current grant on each request. Clients using legacy MCP sessions reconnect after rotation.

## Connect over a private tunnel or HTTPS

For a private SSH tunnel, keep the service on loopback and forward the same local port from the machine running the MCP client.

```sh
ssh -N -L 8470:127.0.0.1:8470 operator@gateway-host
```

For HTTPS, set `resource` to the HTTPS URL and put the proxy on the gateway host. The gateway validates the request's configured authority. Preserve the incoming Host header and disable response buffering for event streams. Configure `allowed_origins` with exact trusted browser origins when browser clients are in use.

```nginx
server {
    listen 443 ssl;
    server_name howl-mcp.example.net;
    ssl_certificate /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/privkey.pem;

    location ~ ^/(mcp|\.well-known/oauth-protected-resource/mcp)$ {
        proxy_pass http://127.0.0.1:8470;
        proxy_set_header Host $http_host;
        proxy_set_header Connection "";
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 65s;
        gzip off;
    }
}
```

## Handle channel data and observer approvals

Treat the gateway host and the integration as recipients of the channel data they can read. The enrolled gateway opens messages locally and returns the authorized content to the integration. Review the selected channels and obtain participant consent for integrations that consume events. Include the integration operator and the observer provider in that review, since each receives the content delivered to it.

Keep human approval on the enrolled operator device. The operator sets the signed channel roster and wake grants and approves observer work against the authorized repository snapshot. The gateway signs integration-origin messages with the enrolled device and records the integration identifier separately from human chat or an agent reply.

The gateway emits request audit entries with the integration ID, HTTP method, and response status. Protect its service logs and keep credentials and payloads out of reverse-proxy log formats. Mesh peers continue to exchange encrypted signed envelopes. Keep the gateway bound to loopback when running a same-host proxy or private tunnel.

## Talk to an ongoing agent

On the agent's mesh node, create a `conversations.json` file in its state directory with mode `600`. Each entry grants one signed peer access to an ongoing conversation and selects the read-only repository snapshot for that conversation.

```json
{
  "conversations": [
    {
      "channel": "<channel ID>",
      "peer": "<operator device ID>",
      "repository": "/absolute/path/to/repo",
      "revision": "main",
      "schedules": [
        { "name": "check-in", "seconds": 3600, "instruction": "Summarize decisions from this conversation." }
      ]
    }
  ]
}
```

With that node's mesh daemon running, start `howl agent serve "$HOWL_STATE" claude "$HOWL_REPOSITORY_IMAGE"` using the environment for the selected host agent. In the TUI, select the agent as a direct peer and send a message. For MCP, configure a conversation entry with `integration` set to the signed integration ID shown in the gateway's chat events. Send through the `dm` tool and read the same direct conversation. When using direct routing, set `route` to the configured peer address.

### Run an isolated worker

Install an ARM64 QEMU binary with HVF or KVM. Create a mode `600` file named `microvm.json` in the agent's state directory with absolute paths to the QEMU binary, a Linux kernel and a trusted initramfs. Set `memory_mib` and `vcpus` for each worker. To make model calls through Howl's guest provider bridge, add `provider` with the `provider` name (`openai` or `xai`) and `model`, and set the corresponding provider key in the host runner's environment.

The guest init extracts the read-only tar disk at `/dev/vda` into its writable `/workspace`. Identify the serial ports by name in `/sys/class/virtio-ports`. The guest sends `HOWL_ACP_READY` followed by a newline on `howl.acp`, then runs its ACP adapter over that port. At teardown it returns an eight-byte big-endian patch length and the patch bytes on `howl.patch`. Set the length to zero for a worker that produced no patch. For inference, run `crates/howl/src/provider_bridge.cjs` in the guest over `howl.provider`, and configure the guest's agent to use its loopback endpoint.

For an existing Howl ChatGPT plan connection, set the profile's provider to `chatgpt_plan` and choose a model available to that connection. Set `HOWL_CHATGPT_NODE` to the absolute Node executable path, `HOWL_CHATGPT_HELPER` to the path of `tools/chatgpt-auth/chatgpt-auth.mjs`, and `HOWL_CHATGPT_STORE` to the existing credential directory. The host broker uses the connection to make requests for the guest. The guest uses the local provider bridge.

```sh
howl worker run "$HOWL_STATE" /path/to/repo main < instruction.txt
```

Worker patches are saved under `worker-patches` in the node's state directory.

Set `"work": true` on a conversation to give its ongoing agent the `start_work` tool. It launches a separate ACP worker and returns a run ID. Send `/work RUN`, `/steer RUN MESSAGE`, or `/cancel RUN` in the same TUI DM or through MCP `dm` to check status, send feedback, or cancel. To give an integration permission to steer work from a human conversation, add its signed integration ID to that conversation's `work_control_from` list.

To let the agent contact other agents in the signed channel, add a `peers` list to its conversation. Each entry takes an `id` and optional `name` and `route`. The `send_peer` tool sends a signed DM and brings a matching peer reply back into the initiating conversation.

## Deliver events to a webhook

Give the webhook worker its own protected JSON configuration. Run it with the enrolled node state and pair each endpoint with the channels and event types the receiver has consent to process. Use metadata-only delivery when a receiver only needs to acknowledge or route an event. Set `include_content` to `true` when the receiver needs message content and the participants have authorized its disclosure.

```json
{
  "endpoints": [
    {
      "name": "observer-events",
      "url": "https://receiver.example.net/howl",
      "signing_secret": "<32 random bytes encoded as 64 hex characters>",
      "channels": ["<channel ID>"],
      "events": ["agent.reply", "run.completed", "run.failed"],
      "enabled": true,
      "include_content": false,
      "allow_private_ips": []
    }
  ]
}
```

```sh
chmod 600 webhooks.json
howl webhook run "$HOWL_STATE" webhooks.json
howl webhook status "$HOWL_STATE"
```

Verify the `Webhook-Signature` header using HMAC-SHA256 over the exact `Webhook-Id`, a period, `Webhook-Timestamp`, a period, and the raw JSON request bytes. The header begins with `v1,` followed by the base64 signature. Verify it with the decoded signing secret before parsing the request body. Check the timestamp against a short acceptance window and store processed webhook IDs so deliveries and manual replays remain idempotent.

For a private receiver, add its exact allowed IP to `allow_private_ips`. The worker validates resolved addresses before connecting. A local fixture can use HTTP with an explicitly allowed literal loopback IP. Use HTTPS for receivers reached over the network.

For an approved replay, obtain the destination and event ID from `howl webhook status`. The receiver continues to see the same event ID.

```sh
howl webhook replay "$HOWL_STATE" webhooks.json observer-events "$HOWL_EVENT_ID"
```

Rotate the signing secret or disable an endpoint by atomically replacing its protected config. Replace the receiver key together with the sender key. The worker binds queued events to the active endpoint configuration and checks channel access before sending. Its delivery status includes the endpoint name, event ID, attempt and outcome.

### Trigger a Grok Bot routine

Add a webhook trigger to the routine in Grok Bot. Copy the routine's **POST to** URL and **key** into an endpoint in the protected webhook configuration. [Grok Bot webhook setup](https://docs.x.ai/grok-bot/skills-routines-and-automations#webhooks)

```json
{
  "endpoints": [
    {
      "name": "grok-bot",
      "url": "<routine POST to URL>",
      "grok_bot_key": "<routine key>",
      "channels": ["<channel ID>"],
      "events": ["run.completed"],
      "enabled": true,
      "include_content": false
    }
  ]
}
```

Howl delivers the event as JSON with the routine key in the `Authorization` header. HTTP 200 confirms the routine started. The routine can use its own Howl MCP connection to fetch context or send a follow-up.
