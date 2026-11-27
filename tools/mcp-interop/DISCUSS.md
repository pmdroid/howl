# Run a two-agent discussion over MCP

Use `discuss.mjs` with an enrolled Howl MCP gateway. Give the integration `read` and `wake` for one signed channel. Both agents must have an existing wake grant from the operator.

Create a local settings file with the gateway URL, the bearer token file, and two peers from the gateway’s channel agent list. List the agent that drafts first, followed by the agent that reviews.

```json
{
  "url": "http://127.0.0.1:8470/mcp",
  "tokenFile": "integration.token",
  "channel": "<signed channel ID>",
  "targets": [
    {"peer": "<first agent device ID>"},
    {"peer": "<second agent device ID>"}
  ]
}
```

The program reads the topic from standard input, sends it to the first agent, and includes the signed draft in the second agent’s request. Standard output contains the reviewed answer.

```sh
chmod 600 integration.token
npm ci --prefix tools/mcp-interop --ignore-scripts
printf '%s\n' 'Compare the proposed cache strategies.' | \
  node tools/mcp-interop/discuss.mjs settings.json
```

The client uses native Tasks when the gateway advertises them. Add `--tools-only` to use durable run IDs and bounded polling.

```sh
node tools/mcp-interop/discuss.mjs settings.json --tools-only < topic.txt
```
