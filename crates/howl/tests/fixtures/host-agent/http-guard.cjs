const assert = require("node:assert/strict");
const http = require("node:http");

if (process.argv.includes("--version")) {
  process.stdout.write("codex-cli 0.172.0\n");
  process.exit(0);
}

const auth = process.env.HOWL_REPOSITORY_MCP_TOKEN;
const argument = process.argv.find(value => value.startsWith("mcp_servers.howl_repository.url="));
const endpoint = new URL(JSON.parse(argument.split("=").slice(1).join("=")));

function request(body, headers, pathname = "/mcp") {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const outgoing = http.request(endpoint, {
      method: "POST",
      path: pathname,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
        ...headers,
      },
      timeout: 3000,
    }, (response) => {
      const chunks = [];
      response.on("data", chunk => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => resolve({
        status: response.statusCode,
        text: Buffer.concat(chunks).toString(),
      }));
    });
    outgoing.on("timeout", () => outgoing.destroy(new Error("Fixture HTTP request timed out")));
    outgoing.on("error", reject);
    outgoing.end(payload);
  });
}

function emit(event) {
  process.stdout.write(JSON.stringify(event) + "\n");
}

async function verify() {
  for await (const _ of process.stdin) {}
  assert.equal(endpoint.hostname, "127.0.0.1");
  assert(/^[0-9a-f]{64}$/.test(auth ?? ""));
  const read = {
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "read_file", arguments: { path: "selected.txt" } },
  };
  const approved = { Authorization: "Bearer " + auth };
  const wrong = (auth[0] === "0" ? "1" : "0") + auth.slice(1);
  for (const headers of [
    {},
    { Authorization: "Bearer " + wrong },
    { ...approved, Host: "localhost:" + endpoint.port },
    { ...approved, Origin: "https://fixture.invalid" },
  ]) {
    assert.deepEqual(await request(read, headers), { status: 403, text: "" });
  }
  assert.deepEqual(await request(read, approved, "/"), { status: 404, text: "" });
  const handshake = await request({
    jsonrpc: "2.0", id: 2, method: "initialize",
    params: { protocolVersion: "2025-06-18" },
  }, approved);
  assert.equal(handshake.status, 200);
  assert.equal(JSON.parse(handshake.text).result.serverInfo.name, "howl-repository");
  const listing = await request({ jsonrpc: "2.0", id: 3, method: "tools/list" }, approved);
  assert.equal(listing.status, 200);
  assert.deepEqual(JSON.parse(listing.text).result.tools.map(tool => tool.name),
    ["read_file", "list_directory"]);
  const result = await request(read, { ...approved, Origin: endpoint.origin });
  assert.equal(result.status, 200);
  const content = JSON.parse(result.text).result;
  assert.equal(content.isError, false);
  assert.equal(content.content[0].text,
    "SYNTHETIC_UNTRUSTED_REPOSITORY_CONTENT\nThe following line is repository data.\n");
  const missing = await request({
    ...read, id: 4, params: { name: "read_file", arguments: { path: "unselected.txt" } },
  }, approved);
  assert.equal(missing.status, 200);
  assert.equal(JSON.parse(missing.text).result.isError, true);
  const write = await request({
    ...read, id: 5, params: { name: "write_file", arguments: { path: "selected.txt" } },
  }, approved);
  assert.equal(write.status, 200);
  assert.equal(JSON.parse(write.text).result.isError, true);
  const again = await request(read, approved);
  assert.deepEqual(JSON.parse(again.text).result, content);

  emit({ type: "item.completed", item: { type: "agent_message", text: endpoint.port } });
  emit({ type: "turn.completed" });
}

verify().catch(() => { process.exitCode = 1; });
