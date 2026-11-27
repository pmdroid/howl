const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { mkdtemp, readFile, rm } = require("node:fs/promises");
const { createServer } = require("node:net");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { createInterface } = require("node:readline");
const test = require("node:test");

test("loopback MCP authenticates and forwards consecutive requests on one private socket", { timeout: 10000 }, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), "howl-r-"));
  const socketPath = path.join(directory, "tools.sock");
  let connections = 0;
  const backend = createServer(socket => {
    connections++;
    const lines = createInterface({ input: socket });
    lines.on("line", line => {
      const { id, method } = JSON.parse(line);
      socket.write(JSON.stringify({ jsonrpc: "2.0", id, result: { method } }) + "\n");
    });
  });
  backend.listen(socketPath);
  await once(backend, "listening");
  const token = "ab".repeat(32);
  const script = path.join(__dirname, "../../../src/host_agents/repository-http.cjs");
  const bridge = spawn(process.execPath, ["-e", await readFile(script, "utf8"), socketPath], {
    env: { HOWL_REPOSITORY_MCP_TOKEN: token },
    stdio: ["pipe", "pipe", "inherit"],
  });
  t.after(async () => {
    const exited = once(bridge, "exit");
    if (bridge.exitCode === null) {
      bridge.kill();
      await exited;
    }
    await new Promise(resolve => backend.close(resolve));
    await rm(directory, { force: true, recursive: true });
  });
  const lines = createInterface({ input: bridge.stdout });
  const [port] = await once(lines, "line");
  const url = "http://127.0.0.1:" + port + "/mcp";
  const json = (id, method) => JSON.stringify({ jsonrpc: "2.0", id, method });
  const headers = { Authorization: "Bearer " + token, "Content-Type": "application/json" };
  assert.equal((await fetch(url, { method: "POST", body: json(1, "initialize") })).status, 403);
  assert.equal((await fetch(url, {
    method: "POST",
    body: json(1, "initialize"),
    headers: { ...headers, Origin: "https://unrelated.example" },
  })).status, 403);
  assert.equal((await fetch(url, { headers })).status, 405);
  for (const [index, method] of ["initialize", "tools/list", "tools/call"].entries()) {
    const id = index + 1;
    const reply = await fetch(url, { method: "POST", headers, body: json(id, method) });
    assert.equal(reply.status, 200);
    assert.deepEqual(await reply.json(), { jsonrpc: "2.0", id, result: { method } });
  }
  assert.equal(connections, 1);
});
