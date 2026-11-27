const assert = require("node:assert/strict");
const { existsSync } = require("node:fs");
const { spawn } = require("node:child_process");
const { createInterface } = require("node:readline");

let server;
let prompt;

function send(message) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
}

async function runTools() {
  const child = spawn(server.command, server.args, { stdio: ["pipe", "pipe", "inherit"] });
  const responses = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  let id = 0;
  async function request(method, params) {
    const requestId = ++id;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }) + "\n");
    const { value, done } = await responses.next();
    assert(!done);
    const reply = JSON.parse(value);
    assert.equal(reply.id, requestId);
    assert(!reply.error);
    return reply.result;
  }
  try {
    const handshake = await request("initialize", { protocolVersion: "2025-06-18" });
    assert.equal(handshake.serverInfo.name, "howl-repository");
    const list = await request("tools/list");
    if (process.env.HOWL_EDITABLE_WORKSPACE === "1") {
      assert.deepEqual(list.tools.map(tool => tool.name),
        ["read_file", "list_directory", "write_file", "delete_file", "run_tests"]);
      const tool = (name, args) => request("tools/call", { name, arguments: args });
      assert.equal((await tool("write_file", { path: "../outside", content: "blocked" })).isError, true);
      assert.equal((await tool("write_file", { path: "selected.txt", content: "edited" })).isError, false);
      assert.equal((await tool("write_file", { path: "new.txt", content: "new" })).isError, false);
      assert.equal((await tool("delete_file", { path: "removed.txt" })).isError, false);
      const test = await tool("run_tests", { argv: ["node", "--test", "workspace.test.cjs"] });
      assert.equal(test.isError, false);
      assert.match(test.content[0].text, /Exit 0/);
      return "Docker edit and tests completed";
    }
    assert.deepEqual(list.tools.map(tool => tool.name), ["read_file", "list_directory"]);
    const call = (name, path) => request("tools/call", { name, arguments: { path } });
    const result = await call("read_file", "selected.txt");
    assert.equal(result.isError, false);
    assert.equal(result.content[0].text.trim(), "HOWL_HOST_REPOSITORY_OK");
    for (const path of ["unselected.txt", "../../etc/passwd", "/etc/passwd"]) {
      assert.equal((await call("read_file", path)).isError, true);
    }
    const listing = await call("list_directory", "");
    const files = JSON.parse(listing.content[0].text).entries;
    assert.deepEqual(files.map(entry => entry.name), ["selected.txt"]);
    return result.content[0].text;
  } finally {
    child.stdin.end();
  }
}

async function run() {
  for await (const line of createInterface({ input: process.stdin })) {
    const { id, method, params, result } = JSON.parse(line);
    if (id === 101) {
      assert.equal(result.outcome.optionId, "deny");
      continue;
    }
    if (id === 102) {
      assert.equal(result.outcome.optionId, "allow");
      send({
        method: "session/update",
        params: { sessionId: "host-fixture", update: {
          sessionUpdate: "agent_message_chunk", content: { type: "text", text: await runTools() },
        } },
      });
      send({ id: prompt, result: { stopReason: "end_turn" } });
      continue;
    }
    switch (method) {
      case "initialize":
        send({ id, result: { protocolVersion: 1, agentCapabilities: { sessionCapabilities: { close: {} } } } });
        break;
      case "session/new":
        assert.equal(params.cwd, process.cwd());
        assert.equal(existsSync("selected.txt"), false);
        assert.equal(params.mcpServers.length, 1);
        server = params.mcpServers[0];
        assert.equal(server.name, "howl_repository");
        send({ id, result: { sessionId: "host-fixture" } });
        break;
      case "session/prompt":
        prompt = id;
        for (const [permission, name] of [[101, "mcp__other__read_file"], [102, "mcp__howl_repository__read_file"]]) {
          send({
            id: permission,
            method: "session/request_permission",
            params: {
              sessionId: "host-fixture",
              toolCall: { toolCallId: String(permission), name },
              options: [
                { optionId: "always", name: "Always", kind: "allow_always" },
                { optionId: "allow", name: "Allow", kind: "allow_once" },
                { optionId: "deny", name: "Deny", kind: "reject_once" },
              ],
            },
          });
        }
        break;
      case "session/close":
        send({ id, result: {} });
        return;
    }
  }
}

run().catch(() => { process.exitCode = 1; });
