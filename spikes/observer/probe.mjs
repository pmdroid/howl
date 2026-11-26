import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:net";
import { createInterface } from "node:readline";

const success = "HOWL_OBSERVER_BOUNDARY_OK";

async function checkBoundary() {
  assert.equal(process.getuid(), 65532);
  const processStatus = readFileSync("/proc/self/status", "utf8");
  assert.match(processStatus, /^CapEff:\s+0+$/m);
  assert.match(processStatus, /^CapBnd:\s+0+$/m);
  assert.match(processStatus, /^NoNewPrivs:\s+1$/m);
  assert.match(processStatus, /^Seccomp:\s+2$/m);
  assert.equal(readFileSync("/workspace/tracked.txt", "utf8"), "selected snapshot\n");
  assert.throws(() => writeFileSync("/workspace/tracked.txt", "changed"), { code: "EROFS" });
  assert.throws(() => statSync(process.env.HOWL_PROBE_HOST_PATH), { code: "ENOENT" });
  assert.throws(() => statSync("/var/run/docker.sock"), { code: "ENOENT" });
  assert.equal(process.env.SSH_AUTH_SOCK, undefined);
  writeFileSync("/scratch/observer-proof", success);
  await new Promise((resolve, reject) => {
    const socket = connect({ host: "192.0.2.1", port: 443 });
    socket.once("error", (error) => {
      if (error.code === "ENETUNREACH") resolve();
      else reject(error);
    });
    socket.once("connect", () => {
      socket.destroy();
      reject(new Error("observer has external network access"));
    });
    socket.setTimeout(2000, () => socket.destroy(new Error("expected a blocked network route")));
  });
  console.log(success);
}

async function runHarness() {
  let verified = false;
  const model = createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== "/v1/chat/completions") {
      response.writeHead(404).end();
      return;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const { messages, tools } = JSON.parse(Buffer.concat(chunks));
    const hasToolResult = messages.some((message) => message.role === "tool");
    const hasBashTool = tools?.some((tool) => tool.function.name === "bash");
    const command = "node /observer/probe.mjs --check-boundary";
    let delta;
    if (hasToolResult) {
      verified = messages.some(
        (message) => message.role === "tool" && JSON.stringify(message.content).includes(success),
      );
      delta = { content: verified ? "Observer boundary passed." : "Observer boundary failed." };
      if (!verified) console.error(JSON.stringify(messages.filter((message) => message.role === "tool")));
    } else if (hasBashTool) {
      delta = {
        tool_calls: [{
          index: 0,
          id: "call_boundary",
          type: "function",
          function: {
            name: "bash",
            arguments: JSON.stringify({
              command, description: "Check the observer fixture", workdir: "/workspace", timeout: 5000,
            }),
          },
        }],
      };
    } else {
      delta = { content: "Observer fixture" };
    }
    const emit = (choice) => response.write(`data: ${JSON.stringify({
      id: "chatcmpl-probe", object: "chat.completion.chunk", created: 1, model: "probe",
      choices: [{ index: 0, ...choice }],
    })}\n\n`);
    response.writeHead(200, { "content-type": "text/event-stream" });
    emit({ delta: { role: "assistant", ...delta }, finish_reason: null });
    emit({ delta: {}, finish_reason: delta.tool_calls ? "tool_calls" : "stop" });
    response.end("data: [DONE]\n\n");
  });
  await new Promise((resolve, reject) => {
    model.once("error", reject);
    model.listen(0, "127.0.0.1", resolve);
  });
  const baseURL = `http://127.0.0.1:${model.address().port}/v1`;
  const config = {
    model: "fixture/probe",
    small_model: "fixture/probe",
    provider: {
      fixture: {
        npm: "@ai-sdk/openai-compatible",
        options: { baseURL, apiKey: "synthetic-model-key" },
        models: { probe: { name: "Observer fixture", tool_call: true, limit: { context: 16000, output: 2048 } } },
      },
    },
    permission: { "*": "deny", bash: "allow" },
  };
  const harness = spawn("opencode", ["acp", "--pure", "--cwd", "/workspace"], {
    cwd: "/workspace",
    env: {
      ...process.env,
      OPENCODE_CONFIG_CONTENT: JSON.stringify(config),
      OPENCODE_DISABLE_MODELS_FETCH: "1",
      OPENCODE_DISABLE_AUTOUPDATE: "1",
      OPENCODE_DISABLE_DEFAULT_PLUGINS: "1",
    },
    stdio: ["pipe", "pipe", "inherit"],
  });
  const pending = new Map();
  harness.once("exit", (code) => {
    for (const { reject } of pending.values()) reject(new Error(`OpenCode exited with status ${code}`));
    pending.clear();
  });
  harness.once("error", (error) => {
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
  });
  const send = (message) => harness.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
  const lines = createInterface({ input: harness.stdout });
  lines.on("line", (line) => {
    const { id, method, result, error, params } = JSON.parse(line);
    if (method) {
      if (id !== undefined) {
        send({ id, error: { code: -32601, message: "client method disabled in observer fixture" } });
      } else if (params?.update?.sessionUpdate === "tool_call_update" && params.update.status === "failed") {
        console.error(JSON.stringify(params.update));
      }
      return;
    }
    const request = pending.get(id);
    if (request) {
      pending.delete(id);
      if (error) request.reject(new Error(JSON.stringify(error)));
      else request.resolve(result);
    }
  });
  let id = 0;
  function request(method, params) {
    return new Promise((resolve, reject) => {
      id += 1;
      pending.set(id, { resolve, reject });
      send({ id, method, params });
    });
  }
  try {
    const initialized = await request("initialize", { protocolVersion: 1, clientCapabilities: {} });
    assert.equal(initialized.protocolVersion, 1);
    const { sessionId } = await request("session/new", { cwd: "/workspace", mcpServers: [] });
    const result = await request("session/prompt", {
      sessionId,
      prompt: [{ type: "text", text: "Run the observer fixture now." }],
    });
    assert.equal(result.stopReason, "end_turn");
    assert.equal(verified, true);
    assert.equal(readFileSync("/scratch/observer-proof", "utf8"), success);
    console.log(`OpenCode ${initialized.agentInfo?.version} ACP 1: ${success}`);
  } finally {
    harness.stdin.end();
    harness.kill();
    lines.close();
    model.close();
    model.closeAllConnections();
  }
}

if (process.argv[2] === "--check-boundary") await checkBoundary();
else await runHarness();
