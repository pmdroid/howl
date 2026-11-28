import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import { userInfo } from "node:os";
import { isAbsolute } from "node:path";

const {
  HOWL_AGENT_CWD: scratch, HOWL_CODEX_EXECUTABLE: executable, HOWL_CODEX_HOME: home,
  HOWL_CODEX_STATE_HOME: stateHome, HOWL_REPOSITORY_MCP_URL: rawUrl,
  HOWL_REPOSITORY_MCP_TOKEN: token,
} = process.env;

function stop(message) {
  process.stderr.write(message + "\n");
  process.exit(64);
}
if (![scratch, executable, home].every((path) => path && isAbsolute(path))
    || (stateHome !== undefined && !isAbsolute(stateHome))
    || process.cwd() !== realpathSync(scratch)) {
  stop("Codex requires absolute executable, home, and assigned scratch paths.");
}
if (!/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/mcp$/.test(rawUrl ?? "")) {
  stop("Codex requires the assigned loopback repository MCP endpoint.");
}
const url = new URL(rawUrl);
if (token !== undefined && !/^[a-zA-Z0-9._~-]{32,256}$/.test(token)) {
  stop("Invalid repository MCP authorization.");
}

const { username, shell } = userInfo();
const environment = {
  HOME: home, USER: username, LOGNAME: username, SHELL: shell || "/bin/sh",
  PATH: "/usr/bin:/bin:/usr/sbin:/sbin", TMPDIR: scratch, LANG: "C.UTF-8",
  CODEX_EXEC_SERVER_URL: "none",
  ...(stateHome ? { CODEX_HOME: stateHome } : {}),
  ...(token ? { HOWL_REPOSITORY_MCP_TOKEN: token } : {}),
};

const version = spawnSync(executable, ["--version"], {
  cwd: scratch, env: environment, encoding: "utf8", timeout: 5000,
});
if (version.status !== 0 || version.stdout.trim() !== "codex-cli 0.159.3") {
  stop("Host Codex requires the tested Codex CLI 0.159.3.");
}

const maxPromptBytes = 16 * 1024 * 1024;
const cli = [
  "--ask-for-approval", "never", "exec", "--json", "--ephemeral",
  "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
  "--sandbox", "read-only", "-c", 'web_search="disabled"',
  "-c", 'forced_login_method="chatgpt"', "-c", "features.skip_host_skill_discovery=true",
  "-c", "mcp_servers.howl_repository.url=" + JSON.stringify(url.href),
];
if (process.env.HOWL_AGENT_MODEL) cli.push("--model", process.env.HOWL_AGENT_MODEL);
const editable = process.env.HOWL_EDITABLE_WORKSPACE === "1";
const work = process.env.HOWL_WORK_TOOLS === "1";
if (editable || work) {
  const tools = ["read_file", "list_directory"];
  if (editable) tools.push("write_file", "delete_file", "run_tests");
  if (work) tools.push("start_work", "send_peer");
  cli.push("-c", "mcp_servers.howl_repository.enabled_tools=" + JSON.stringify(tools),
    "-c", 'mcp_servers.howl_repository.default_tools_approval_mode="approve"',
    "-c", "mcp_servers.howl_repository.tool_timeout_sec=45");
}
if (token) {
  cli.push("-c", 'mcp_servers.howl_repository.bearer_token_env_var="HOWL_REPOSITORY_MCP_TOKEN"');
}
for (const feature of [
  "apps", "code_mode", "hooks", "image_generation", "multi_agent", "multi_agent_v2",
  "plugins", "remote_plugin", "shell_tool", "skill_mcp_dependency_install",
  "skill_search", "unified_exec", "view_image",
]) {
  cli.push("-c", `features.${feature}=false`);
}
cli.push("-");

let initialized = false;
let session;
let active;

function send(message) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
}

function fail(id, code, message) {
  if (id !== undefined) send({ id, error: { code, message } });
}

async function* lines(stream, maxBytes) {
  let parts = [];
  let size = 0;
  for await (const chunk of stream) {
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start);
      const end = newline < 0 ? chunk.length : newline;
      const part = chunk.subarray(start, end);
      size += part.length;
      if (size > maxBytes) throw new Error("Oversized frame");
      parts.push(part);
      if (newline < 0) break;
      const line = Buffer.concat(parts, size).toString("utf8");
      parts = [];
      size = 0;
      yield line;
      start = newline + 1;
    }
  }
  if (size > 0) throw new Error("Incomplete frame");
}

function cancel(turn) {
  turn.cancelled = true;
  turn.child.kill("SIGTERM");
}

async function prompt(id, selected, text) {
  const context = selected.history.length === 0 ? text :
    "Earlier turns in this conversation:\n" + JSON.stringify(selected.history) +
    "\n\nCurrent user message:\n" + text;
  const child = spawn(executable, cli, { cwd: scratch, env: environment, stdio: ["pipe", "pipe", "ignore"] });
  const turn = { child, cancelled: false };
  active = turn;
  const exit = new Promise((resolve) => {
    child.once("error", () => resolve(null));
    child.once("close", resolve);
  });
  child.stdin.on("error", () => {});
  child.stdin.end(context);
  let reply = "";
  let completed = false;
  try {
    for await (const line of lines(child.stdout, 512 * 1024)) {
      if (turn.cancelled) continue;
      const event = JSON.parse(line);
      if (event.type === "turn.completed") completed = true;
      if (event.type !== "item.completed" || event.item?.type !== "agent_message") continue;
      const content = event.item.text;
      if (typeof content !== "string" || !content) continue;
      if (Buffer.byteLength(reply + content) > 128 * 1024) throw new Error("Oversized reply");
      reply += content;
      send({ method: "session/update", params: {
        sessionId: selected.id,
        update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: content } },
      } });
    }
    const status = await exit;
    if (turn.cancelled) {
      send({ id, result: { stopReason: "cancelled" } });
    } else if (status !== 0 || !completed) {
      fail(id, -32603, "The native Codex turn did not complete.");
    } else {
      selected.history.push({ user: text, assistant: reply });
      while (Buffer.byteLength(JSON.stringify(selected.history)) > 64 * 1024) selected.history.shift();
      send({ id, result: { stopReason: "end_turn" } });
    }
  } catch {
    child.kill("SIGTERM");
    fail(id, -32603, "The native Codex output was invalid.");
  } finally {
    active = null;
  }
}

function receive({ id, method, params = {} }) {
  if (method === "initialize" && !initialized) {
    if (!Number.isInteger(params.protocolVersion) || params.protocolVersion < 1) {
      fail(id, -32602, "Invalid ACP version.");
      return;
    }
    initialized = true;
    send({ id, result: { protocolVersion: 1, agentInfo: { name: "howl-codex", version: "1" },
      agentCapabilities: { sessionCapabilities: { close: {} } } } });
    return;
  }
  if (initialized && method === "session/new") {
    if (session || params.cwd !== scratch) {
      fail(id, -32602, "Invalid Codex scratch session.");
      return;
    }
    session = { id: randomUUID(), history: [] };
    send({ id, result: { sessionId: session.id } });
    return;
  }
  if (!session || params.sessionId !== session.id) {
    fail(id, -32602, "Unknown Codex session.");
    return;
  }
  if (method === "session/cancel") {
    if (active) cancel(active);
  } else if (method === "session/close") {
    if (active) cancel(active);
    session = null;
    send({ id, result: {} });
  } else if (method === "session/prompt") {
    if (active) {
      fail(id, -32603, "A Codex turn is already running.");
      return;
    }
    const blocks = params.prompt;
    if (!Array.isArray(blocks) || !blocks.length
        || blocks.some((block) => block?.type !== "text" || typeof block.text !== "string")) {
      fail(id, -32602, "Expected a text prompt.");
      return;
    }
    const text = blocks.map((block) => block.text).join("\n");
    if (!text.trim() || Buffer.byteLength(text) > maxPromptBytes) {
      fail(id, -32602, "Codex prompt is empty or too large.");
      return;
    }
    void prompt(id, session, text);
  } else {
    fail(id, -32601, "Unsupported ACP method.");
  }
}

function terminate() {
  if (active) cancel(active);
}
process.once("SIGTERM", () => {
  terminate();
  process.exit(0);
});
try {
  for await (const line of lines(process.stdin, 6 * maxPromptBytes + 8192)) {
    try {
      receive(JSON.parse(line));
    } catch {
      send({ id: null, error: { code: -32700, message: "Invalid ACP input." } });
    }
  }
} finally {
  terminate();
}
