import { realpathSync } from "node:fs";
import { userInfo } from "node:os";
import { isAbsolute } from "node:path";

function refuse(message) {
  process.stderr.write(message + "\n");
  process.exit(64);
}

const executable = process.env.HOWL_CLAUDE_EXECUTABLE;
const home = process.env.HOWL_CLAUDE_HOME;
const scratch = process.env.HOWL_AGENT_CWD;
if (![executable, home, scratch].every((value) => value && isAbsolute(value))) {
  refuse("Claude Code requires absolute executable, home, and scratch paths.");
}
if (realpathSync(scratch) !== process.cwd()) {
  refuse("Claude Code can only start in its assigned scratch directory.");
}

const request = process.argv.slice(2);
const { username, shell } = userInfo();
const environment = {
  HOME: home,
  USER: username,
  LOGNAME: username,
  SHELL: shell || "/bin/sh",
  LANG: "C.UTF-8",
  PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
  TMPDIR: scratch,
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
  CLAUDE_CODE_DISABLE_AUTO_MEMORY: "1",
  CLAUDE_CODE_DISABLE_ATTACHMENTS: "1",
  DISABLE_AUTOUPDATER: "1",
  ENABLE_CLAUDEAI_MCP_SERVERS: "false",
};

if (request[0] === "auth" && request[1] === "status" &&
    request.slice(2).every((arg) => arg === "--json")) {
  process.execve(executable, [executable, "--restricted", "auth", "status", "--json"], environment);
}
if (request.length === 1 && ["--version", "-v"].includes(request[0])) {
  process.execve(executable, [executable, "--version"], environment);
}
if (!request.includes("--input-format") || !request.includes("--output-format")) {
  refuse("Claude Code host execution requires a streaming ACP session.");
}

const forbidden = new Set([
  "--", "--add-dir", "--agent", "--agents", "--bare",
  "--plugin-dir", "--plugin-url", "--sdk-url", "--tmux", "--worktree", "-w",
]);
const args = [];
for (let index = 0; index < request.length; index++) {
  const arg = request[index];
  const flag = arg.split("=", 1)[0];
  if (forbidden.has(flag)) refuse("Claude Code received an unsafe session option.");
  if (flag === "--dangerously-skip-permissions" || flag === "--allow-dangerously-skip-permissions") continue;
  if (["--setting-sources", "--settings", "--permission-mode"].includes(flag)) {
    if (arg === flag) index++;
    continue;
  }
  if (["--tools", "--allowed-tools", "--allowedTools"].includes(flag)) {
    if (arg === flag) {
      while (request[index + 1] !== undefined && !request[index + 1].startsWith("-")) {
        index++;
      }
    }
    continue;
  }
  args.push(arg);
}
const settings = JSON.stringify({
  claudeMdExcludes: ["**"],
  disableAllHooks: true,
  disableClaudeAiConnectors: true,
});
const editable = process.env.HOWL_EDITABLE_WORKSPACE === "1";
const work = process.env.HOWL_WORK_TOOLS === "1";
const tools = ["read_file", "list_directory"];
if (editable) tools.push("write_file", "delete_file", "run_tests");
if (work) tools.push("start_work", "send_peer");
args.push(
  "--restricted", "--strict-mcp-config", "--tools", "", "--permission-mode", editable || work ? "default" : "plan",
  "--allowedTools", ...tools.map(name => "mcp__howl_repository__" + name),
  "--settings", settings,
);
process.execve(executable, [executable, ...args], environment);
