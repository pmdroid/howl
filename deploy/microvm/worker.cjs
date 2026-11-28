const { spawn, spawnSync } = require("node:child_process");
const { createInterface } = require("node:readline");
const { writeSync, readFileSync, createReadStream, createWriteStream } = require("node:fs");
const vsock = process.env.HOWL_GUEST_VSOCK === "1";
const input = vsock ? createReadStream(null, { fd: 0, autoClose: false }) : process.stdin;
const output = vsock ? createWriteStream(null, { fd: 1, autoClose: false }) : process.stdout;
function git(args) {
  const result = spawnSync("/usr/bin/git", args, { maxBuffer: 4 * 1024 * 1024, encoding: null });
  if (result.status !== 0) throw new Error("Guest Git command failed");
  return result.stdout;
}
git(["init", "-q", "--template="]);
git(["add", "-A"]);
git(["-c", "user.name=Howl Worker", "-c", "user.email=worker@howl.invalid", "commit", "-qm", "Base snapshot"]);
const adapter = spawn(process.execPath, ["/fixture/codex-guest.mjs", readFileSync("/etc/howl-model", "utf8").trim()], { stdio: ["pipe", "pipe", "ignore"] });
adapter.stdin.on("error", () => {});
function send(value, done) { output.write(JSON.stringify(value) + "\n", done); }
let initialize;
let closed = false;
adapter.on("exit", () => { if (!closed) process.exit(1); });
createInterface({ input: adapter.stdout }).on("line", line => {
  const value = JSON.parse(line);
  if (initialize !== undefined && value.id === initialize && value.result?.agentCapabilities) {
    value.result.agentCapabilities.sessionCapabilities = { ...value.result.agentCapabilities.sessionCapabilities, close: {} };
  }
  send(value);
});
output.write("HOWL_ACP_READY\n");
const requests = createInterface({ input });
requests.on("line", line => {
  const message = JSON.parse(line);
  if (message.method === "initialize") initialize = message.id;
  if (message.method !== "session/close") {
    adapter.stdin.write(line + "\n");
    return;
  }
  closed = true;
  adapter.kill();
  git(["add", "-N", "."]);
  const patch = git(["diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD"]);
  const size = Buffer.alloc(8);
  size.writeBigUInt64BE(BigInt(patch.length));
  send({ jsonrpc: "2.0", id: message.id, result: {} }, error => {
    if (error) throw error;
    for (const part of [size, patch]) {
      for (let offset = 0; offset < part.length;) offset += writeSync(4, part, offset, part.length - offset);
    }
    requests.close();
    input.destroy();
    setTimeout(() => {}, 10_000);
  });
});
