const fs = require("node:fs/promises");
const { constants } = require("node:fs");
const path = require("node:path");

const { execFile } = require("node:child_process");
const editable = process.argv[1] === "edit";
const workspace = editable ? "/scratch/workspace" : "/workspace";
const requestLimit = editable ? 128 * 1024 : 16 * 1024;
const fileLimit = 64 * 1024;
const entryLimit = 256;
const protocols = new Set(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]);

const tools = [
  {
    name: "read_file",
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    description: "Read a UTF-8 file from the approved repository snapshot.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "list_directory",
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    description: "List a directory in the approved repository snapshot. Use an empty path for its root.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
      additionalProperties: false,
    },
  },
];

if (process.argv[2] === "work") {
  tools.push({
    name: "start_work",
    description: "Queue a fresh ACP worker in an isolated microVM for this conversation's approved repository. Use the same request key and instruction to retry.",
    inputSchema: {
      type: "object",
      properties: { request_key: { type: "string" }, instruction: { type: "string" } },
      required: ["request_key", "instruction"],
      additionalProperties: false,
    },
  });
  tools.push({
    name: "send_peer",
    description: "Send one message to an approved peer. The peer's signed reply enters this conversation in a later turn.",
    inputSchema: {
      type: "object",
      properties: { peer: { type: "string" }, text: { type: "string" } },
      required: ["peer", "text"],
      additionalProperties: false,
    },
  });
}

if (editable) {
  const string = { type: "string" };
  for (const [name, description, properties] of [
    ["write_file", "Write a UTF-8 file in the disposable Docker workspace.", { path: string, content: string }],
    ["delete_file", "Delete a file in the disposable Docker workspace.", { path: string }],
    ["run_tests", "Run a test command in the Docker workspace. Pass the executable and each argument separately.", {
      argv: { type: "array", items: string, minItems: 1, maxItems: 32 },
    }],
  ]) {
    tools.push({
      name, description,
      inputSchema: { type: "object", properties, required: Object.keys(properties), additionalProperties: false },
    });
  }
}

async function resolve(relative, allowRoot, create = false) {
  if (relative === "" && allowRoot) return workspace;
  if (typeof relative !== "string" || relative.length > 4096 || relative.includes("\\")
      || relative.includes("\0") || relative.split("/").some(part => !part || part === "." || part === ".." || (editable && part.startsWith(".")))) {
    throw new Error("Use a relative path in the approved snapshot.");
  }
  const file = path.join(workspace, relative);
  if (create) {
    let parent = workspace;
    for (const part of relative.split("/").slice(0, -1)) {
      parent = path.join(parent, part);
      await fs.mkdir(parent).catch(error => { if (error.code !== "EEXIST") throw error; });
      if (await fs.realpath(parent) !== parent) throw new Error("Symbolic links are unavailable.");
    }
    try {
      if (!(await fs.lstat(file)).isFile()) throw new Error("Expected a regular file.");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  } else if (await fs.realpath(file) !== file) {
    throw new Error("Symbolic links are unavailable.");
  }
  return file;
}

async function readFile(file) {
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const status = await handle.stat();
    if (!status.isFile() || status.size > fileLimit) throw new Error("Read a UTF-8 file of at most 64 KiB.");
    const buffer = Buffer.alloc(fileLimit + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > fileLimit) throw new Error("Read a UTF-8 file of at most 64 KiB.");
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, size));
  } finally {
    await handle.close();
  }
}

async function listDirectory(directory) {
  const handle = await fs.opendir(directory);
  const entries = [];
  let truncated = false;
  for await (const entry of handle) {
    if (!entry.isFile() && !entry.isDirectory()) continue;
    if (entries.length === entryLimit) {
      truncated = true;
      break;
    }
    entries.push({ name: entry.name, directory: entry.isDirectory() });
  }
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  return JSON.stringify({ entries, truncated });
}

function content(text, isError) {
  return { content: [{ type: "text", text }], isError };
}

async function callTool(params) {
  const { name, arguments: args } = params ?? {};
  if (editable && name === "run_tests") {
    const { argv } = args ?? {};
    if (!Array.isArray(argv) || argv.length < 1 || argv.length > 32 ||
        argv.some(arg => typeof arg !== "string" || arg.length > 4096 || arg.includes("\0")) || !argv[0]) {
      return content("Supply a test executable and its arguments.", true);
    }
    const [program, ...arguments_] = argv;
    return new Promise(resolve => {
      execFile(program, arguments_, {
        cwd: workspace, timeout: 30000, killSignal: "SIGKILL", maxBuffer: 16 * 1024,
      }, (error, stdout, stderr) => {
        const status = error ? (error.killed ? "Test command exceeded its limit" : "Test command failed: " + error.code) : "Exit 0";
        resolve(content(status + "\n" + stdout + stderr, Boolean(error)));
      });
    });
  }
  if (editable && name === "write_file") {
    try {
      if (typeof args?.content !== "string" || Buffer.byteLength(args.content) > fileLimit) {
        return content("Supply UTF-8 text of at most 64 KiB.", true);
      }
      const file = await resolve(args.path, false, true);
      const handle = await fs.open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o644);
      try {
        if (!(await handle.stat()).isFile()) throw new Error("Expected a regular file.");
        await handle.truncate();
        await handle.writeFile(args.content);
      } finally {
        await handle.close();
      }
      return content("File written.", false);
    } catch {
      return content("The file could not be written in the Docker workspace.", true);
    }
  }
  if (!args || Object.keys(args).length !== 1 || typeof args.path !== "string") {
    return content("Supply one relative repository path.", true);
  }
  try {
    switch (name) {
      case "read_file":
        return content(await readFile(await resolve(args.path, false)), false);
      case "delete_file":
        if (!editable) return content("Unknown repository tool.", true);
        await fs.unlink(await resolve(args.path, false));
        return content("File deleted.", false);
      case "list_directory":
        return content(await listDirectory(await resolve(args.path, true)), false);
      default:
        return content("Unknown repository tool.", true);
    }
  } catch {
    return content("The requested path could not be read from the approved snapshot.", true);
  }
}

function write(id, field, value) {
  return new Promise((resolve, reject) => {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, [field]: value }) + "\n",
      error => error ? reject(error) : resolve());
  });
}

async function handle(line) {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    return write(null, "error", { code: -32700, message: "Invalid JSON" });
  }
  if (request?.jsonrpc !== "2.0" || typeof request.method !== "string") {
    return write(null, "error", { code: -32600, message: "Invalid request" });
  }
  if (!Object.hasOwn(request, "id")) return;
  const id = request.id;
  if (typeof id !== "string" && !Number.isSafeInteger(id)) {
    return write(null, "error", { code: -32600, message: "Invalid request ID" });
  }
  switch (request.method) {
    case "initialize": {
      const requested = request.params?.protocolVersion;
      const protocolVersion = protocols.has(requested) ? requested : "2025-06-18";
      return write(id, "result", {
        protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "howl-repository", version: "0.1.0" },
      });
    }
    case "ping":
      return write(id, "result", {});
    case "tools/list":
      return write(id, "result", { tools });
    case "tools/call":
      return write(id, "result", await callTool(request.params));
    default:
      return write(id, "error", { code: -32601, message: "Method not found" });
  }
}

async function run() {
  let pending = Buffer.alloc(0);
  for await (const chunk of process.stdin) {
    pending = Buffer.concat([pending, chunk]);
    for (let boundary; (boundary = pending.indexOf(10)) >= 0;) {
      if (boundary > requestLimit) throw new Error("Request exceeds the size limit.");
      await handle(pending.subarray(0, boundary).toString("utf8"));
      pending = pending.subarray(boundary + 1);
    }
    if (pending.length > requestLimit) throw new Error("Request exceeds the size limit.");
  }
}

run().catch(() => { process.exitCode = 1; });
