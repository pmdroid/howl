const fs = require("node:fs");
const path = require("node:path");

const original = "/workspace";
const work = "/scratch/workspace";
const generated = new Set(["node_modules", "target", "coverage", "dist", "build"]);
const maxFile = 2 * 1024 * 1024;
const maxChanges = 128;
const maxOutput = 3 * 1024 * 1024;

function textFile(root, relative) {
  const name = path.join(root, relative);
  try {
    const file = fs.lstatSync(name);
    if (!file.isFile() || file.size > maxFile || fs.realpathSync(name) !== name) return undefined;
    const content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(fs.readFileSync(name));
    return content.includes("\0") ? undefined : { content, executable: Boolean(file.mode & 0o100) };
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
    if (error.code === "ERR_ENCODING_INVALID_ENCODED_DATA") return undefined;
    throw error;
  }
}

function files(root, skipGenerated, relative = "", output = []) {
  for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
    if (entry.name.startsWith(".") || entry.name.length > 255 || /[:\\\x00-\x1f\x7f]/.test(entry.name)) continue;
    const name = path.join(relative, entry.name);
    if (name.length > 512) continue;
    if (entry.isDirectory() && !(skipGenerated && generated.has(entry.name))) {
      files(root, skipGenerated, name, output);
    } else if (entry.isFile()) {
      output.push(name);
      if (output.length > 1024) throw new Error("Too many workspace files to export");
    }
  }
  return output;
}

if (process.argv[1] === "export") {
  const changes = [];
  let size = 0;
  const paths = new Set([...files(original, false), ...files(work, true)]);
  for (const relative of [...paths].sort()) {
    const before = textFile(original, relative);
    const after = textFile(work, relative);
    if (after === undefined) {
      if (before) throw new Error("A tracked file is no longer a regular UTF-8 file");
      continue;
    }
    if (JSON.stringify(before) === JSON.stringify(after)) continue;
    const entry = { path: relative, before, after };
    size += Buffer.byteLength(JSON.stringify(entry));
    if (size > maxOutput || changes.length === maxChanges) throw new Error("Workspace changes exceed the export limit");
    changes.push(entry);
  }
  process.stdout.write(JSON.stringify(changes));
} else {
  fs.cpSync(original, work, { recursive: true });
  for (const relative of files(work, false)) {
    const name = path.join(work, relative);
    fs.chmodSync(name, fs.statSync(name).mode | 0o200);
  }
  process.stdout.write("ready\n");
  setInterval(() => {}, 1000);
}
