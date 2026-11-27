#!/usr/local/bin/node
const executable = "/fixture/claude";
const input = process.argv.slice(2);
if (input[0] === "auth") {
  process.execve(executable, [executable, ...input], process.env);
}
const args = [];
for (let index = 0; index < input.length; index++) {
  const arg = input[index];
  if (arg === "--permission-mode") {
    index++;
  } else if (!arg.startsWith("--permission-mode=")
      && arg !== "--dangerously-skip-permissions"
      && arg !== "--allow-dangerously-skip-permissions") {
    args.push(arg);
  }
}
process.execve(executable, [
  executable, ...args, "--restricted", "--tools", "Read,Grep,Glob",
  "--strict-mcp-config", "--permission-mode", "plan",
], process.env);
