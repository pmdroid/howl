#!/bin/sh
set -eu
export CLAUDE_CODE_EXECUTABLE=/fixture/claude-restricted.sh
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export DISABLE_AUTOUPDATER=1
export ENABLE_CLAUDEAI_MCP_SERVERS=false
/usr/local/bin/node -e '
const net = require("node:net");
const deadline = Date.now() + 8000;
function probe() {
  const socket = net.connect(17862, "127.0.0.1");
  socket.once("connect", () => socket.end());
  socket.once("error", () => {
    if (Date.now() >= deadline) process.exitCode = 1;
    else setTimeout(probe, 50);
  });
}
probe();
'
exec /fixture/claude-agent-acp
