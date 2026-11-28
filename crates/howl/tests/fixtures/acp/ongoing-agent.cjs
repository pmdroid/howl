const { createInterface } = require("node:readline");
const { randomUUID } = require("node:crypto");
const sessionId = randomUUID();
let turns = 0;

function send(frame) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...frame }) + "\n");
}

async function run() {
  for await (const line of createInterface({ input: process.stdin })) {
    const { id, method, params } = JSON.parse(line);
    if (method === "initialize") {
      send({ id, result: { protocolVersion: 1, agentCapabilities: { sessionCapabilities: { close: {} } } } });
    } else if (method === "session/new") {
      send({ id, result: { sessionId } });
    } else if (method === "session/prompt") {
      const data = JSON.parse(params.prompt[0].text.split("\n").at(-1));
      if (data.input.endsWith("slow-canary")) await new Promise(resolve => setTimeout(resolve, 11000));
      const shared = data.earlier_exchanges.filter(entry => entry.input.startsWith("/thread review "));
      const slow = shared.find(entry => entry.input.endsWith("slow-canary"));
      let text = `turn-${++turns}-${data.input}`;
      if (data.input.includes("probe-")) {
        text = `pending=${slow?.reply === null} completed=${shared.filter(entry => entry.reply !== null).length} private=${data.earlier_exchanges.some(entry => entry.input === "private-canary")} sender=${slow?.sender}`;
      }
      send({ method: "session/update", params: { sessionId, update: {
        sessionUpdate: "agent_message_chunk", content: { type: "text", text },
      } } });
      send({ id, result: { stopReason: "end_turn" } });
    } else if (method === "session/close") {
      send({ id, result: {} });
      return;
    }
  }
}

run().catch(() => process.exit(1));
