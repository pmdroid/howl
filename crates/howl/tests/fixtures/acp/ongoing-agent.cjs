const { createInterface } = require("node:readline");
const { randomUUID } = require("node:crypto");
const sessionId = randomUUID();
let turns = 0;

function send(frame) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...frame }) + "\n");
}

async function answer(prompt) {
  if (prompt.startsWith("Summarize the conversation transcript")) {
    return prompt.match(/archive-[0-9a-f]{16}/)?.[0] ?? "no fact in transcript";
  }
  const data = JSON.parse(prompt.split("\n").at(-1));
  if (data.input.endsWith("slow-canary")) await new Promise(resolve => setTimeout(resolve, 11000));
  if (data.input.endsWith("inspect-context")) {
    const exchanges = data.earlier_exchanges;
    const summary = data.conversation_summary?.match(/archive-[0-9a-f]{16}/)?.[0] ?? "empty";
    const raw = exchanges.some(exchange => exchange.input.includes("fact=archive-"));
    const privateFact = exchanges.some(exchange => exchange.input === "private-context-canary");
    return `history=${exchanges.length} summary=${summary} raw=${raw} private=${privateFact}`;
  }
  if (data.input === "private-context-canary" || data.input.match(/^\/thread review (fact=|note-|filler-)/)) return "ack";
  const shared = data.earlier_exchanges.filter(entry => entry.input.startsWith("/thread review "));
  const slow = shared.find(entry => entry.input.endsWith("slow-canary"));
  let text = `turn-${++turns}-${data.input}`;
  if (data.input.includes("probe-")) {
    text = `pending=${slow?.reply === null} completed=${shared.filter(entry => entry.reply !== null).length} private=${data.earlier_exchanges.some(entry => entry.input === "private-canary")} sender=${slow?.sender}`;
  }
  return text;
}

async function run() {
  for await (const line of createInterface({ input: process.stdin })) {
    const { id, method, params } = JSON.parse(line);
    if (method === "initialize") {
      send({ id, result: { protocolVersion: 1, agentCapabilities: { sessionCapabilities: { close: {} } } } });
    } else if (method === "session/new") {
      send({ id, result: { sessionId } });
    } else if (method === "session/prompt") {
      const text = await answer(params.prompt[0].text);
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
