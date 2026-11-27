import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

const lines = createInterface({ input: process.stdin });
const minimal = process.argv.includes("--minimal");
const sessionId = "synthetic-session";
const send = (message) => process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
const reply = (id, result = {}) => send({ id, result });
let pending;
let options;
let permissionReply;

lines.on("line", (line) => {
  const { id, method, params, result } = JSON.parse(line);
  if (method === "initialize") {
    if (process.argv.includes("--expect-v2-offer") && params.protocolVersion !== 2) process.exit(48);
    reply(id, {
      protocolVersion: 1,
      agentInfo: { name: "howl-acp-fixture", version: "1" },
      agentCapabilities: minimal ? {} : {
        loadSession: true,
        sessionCapabilities: { resume: {}, close: {} },
      },
    });
  } else if (method === "session/new") {
    if (readFileSync("/workspace/tracked.txt", "utf8") !== "approved\n") process.exit(44);
    reply(id, { sessionId });
  } else if (method === "session/load" || method === "session/resume" || method === "session/close") {
    if (minimal || params.sessionId !== sessionId) process.exit(45);
    reply(id);
  } else if (method === "session/prompt") {
    const text = params.prompt[0].text;
    if (text === "crash") process.exit(43);
    if (text === "oversize") {
      process.stdout.write("a".repeat(270000));
      return;
    }
    if (text === "ignore") return;
    if (text === "hold" || text === "permanent") {
      pending = id;
      options = [{ optionId: "permanent", name: "Allow permanently", kind: "allow_always" }];
      if (text === "hold") options.push({ optionId: "deny", name: "Deny once", kind: "reject_once" });
      send({
        id: "fixture-permission",
        method: "session/request_permission",
        params: { sessionId, toolCall: { toolCallId: "fixture-tool" }, options },
      });
      return;
    }
    send({
      method: "session/update",
      params: {
        sessionId,
        update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: "fixture reply" } },
      },
    });
    reply(id, { stopReason: "end_turn" });
  } else if (method === "session/cancel" && pending !== undefined) {
    const expected = options.length === 2 ? "selected" : "cancelled";
    if (permissionReply?.outcome !== expected) process.exit(46);
    if (expected === "selected" && permissionReply.optionId !== "deny") process.exit(47);
    reply(pending, { stopReason: "cancelled" });
    pending = undefined;
  } else if (id === "fixture-permission") {
    permissionReply = result.outcome;
  }
});
