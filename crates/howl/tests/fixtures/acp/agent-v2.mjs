import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";

import { burst } from "./reply-burst.mjs";

const lines = createInterface({ input: process.stdin });
const sessionId = "synthetic-v2-session";
const send = (message) => process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
const reply = (id, result = {}) => send({ id, result });
const update = (update, session = sessionId) => send({
  method: "session/update",
  params: { sessionId: session, update },
});
const state = (state, properties = {}, session = sessionId) =>
  update({ sessionUpdate: "state_update", state, ...properties }, session);
let permissionResponse;
let expectedPermission;

lines.on("line", (line) => {
  const { id, method, params, result } = JSON.parse(line);
  if (method === "initialize") {
    if (params.protocolVersion !== 2 || params.info.name !== "howl") process.exit(48);
    reply(id, {
      protocolVersion: 2,
      info: { name: "howl-acp-v2-fixture", version: "1" },
      capabilities: { session: {} },
    });
  } else if (method === "session/new") {
    if (params.cwd !== "/workspace" || readFileSync("/workspace/tracked.txt", "utf8") !== "approved\n") {
      process.exit(49);
    }
    if (process.argv.includes("--initial-active")) state("running");
    reply(id, { sessionId });
    if (!process.argv.includes("--initial-active")) state("idle");
  } else if (method === "session/resume") {
    if (params.sessionId !== sessionId || params.cwd !== "/workspace") process.exit(50);
    state("idle", { stopReason: "end_turn" });
    reply(id);
  } else if (method === "session/close") {
    if (params.sessionId !== sessionId) process.exit(51);
    reply(id);
  } else if (method === "session/prompt") {
    const text = params.prompt[0].text;
    if (text === "crash") process.exit(52);
    const pause = text === "hold" || text === "permanent";
    const messageId = `user-${id}`;
    state("idle", { stopReason: "max_tokens" });
    state("running");
    state("idle", { stopReason: "refusal" }, "unrelated-session");
    update({
      sessionUpdate: "user_message",
      messageId,
      content: params.prompt,
    });
    if (pause) {
      reply(id, { messageId });
      expectedPermission = text === "hold" ? "selected" : "cancelled";
      const options = [{ optionId: "permanent", name: "Allow permanently", kind: "allow_always" }];
      if (text === "hold") options.push({ optionId: "deny", name: "Deny once", kind: "reject_once" });
      send({
        id: "fixture-permission",
        method: "session/request_permission",
        params: {
          sessionId,
          title: "Read workspace file",
          subject: { type: "tool_call", toolCall: { toolCallId: "fixture-tool" } },
          options,
        },
      });
      state("requires_action");
      return;
    }
    if (text === "wait") {
      reply(id, { messageId });
      return;
    }
    if (text === "burst") {
      reply(id, { messageId });
      burst(update, true);
      state("idle", { stopReason: "end_turn" });
      return;
    }
    if (text === "error") {
      reply(id, { messageId });
      state("idle", { stopReason: "error", error: { code: -32030, message: "synthetic failure" } });
      return;
    }
    update({
      sessionUpdate: "agent_message_chunk",
      messageId: `assistant-${id}`,
      content: { type: "text", text: "v2 fixture reply" },
    });
    state("idle", { stopReason: "end_turn" });
    reply(id, { messageId });
  } else if (method === "session/cancel") {
    if (expectedPermission && (permissionResponse?.outcome !== expectedPermission
      || (expectedPermission === "selected" && permissionResponse.optionId !== "deny"))) process.exit(53);
    expectedPermission = undefined;
    state("idle", { stopReason: "cancelled" });
    permissionResponse = undefined;
  } else if (id === "fixture-permission") {
    permissionResponse = result.outcome;
  }
});
