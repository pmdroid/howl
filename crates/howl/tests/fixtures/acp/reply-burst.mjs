export function burst(update, v2) {
  for (let i = 0; i < 160; i++) {
    update({ sessionUpdate: "tool_call", toolCallId: "tool-" + i, title: "Read file" });
    update({ sessionUpdate: "agent_message_chunk", messageId: "answer", content: { type: "text", text: i + "/" } });
  }
  if (v2) {
    update({ sessionUpdate: "agent_message_chunk", messageId: "worker", content: { type: "text", text: "starting" } });
    update({ sessionUpdate: "agent_message", messageId: "worker", content: [{ type: "text", text: "run-42" }] });
  }
}
