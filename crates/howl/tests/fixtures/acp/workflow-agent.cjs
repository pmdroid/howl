const assert = require("node:assert/strict");
const { existsSync, readFileSync } = require("node:fs");
const { createInterface } = require("node:readline");

const [stage] = process.argv.slice(1);
const stages = {
  "architect-draft": {
    request: "DRAFT_REQUEST", selected: "Architect selected data\n", role: "architect",
    reply: "HOWL_ARCHITECT_DRAFT",
  },
  reviewer: {
    request: "REVIEW_REQUEST", selected: "Reviewer selected data\n", role: "reviewer",
    context: { role: "architect", text: "HOWL_ARCHITECT_DRAFT" }, reply: "HOWL_REVIEWER_FEEDBACK",
  },
  "architect-final": {
    request: "FINAL_REQUEST", selected: "Architect selected data\n", role: "architect",
    context: { role: "reviewer", text: "HOWL_REVIEWER_FEEDBACK" }, reply: "HOWL_ARCHITECT_FINAL",
  },
};
const fixture = stages[stage];
assert(fixture);
const sessionId = stage + "-fixture";

function send(message) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
}

async function run() {
  for await (const line of createInterface({ input: process.stdin })) {
    const { id, method, params } = JSON.parse(line);
    switch (method) {
      case "initialize":
        assert.equal(params.protocolVersion, 1);
        send({ id, result: {
          protocolVersion: 1, agentCapabilities: { sessionCapabilities: { close: {} } },
        } });
        break;
      case "session/new":
        assert.equal(params.cwd, "/workspace");
        assert.equal(readFileSync("/workspace/selected.txt", "utf8"), fixture.selected);
        assert.equal(existsSync("/workspace/unselected.txt"), false);
        send({ id, result: { sessionId } });
        break;
      case "session/prompt": {
        assert.equal(params.sessionId, sessionId);
        const prompt = params.prompt.map(item => item.text).join("\n");
        const data = JSON.parse(prompt.split("\n").at(-1));
        assert.equal(data.role, fixture.role);
        assert.equal(data.human_instruction, fixture.request);
        assert.deepEqual(data.context_messages.map(message => ({
          author: message.body.author,
          role: message.body.role,
          text: message.body.text,
        })), fixture.context ? [{ author: "agent", ...fixture.context }] : []);
        send({
          method: "session/update", params: {
            sessionId, update: {
              sessionUpdate: "agent_message_chunk", content: { type: "text", text: fixture.reply },
            },
          },
        });
        send({ id, result: { stopReason: "end_turn" } });
        break;
      }
      case "session/close":
        assert.equal(params.sessionId, sessionId);
        send({ id, result: {} });
        return;
      default:
        throw new Error("Unexpected workflow agent call");
    }
  }
}

run().catch(() => { process.exitCode = 1; });
