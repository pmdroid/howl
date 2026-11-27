const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { existsSync, readFileSync } = require("node:fs");
const { createInterface } = require("node:readline");

const [agent] = process.argv.slice(1);
const selected = { architect: "Architect selected data\n", reviewer: "Reviewer selected data\n" };
const turns = {
  DRAFT_REQUEST: {
    agent: "architect", reply: "HOWL_ARCHITECT_DRAFT",
  },
  REVIEW_REQUEST: {
    agent: "reviewer", context: "HOWL_ARCHITECT_DRAFT", reply: "HOWL_REVIEWER_FEEDBACK",
  },
  FINAL_REQUEST: {
    agent: "architect", context: "HOWL_REVIEWER_FEEDBACK", reply: "HOWL_ARCHITECT_FINAL",
    previous: [{ instruction: "DRAFT_REQUEST", reply: "HOWL_ARCHITECT_DRAFT" }],
  },
};
assert(selected[agent]);
const sessionId = randomUUID();

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
        assert.equal(readFileSync("/workspace/selected.txt", "utf8"), selected[agent]);
        assert.equal(existsSync("/workspace/unselected.txt"), false);
        send({ id, result: { sessionId } });
        break;
      case "session/prompt": {
        assert.equal(params.sessionId, sessionId);
        const prompt = params.prompt.map(item => item.text).join("\n");
        const data = JSON.parse(prompt.split("\n").at(-1));
        const fixture = turns[data.human_instruction];
        assert.equal(fixture.agent, agent);
        assert.deepEqual(data.context_messages.map(message => ({
          author: message.body.author,
          text: message.body.text,
        })), fixture.context ? [{ author: "agent", text: fixture.context }] : []);
        assert.deepEqual(data.previous_turns ?? [], fixture.previous ?? []);
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

run().catch(() => process.exit(1));
