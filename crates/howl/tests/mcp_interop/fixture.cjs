const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createInterface } = require('node:readline');
const { setTimeout: delay } = require('node:timers/promises');

const [role] = process.argv.slice(1);
const sessionId = role + '-mcp-test';

function send(message) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...message }) + '\n');
}

async function run() {
  for await (const line of createInterface({ input: process.stdin })) {
    const { id, method, params } = JSON.parse(line);
    switch (method) {
      case 'initialize':
        send({ id, result: {
          protocolVersion: 1,
          agentCapabilities: { sessionCapabilities: { close: {} } },
        } });
        break;
      case 'session/new':
        assert.equal(params.cwd, '/workspace');
        assert.equal(readFileSync('/workspace/selected.txt', 'utf8'), 'approved fixture\n');
        send({ id, result: { sessionId } });
        break;
      case 'session/prompt': {
        assert.equal(params.sessionId, sessionId);
        const prompt = params.prompt.map(item => item.text).join('\n');
        const data = JSON.parse(prompt.split('\n').at(-1));
        assert.equal(data.role, role);
        const input = data.human_instruction;
        if (input === 'MCP_INTEROP_CANCEL') await delay(300);
        if (input.startsWith('MCP_INTEROP_REVIEW')) {
          assert.ok(input.includes('HOWL_MCP_ARCHITECT'));
        }
        send({
          method: 'session/update', params: {
            sessionId,
            update: {
              sessionUpdate: 'agent_message_chunk',
              content: { type: 'text', text: 'HOWL_MCP_' + role.toUpperCase() },
            },
          },
        });
        send({ id, result: { stopReason: 'end_turn' } });
        break;
      }
      case 'session/close':
        send({ id, result: {} });
        return;
      default:
        throw new Error('Unexpected fixture ACP call');
    }
  }
}

run().catch(error => {
  process.stderr.write(error.message + '\n');
  process.exitCode = 1;
});
