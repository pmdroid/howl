import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { resultFromTaskOutcome } from '@modelcontextprotocol/ext-tasks/client';
import {
  call,
  gateway,
  openClient,
  taskSession,
  tasksCapability,
  waitRun,
  wakeArgs,
} from './client.mjs';

const [path, mode] = process.argv.slice(2);
assert.ok(path && (mode === undefined || mode === '--tools-only'),
  'usage: node discuss.mjs SETTINGS.json [--tools-only]');
const file = resolve(path);
const settings = JSON.parse(await readFile(file, 'utf8'));
const { channel, targets } = settings;
const id = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
assert.ok(id(channel), 'an explicit channel ID is required');
assert.ok(Array.isArray(targets) && targets.length === 2 &&
  targets.every(target => id(target.peer) && id(target.target)) &&
  targets[0].target !== targets[1].target, 'distinct architect and reviewer targets are required');

let topic = '';
process.stdin.setEncoding('utf8');
for await (const input of process.stdin) {
  topic += input;
  assert.ok(Buffer.byteLength(topic) <= 8_192, 'discussion topic exceeds 8192 bytes');
}
topic = topic.trim();
assert.ok(topic.length, 'provide the discussion topic on stdin');

const timeoutMs = 180_000;
const closes = [];
try {
  const server = await gateway(settings, file, closes);
  const capabilities = mode === '--tools-only' ? {} : tasksCapability;
  const client = await openClient(server, undefined, closes, capabilities);
  const offered = client.getServerCapabilities().extensions?.['io.modelcontextprotocol/tasks'];
  const tasks = mode !== '--tools-only' && client.getProtocolEra() === 'modern' && offered
    ? await taskSession(client, server) : undefined;
  if (tasks) closes.push(() => tasks.close());

  async function ask(target, text) {
    assert.ok(Buffer.byteLength(text) <= 48_000, 'discussion input exceeds the wake size limit');
    const args = wakeArgs(channel, { ...target, text });
    let result;
    if (tasks) {
      const execution = await tasks.callTool('wake', args, { signal: AbortSignal.timeout(timeoutMs) });
      result = resultFromTaskOutcome((await execution.settle()).outcome).structuredContent;
    } else {
      const { run } = await call(client, 'wake', args);
      result = await waitRun(client, channel, run, timeoutMs);
    }
    assert.ok(result.status === 'completed' && typeof result.reply?.text === 'string',
      `observer run ended as ${result.status}`);
    return result.reply.text;
  }

  const draft = await ask(targets[0], 'Draft a response to this topic:\n\n' + topic);
  const review = await ask(
    targets[1],
    'Review the draft for accuracy and return a polished final response.\n\nTopic:\n' +
      topic + '\n\nDraft:\n' + draft,
  );
  process.stdout.write(review + '\n');
} finally {
  for (const close of closes.reverse()) await close();
}
