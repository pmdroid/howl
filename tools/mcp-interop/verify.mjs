import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { resultFromTaskOutcome } from '@modelcontextprotocol/ext-tasks/client';
import {
  call,
  gateway,
  legacy,
  modern,
  openClient,
  taskSession,
  tasksCapability,
  waitRun,
  wakeArgs,
} from './client.mjs';

const closes = [];
assert.ok(process.argv[2], 'a Howl fixture JSON path is required');
const file = resolve(process.argv[2]);
const fixture = JSON.parse(await readFile(file, 'utf8'));

async function protectedResource(server) {
  const response = await fetch(server.url, {
    headers: { Accept: 'text/event-stream' },
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
  });
  assert.equal(response.status, 401);
  const challenge = response.headers.get('www-authenticate') ?? '';
  const reference = challenge.match(/resource_metadata="([^"]+)"/);
  assert.ok(reference, 'unauthorized request omitted protected-resource discovery');
  const metadata = new URL(reference[1]);
  assert.equal(metadata.origin, server.url.origin);
  const discovery = await fetch(metadata, { redirect: 'error', signal: AbortSignal.timeout(5_000) });
  assert.equal(discovery.status, 200);
  const resource = await discovery.json();
  assert.equal(resource.resource, server.url.href);
  assert.deepEqual(resource.bearer_methods_supported, ['header']);
  assert.ok(resource.scopes_supported.includes('howl:read'));
}

async function discover(client, channel, deniedChannel) {
  const advertised = new Set((await client.listTools()).tools.map(tool => tool.name));
  for (const required of ['list_channels', 'list_agents', 'read', 'wake', 'get_run', 'cancel_run']) {
    assert.ok(advertised.has(required), `missing tool ${required}`);
  }
  for (const privileged of ['grant_wake', 'promote_builder', 'approve']) {
    assert.ok(!advertised.has(privileged));
    await assert.rejects(call(client, privileged, { channel }));
  }
  assert.ok((await call(client, 'list_channels', {})).channels.includes(channel));
  const history = `howl://channels/${channel}/history`;
  const results = await client.listResources();
  assert.ok(results.resources.some(resource => resource.uri === history));
  assert.ok((await client.listResourceTemplates()).resourceTemplates.length >= 2);
  assert.equal((await client.readResource({ uri: history })).contents[0].mimeType, 'application/json');
  assert.ok((await client.listPrompts()).prompts.some(prompt => prompt.name === 'review'));
  const prompt = await client.getPrompt({ name: 'review', arguments: { topic: 'Howl deterministic fixture' } });
  assert.equal(prompt.messages[0].role, 'user');
  if (deniedChannel) {
    await assert.rejects(client.readResource({ uri: `howl://channels/${deniedChannel}/history` }));
    await assert.rejects(call(client, 'read', { channel: deniedChannel }));
    assert.ok(!results.resources.some(resource => resource.uri.includes(deniedChannel)));
  }
  return advertised;
}

async function verifyRuns(server, modernClient, legacyClient, report) {
  assert.equal(fixture.targets.length, 2);
  const [first, second] = fixture.targets;
  const session = await taskSession(modernClient, server);
  closes.push(() => session.close());
  const execution = await session.callTool('wake', wakeArgs(fixture.channel, first));
  assert.equal(execution.kind, 'task');
  const reference = execution.serializeReference();
  await execution.detach();
  await execution.result();
  await session.close();
  await modernClient.close();
  if (fixture.restartGateway) {
    await legacyClient.close();
    const input = createInterface({ input: process.stdin });
    const ready = once(input, 'line');
    process.stdout.write(JSON.stringify({ phase: 'restart_gateway' }) + '\n');
    assert.equal((await ready)[0], 'reader-ready');
    input.close();
    report.gatewayRestart = true;
  }

  const reconnected = await openClient(server, modern, closes, tasksCapability);
  const reinitialized = fixture.restartGateway ? await openClient(server, legacy, closes) : legacyClient;
  const recovered = await taskSession(reconnected, server);
  closes.push(() => recovered.close());
  const resumed = await recovered.resumeTask(reference, { signal: AbortSignal.timeout(90_000) });
  const result = resultFromTaskOutcome((await resumed.settle()).outcome);
  assert.equal(result.structuredContent.status, 'completed');
  assert.ok(result.structuredContent.reply.text.includes(first.expect));

  const fallbackArgs = wakeArgs(fixture.channel, {
    ...second,
    text: second.text + '\n' + result.structuredContent.reply.text,
  });
  const fallback = await call(reinitialized, 'wake', fallbackArgs);
  const duplicate = await call(reinitialized, 'wake', fallbackArgs);
  assert.equal(fallback.run, duplicate.run);
  assert.equal(fallback.wake_message, duplicate.wake_message);
  const oldResult = await waitRun(reinitialized, fixture.channel, fallback.run);
  assert.equal(oldResult.status, 'completed');
  assert.ok(oldResult.reply.text.includes(second.expect));
  report.nativeTasksReconnect = true;
  report.toolsOnlyFinalResult = true;
  report.idempotentWake = true;

  if (fixture.cancelTarget) {
    const cancelled = await recovered.callTool('wake', wakeArgs(fixture.channel, fixture.cancelTarget));
    assert.equal(cancelled.kind, 'task');
    const cancellation = cancelled.serializeReference();
    await recovered.cancelTask(cancellation.taskId);
    const state = await waitRun(reconnected, fixture.channel, cancellation.taskId);
    assert.ok(['completed', 'cancelled'].includes(state.status));
    assert.equal(state.cancellation_requested, true);
    report.cancellationOutcome = state.status;
  }
}

async function observedAt(marker) {
  const observation = resolve(dirname(file), fixture.observations, marker);
  const deadline = performance.now() + 5_000;
  while (performance.now() < deadline) {
    try {
      const data = await readFile(observation, 'utf8');
      const timestamp = Number(data);
      if (timestamp > 0) return timestamp;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await delay(25);
  }
  assert.fail('signed mesh event was not observed on the gateway node');
}

function percentiles(samples) {
  const ordered = samples.sort((a, b) => a - b);
  const at = fraction => Math.round(ordered[Math.ceil(ordered.length * fraction) - 1]);
  return { samples: ordered.length, p50: at(0.5), p95: at(0.95) };
}

async function subscriptionLatency(reader, writer, advertised, report) {
  const uri = `howl://channels/${fixture.channel}/history`;
  let nextUpdate;
  const initial = new Promise(resolveUpdate => {
    nextUpdate = resolveUpdate;
  });
  reader.setNotificationHandler('notifications/resources/updated', notification => {
    if (notification.params.uri === uri) nextUpdate?.();
  });
  const subscription = await reader.listen({ resourceSubscriptions: [uri] }, { timeout: 10_000 });
  closes.push(() => subscription.close());
  const ready = AbortSignal.timeout(5_000);
  await Promise.race([
    initial,
    once(ready, 'abort').then(() => assert.fail('notification baseline timed out')),
  ]);
  const writerSamples = [];
  const gatewaySamples = [];
  for (let index = 0; index < 20; index++) {
    const start = performance.now();
    const event = new Promise(resolveUpdate => {
      nextUpdate = () => resolveUpdate({ elapsed: performance.now() - start, time: Date.now() });
    });
    const marker = randomUUID();
    const text = `howl-mcp-interop-${marker}`;
    await call(writer, 'post', { channel: fixture.channel, text });
    const signal = AbortSignal.timeout(5_000);
    const notification = await Promise.race([
      event,
      once(signal, 'abort').then(() => assert.fail('notification timed out')),
    ]);
    const history = await reader.readResource({ uri });
    assert.ok(history.contents.some(content => content.text.includes(text)));
    writerSamples.push(notification.elapsed);
    const observed = await observedAt(marker);
    gatewaySamples.push(Math.max(0, notification.time - observed));
  }
  nextUpdate = undefined;
  report.gatewayEventToNotificationMs = percentiles(gatewaySamples);
  report.writerPostToNotificationMs = percentiles(writerSamples);
  assert.ok(report.gatewayEventToNotificationMs.p95 < 1000, JSON.stringify(report));
  assert.ok(advertised.has('read_events') && advertised.has('wait_for_events'));
}

try {
  const server = await gateway(fixture, file, closes);
  await protectedResource(server);
  const newClient = await openClient(server, modern, closes, fixture.targets ? tasksCapability : {});
  const oldClient = await openClient(server, legacy, closes);
  const tools = await discover(newClient, fixture.channel, fixture.deniedChannel);
  await discover(oldClient, fixture.channel, fixture.deniedChannel);
  const report = { client: '@modelcontextprotocol/client 2.4.0', modern, legacy, protectedResource: true };
  if (fixture.targets) await verifyRuns(server, newClient, oldClient, report);
  if (fixture.writer) {
    const reader = fixture.targets ? await openClient(server, modern, closes) : newClient;
    const writer = await openClient(await gateway(fixture.writer, file, closes), modern, closes);
    await subscriptionLatency(reader, writer, tools, report);
  }
  process.stdout.write(JSON.stringify(report) + '\n');
} finally {
  for (const close of closes.reverse()) await close();
}
