import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { EventSourceParserStream } from 'eventsource-parser/stream';
import {
  createTaskSessionEndpointId,
  createTaskSessionFromClient,
} from '@modelcontextprotocol/ext-tasks/client';

export const modern = '2026-07-28';
export const legacy = '2025-11-25';
const clientInfo = { name: 'howl-mcp', version: '0.1.0' };
export const tasksCapability = { extensions: { 'io.modelcontextprotocol/tasks': {} } };

export async function gateway(connection, file, closes) {
  const url = new URL(connection.url);
  assert.equal(url.pathname, '/mcp');
  assert.ok(
    url.protocol === 'https:' ||
      (url.protocol === 'http:' && url.hostname === '127.0.0.1'),
    'MCP interop requires HTTPS or IPv4 loopback',
  );
  if (process.env.HOWL_MCP_DOCKER_HOST) {
    assert.equal(url.hostname, '127.0.0.1');
    await forwardLoopback(Number(url.port), process.env.HOWL_MCP_DOCKER_HOST, closes);
  }
  const tokenPath = resolve(dirname(file), connection.tokenFile);
  const credentials = await open(tokenPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let token;
  try {
    const stat = await credentials.stat();
    assert.ok(stat.isFile() && (stat.mode & 0o077) === 0 && stat.size <= 8193,
      'store the MCP credential in a protected regular file');
    token = (await credentials.readFile('utf8')).trim();
  } finally {
    await credentials.close();
  }
  assert.ok(token.length >= 32, 'a protected fixture bearer token is required');
  return { url, token, freshConnections: connection.restartGateway === true };
}

async function forwardLoopback(port, host, closes) {
  const sockets = new Set();
  const listener = createServer(incoming => {
    const outgoing = connect(port, host);
    sockets.add(incoming).add(outgoing);
    incoming.on('error', () => outgoing.destroy());
    outgoing.on('error', () => incoming.destroy());
    incoming.on('close', () => sockets.delete(incoming));
    outgoing.on('close', () => sockets.delete(outgoing));
    incoming.pipe(outgoing).pipe(incoming);
  });
  listener.listen(port, '127.0.0.1');
  await once(listener, 'listening');
  closes.push(() => {
    for (const socket of sockets) socket.destroy();
    return new Promise(resolveClose => listener.close(resolveClose));
  });
}

export async function openClient(server, protocolVersion, closes, capabilities = {}) {
  const mode = protocolVersion === modern ? { pin: modern } : protocolVersion === legacy ? 'legacy' : 'auto';
  const client = new Client(clientInfo, {
    versionNegotiation: { mode },
    supportedProtocolVersions: protocolVersion ? [protocolVersion] : [modern, legacy],
    capabilities,
  });
  const transport = new StreamableHTTPClientTransport(server.url, {
    authProvider: { token: async () => server.token },
    requestInit: {
      redirect: 'error',
      headers: server.freshConnections ? { Connection: 'close' } : undefined,
    },
  });
  closes.push(() => client.close());
  await client.connect(transport);
  if (protocolVersion) {
    assert.equal(client.getProtocolEra(), protocolVersion === modern ? 'modern' : 'legacy');
  }
  return client;
}

export async function call(client, name, args) {
  const result = await client.callTool({ name, arguments: args }, { timeout: 10_000 });
  assert.ok(!result.isError, `tool ${name} failed`);
  assert.ok(result.structuredContent, `tool ${name} omitted structured output`);
  return result.structuredContent;
}

export async function taskSession(client, server) {
  assert.ok(client.getServerCapabilities().extensions?.['io.modelcontextprotocol/tasks']);
  const endpointId = await createTaskSessionEndpointId('howl-interop', server.url.href);
  let id = 1;
  return createTaskSessionFromClient(client, {
    endpointId,
    v2RequestFraming: {
      protocolVersion: modern,
      clientInfo,
      clientCapabilities: tasksCapability,
    },
    rawDispatch: async (request, options) => {
      const headers = new Headers(options?.headers);
      Object.entries({
        Authorization: `Bearer ${server.token}`,
        Accept: 'application/json, text/event-stream',
        'Content-Type': 'application/json',
        'MCP-Protocol-Version': modern,
        'Mcp-Method': request.method,
        'Mcp-Name': request.params.name ?? request.params.taskId,
      }).forEach(([name, value]) => headers.set(name, value));
      if (server.freshConnections) headers.set('Connection', 'close');
      const signals = [AbortSignal.timeout(10_000)];
      if (options?.signal) signals.push(options.signal);
      const requestId = id++;
      const response = await fetch(server.url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ jsonrpc: '2.0', ...request, id: requestId }),
        redirect: 'error',
        signal: AbortSignal.any(signals),
      });
      const result = await rpcResponse(response, requestId);
      assert.equal(result.jsonrpc, '2.0');
      return result;
    },
  });
}

async function rpcResponse(response, requestId) {
  const type = response.headers.get('content-type')?.split(';')[0];
  if (type === 'application/json') return response.json();
  assert.equal(type, 'text/event-stream', 'unexpected MCP response media type');
  const messages = response.body.pipeThrough(new TextDecoderStream())
    .pipeThrough(new EventSourceParserStream());
  for await (const { data } of messages) {
    if (!data) continue;
    const message = JSON.parse(data);
    if (message.id === requestId) return message;
  }
  assert.fail('MCP stream ended before its response');
}

export function wakeArgs(channel, { peer, target, text }) {
  return { channel, peer, target, text, key: randomUUID(), lifetime: 90 };
}

export async function waitRun(client, channel, run, timeoutMs = 90_000) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    const state = await call(client, 'get_run', { channel, run });
    if (state.status !== 'working') return state;
    await delay(750);
  }
  assert.fail('durable run timed out');
}
