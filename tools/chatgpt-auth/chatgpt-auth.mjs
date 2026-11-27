import { spawn } from 'node:child_process';
import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify } from 'node:crypto';
import { constants, fstatSync } from 'node:fs';
import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import { createServer } from 'node:http';
import { isAbsolute, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const issuer = 'https://auth.openai.com';
const resource = 'https://api.openai.com/v1';
const callbackPath = '/auth/callback';
const scope = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const refreshRejections = new Set([
  'invalid_grant', 'invalid_refresh_token', 'token_expired', 'refresh_token_expired',
  'refresh_token_invalidated', 'refresh_token_reused',
]);

class AuthError extends Error {}

const fail = message => { throw new AuthError(message); };
const now = () => Math.floor(Date.now() / 1000);
const randomSecret = () => randomBytes(32).toString('base64url');
const isToken = token => typeof token === 'string' && /^[\x21-\x7e]{1,16384}$/.test(token);
const issuedClient = value => typeof value === 'string' && /^oaiapp_[a-zA-Z0-9_-]+$/.test(value);
const hasPlan = scopes => Array.isArray(scopes) && ['resource.invoke', 'chatgpt.tokens.use.direct']
  .every(required => scopes.includes(required));

function equal(expected, value) {
  if (typeof value !== 'string') return false;
  const left = Buffer.from(expected);
  const right = Buffer.from(value);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function localDirectory(path) {
  if (!isAbsolute(path)) fail('Use an absolute directory for Howl ChatGPT credentials.');
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.uid !== process.getuid() || (metadata.mode & 0o777) !== 0o700
      || await realpath(path) !== path) {
    fail('The Howl ChatGPT credential directory must be a private, owner-only directory.');
  }
}

async function readRecord(path) {
  let fd;
  try {
    fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = await fd.stat();
    if (!metadata.isFile() || metadata.uid !== process.getuid() || (metadata.mode & 0o777) !== 0o600
        || metadata.size > 65536) {
      fail('The Howl ChatGPT credential file must be private and owned by the current user.');
    }
    return JSON.parse(await fd.readFile('utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  } finally {
    await fd?.close();
  }
}

async function writeRecord(path, value) {
  const temporary = path + '.' + randomUUID();
  const fd = await open(temporary, 'wx', 0o600);
  try {
    try {
      await fd.writeFile(JSON.stringify(value));
      await fd.sync();
    } finally {
      await fd.close();
    }
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

async function locked(directory, action) {
  const database = new DatabaseSync(join(directory, 'session-lock.sqlite'), { timeout: 20000 });
  try {
    database.exec('BEGIN IMMEDIATE');
    const result = await action();
    database.exec('COMMIT');
    return result;
  } finally {
    database.close();
  }
}

async function tokenRequest(parameters) {
  const response = await fetch(issuer + '/api/accounts/oauth/token', {
    method: 'POST',
    body: new URLSearchParams({ ...parameters, resource }),
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new AuthError('OpenAI declined the credential request. Sign in again if the session has expired.');
    error.terminalRefresh = refreshRejections.has(result?.error);
    throw error;
  }
  return result;
}

function scopeList(value, previous) {
  const scopes = typeof value === 'string' ? value.trim().split(/\s+/) : previous;
  if (!Array.isArray(scopes)) fail('OpenAI did not confirm the granted permissions.');
  return scopes;
}

function credentialUpdate(response, previous = {}) {
  const scopes = scopeList(response.scope, previous.scopes);
  const refresh = response.refresh_token;
  if (String(response.token_type).toLowerCase() !== 'bearer'
      || !isToken(response.access_token) || !isToken(refresh)
      || !Number.isSafeInteger(response.expires_in) || response.expires_in <= 0
      || response.expires_in > 86400) fail('OpenAI returned invalid session credentials.');
  return {
    access: response.access_token,
    refresh,
    scopes,
    expires: now() + response.expires_in,
    refreshAfter: Number.isSafeInteger(response.earliest_refresh_at) ? response.earliest_refresh_at : null,
  };
}

export function verifiedIdentity(token, keys, client, nonce, time = now()) {
  if (!isToken(token)) fail('OpenAI returned an invalid identity token.');
  const jwt = token.split('.');
  if (jwt.length !== 3 || !jwt.every(part => /^[a-zA-Z0-9_-]+$/.test(part))) {
    fail('OpenAI returned an invalid identity token.');
  }
  const [head, body, signature] = jwt;
  const header = JSON.parse(Buffer.from(head, 'base64url'));
  if (header.alg !== 'RS256' || header.crit !== undefined || typeof header.kid !== 'string') {
    fail('OpenAI returned an unsupported identity token.');
  }
  const key = keys.find(key => key.kid === header.kid && key.kty === 'RSA'
    && (key.use === undefined || key.use === 'sig') && (key.alg === undefined || key.alg === 'RS256'));
  if (!key || !verify('sha256', Buffer.from(head + '.' + body), createPublicKey({ key, format: 'jwk' }),
    Buffer.from(signature, 'base64url'))) fail('OpenAI returned an invalid identity signature.');

  const claims = JSON.parse(Buffer.from(body, 'base64url'));
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
  if (claims.iss !== issuer || !Array.isArray(audiences) || !audiences.includes(client)
      || ((audiences.length > 1 || claims.azp !== undefined) && claims.azp !== client)
      || !Number.isFinite(claims.exp) || time >= claims.exp
      || (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || time < claims.nbf))
      || !equal(nonce, claims.nonce) || typeof claims.sub !== 'string' || !claims.sub) {
    fail('OpenAI returned identity claims that did not match this sign-in.');
  }
  return claims.sub;
}

async function identity(token, client, nonce) {
  const response = await fetch(issuer + '/.well-known/jwks.json', {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) fail('Could not fetch OpenAI identity signing keys.');
  const { keys } = await response.json();
  if (!Array.isArray(keys)) fail('OpenAI returned invalid identity signing keys.');
  return verifiedIdentity(token, keys, client, nonce);
}

function browserOpen(url) {
  const command = process.platform === 'darwin' ? 'open' : 'xdg-open';
  return new Promise((resolve, reject) => {
    const child = spawn(command, [url], { stdio: 'ignore' });
    child.once('error', reject);
    child.once('exit', code => code === 0 ? resolve() : reject(new Error('Browser launch failed')));
  });
}

export function callbackParameters(requestUrl, state, client) {
  const url = new URL(requestUrl, 'http://127.0.0.1');
  if (url.origin !== 'http://127.0.0.1' || url.pathname !== callbackPath
      || url.searchParams.getAll('state').length !== 1 || !equal(state, url.searchParams.get('state'))) {
    return null;
  }
  if (url.searchParams.has('error')) return { denied: true };
  const codes = url.searchParams.getAll('code');
  const clients = url.searchParams.getAll('client_id');
  const resultClient = clients[0] ?? client;
  if (codes.length !== 1 || !isToken(codes[0]) || clients.length > 1 || !issuedClient(resultClient)
      || (client && client !== resultClient)) return { denied: true };
  return { code: codes[0], client: resultClient };
}

async function browserConsent(host, client) {
  const state = randomSecret();
  const nonce = randomSecret();
  const verifier = randomSecret();
  let resolveCallback;
  let complete = false;
  const callback = new Promise(resolve => { resolveCallback = resolve; });
  const server = createServer((request, response) => {
    let result;
    try {
      if (request.method === 'GET' && !complete) result = callbackParameters(request.url, state, client);
    } catch {}
    if (result) complete = true;
    response.writeHead(result ? 200 : 400, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
    });
    response.end(result ? 'Return to the terminal to finish connecting Howl.' : 'Invalid Howl callback.');
    if (result) resolveCallback(result);
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const redirect = `http://127.0.0.1:${server.address().port}${callbackPath}`;
  const authorize = new URL(issuer + '/api/accounts/authorize');
  authorize.search = new URLSearchParams({
    client_id: client ?? 'dynamic_agent_client',
    ext_agent_host_id: host,
    response_type: 'code',
    redirect_uri: redirect,
    scope,
    resource,
    state,
    nonce,
    code_challenge_method: 'S256',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    ...(!client ? { agent_name_hint: 'Howl' } : {}),
  });
  const timer = new AbortController();
  try {
    await browserOpen(authorize.href);
    process.stderr.write('Complete Continue with ChatGPT in your browser.\n');
    const result = await Promise.race([callback, delay(600000, null, { signal: timer.signal })]);
    if (!result || result.denied) fail('Howl ChatGPT authorization was declined or did not complete.');
    return { ...result, nonce, verifier, redirect };
  } finally {
    timer.abort();
    server.closeAllConnections();
    server.close();
  }
}

async function signIn(directory, path) {
  const hostPath = join(directory, 'host.json');
  const { host, previous } = await locked(directory, async () => {
    const savedHost = await readRecord(hostPath);
    const host = savedHost?.host ?? 'urn:uuid:' + randomUUID();
    if (!savedHost) await writeRecord(hostPath, { host });
    const previous = await readRecord(path);
    return { host, previous };
  });
  const client = previous?.client;
  const consent = await browserConsent(host, client);
  if (!client) {
    await locked(directory, async () => {
      if (await readRecord(path)) fail('A Howl ChatGPT connection was registered during authorization.');
      await writeRecord(path, { client: consent.client });
    });
  }
  const response = await tokenRequest({
    grant_type: 'authorization_code',
    client_id: consent.client,
    code: consent.code,
    code_verifier: consent.verifier,
    redirect_uri: consent.redirect,
  });
  const subject = await identity(response.id_token, consent.client, consent.nonce);
  if (previous?.subject && previous.subject !== subject) {
    fail('OpenAI returned a different account for the saved Howl connection.');
  }
  const credentials = credentialUpdate(response);
  await locked(directory, async () => {
    const current = await readRecord(path);
    if (current?.client !== consent.client || (current.subject && current.subject !== subject)) {
      fail('The selected Howl ChatGPT account changed during authorization.');
    }
    await writeRecord(path, { client: consent.client, subject, ...credentials });
  });
  if (!hasPlan(credentials.scopes)) fail('ChatGPT plan usage was not granted for Howl.');
  process.stderr.write('Howl is connected to your ChatGPT plan.\n');
}

async function accessToken(directory, path) {
  return locked(directory, async () => {
    const record = await readRecord(path);
    if (!record || !issuedClient(record.client) || !hasPlan(record.scopes ?? [])) {
      fail('Connect Howl to your ChatGPT plan first.');
    }
    const time = now();
    if (Number.isSafeInteger(record.expires) && isToken(record.access) && (record.expires > time + 180
        || (record.expires > time && record.refreshAfter > time))) return record.access;
    if (!isToken(record.refresh)) fail('Sign in to reconnect Howl to your ChatGPT plan.');
    let response;
    try {
      response = await tokenRequest({
        grant_type: 'refresh_token',
        client_id: record.client,
        refresh_token: record.refresh,
      });
    } catch (error) {
      if (error.terminalRefresh) {
        await writeRecord(path, { client: record.client, subject: record.subject });
      }
      throw error;
    }
    const credentials = credentialUpdate(response, record);
    await writeRecord(path, { client: record.client, subject: record.subject, ...credentials });
    if (!hasPlan(credentials.scopes)) fail('ChatGPT plan usage was not granted for Howl.');
    return credentials.access;
  });
}

async function modelList(token) {
  const response = await fetch(resource + '/models', {
    headers: { Authorization: 'Bearer ' + token },
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) fail('Could not list models for the Howl ChatGPT plan connection.');
  const { models } = await response.json();
  if (!Array.isArray(models)) fail('OpenAI returned an invalid ChatGPT plan model list.');
  const display = models
    .filter(model => model?.visibility === 'list' && /^[a-zA-Z0-9._-]{1,128}$/.test(model.slug ?? ''))
    .map(model => model.slug);
  process.stdout.write(JSON.stringify(display) + '\n');
}

async function main() {
  const [, , command, directory] = process.argv;
  if (process.argv.length !== 4 || !['sign-in', 'token', 'models'].includes(command)) {
    fail('Usage: node chatgpt-auth.mjs sign-in|token|models ABSOLUTE_CREDENTIAL_DIRECTORY');
  }
  if (command === 'token' && !fstatSync(1).isFIFO()) {
    fail('Howl ChatGPT token output requires a private pipe.');
  }
  process.umask(0o077);
  await localDirectory(directory);
  const path = join(directory, 'session.json');
  if (command === 'sign-in') {
    await signIn(directory, path);
  } else {
    const token = await accessToken(directory, path);
    if (command === 'models') await modelList(token);
    else process.stdout.write(token + '\n');
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(error instanceof AuthError ? error.message + '\n' : 'Howl ChatGPT authorization failed.\n');
    process.exitCode = 1;
  });
}
