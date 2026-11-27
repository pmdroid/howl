import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import { chmod, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { callbackParameters, verifiedIdentity } from './chatgpt-auth.mjs';

test('callbacks bind the issued client and authorization state', () => {
  const callback = '/auth/callback?state=pending&code=code&client_id=oaiapp_howl';
  assert.deepEqual(callbackParameters(callback, 'pending'), { code: 'code', client: 'oaiapp_howl' });
  assert.equal(callbackParameters(callback, 'other'), null);
  assert.equal(callbackParameters(callback + '&state=pending', 'pending'), null);
  assert.deepEqual(callbackParameters(callback, 'pending', 'oaiapp_other'), { denied: true });
  assert.deepEqual(callbackParameters('/auth/callback?state=pending&code=value', 'pending', 'oaiapp_howl'),
    { code: 'value', client: 'oaiapp_howl' });
  assert.deepEqual(callbackParameters('/auth/callback?state=pending&error=access_denied', 'pending'), { denied: true });
});

test('OpenAI identity requires a valid signature and matching issuer, audience, nonce and expiry', () => {
  const signer = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = { ...signer.publicKey.export({ format: 'jwk' }), alg: 'RS256', kid: 'test', use: 'sig' };
  const encoded = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encoded({ alg: 'RS256', kid: 'test' });
  const token = claims => {
    const input = header + '.' + encoded(claims);
    return input + '.' + sign('sha256', Buffer.from(input), signer.privateKey).toString('base64url');
  };
  const valid = { iss: 'https://auth.openai.com', aud: 'oaiapp_howl', nonce: 'pending', sub: 'subject', exp: 100 };
  assert.equal(verifiedIdentity(token(valid), [key], 'oaiapp_howl', 'pending', 99), 'subject');
  for (const claims of [
    { iss: 'https://example.org' },
    { aud: 'oaiapp_other' },
    { aud: ['oaiapp_howl', 'oaiapp_other'], azp: 'oaiapp_other' },
    { nonce: 'other' },
    { exp: 99 },
  ]) {
    assert.throws(() => verifiedIdentity(token({ ...valid, ...claims }), [key], 'oaiapp_howl', 'pending', 99));
  }
  const [head, , signature] = token(valid).split('.');
  const forged = head + '.' + encoded({ ...valid, sub: 'forged' }) + '.' + signature;
  assert.throws(() => verifiedIdentity(forged, [key], 'oaiapp_howl', 'pending', 99), /invalid identity signature/);
});

test('only a private pipe reads a token from a private store with a plan grant', async () => {
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'howl-chatgpt-test-'));
  try {
    const script = fileURLToPath(new URL('./chatgpt-auth.mjs', import.meta.url));
    const run = () => spawnSync('bash', ['-o', 'pipefail', '-c', '"$1" "$2" token "$3" | cat', '_',
      process.execPath, script, directory], { encoding: 'utf8' });
    const expires = Math.floor(Date.now() / 1000) + 3600;
    const record = {
      expires,
      client: 'oaiapp_howl',
      access: 'a-synthetic-plan-token',
      scopes: ['resource.invoke', 'chatgpt.tokens.use.direct'],
    };
    const path = join(directory, 'session.json');
    await writeFile(path, JSON.stringify(record), { mode: 0o600 });
    const allowed = run();
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.equal(allowed.stdout.trim(), record.access);

    const direct = spawnSync(process.execPath, [script, 'token', directory], { encoding: 'utf8' });
    assert.equal(direct.status, 1);
    assert.equal(direct.stdout, '');
    assert.match(direct.stderr, /private pipe/);

    await writeFile(path, JSON.stringify({ ...record, scopes: ['resource.invoke'] }));
    const missingScope = run();
    assert.equal(missingScope.status, 1);
    assert.equal(missingScope.stdout, '');

    await chmod(path, 0o644);
    const exposed = run();
    assert.equal(exposed.status, 1);
    assert.equal(exposed.stdout, '');
    assert.match(exposed.stderr, /credential file must be private/);

    await rm(path);
    await writeFile(join(directory, 'other.json'), JSON.stringify(record), { mode: 0o600 });
    await symlink('other.json', path);
    const redirected = run();
    assert.equal(redirected.status, 1);
    assert.equal(redirected.stdout, '');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('an unexpectedly killed credential process releases its lock', async () => {
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'howl-chatgpt-lock-'));
  const program = 'import {DatabaseSync} from "node:sqlite";'
    + 'const db = new DatabaseSync(process.argv[1]);'
    + 'db.exec("BEGIN IMMEDIATE");'
    + 'process.stdout.write("ready");'
    + 'setInterval(() => {}, 1000);';
  const path = join(directory, 'session-lock.sqlite');
  const owner = spawn(process.execPath, ['--input-type=module', '-e', program, path]);
  try {
    assert.equal((await once(owner.stdout, 'data'))[0].toString(), 'ready');
    const exited = once(owner, 'exit');
    owner.kill('SIGKILL');
    await exited;
    const replacement = spawnSync(process.execPath, ['--input-type=module', '-e',
      'import {DatabaseSync} from "node:sqlite"; const db = new DatabaseSync(process.argv[1]); db.exec("BEGIN IMMEDIATE"); db.close();',
      path], { encoding: 'utf8' });
    assert.equal(replacement.status, 0, replacement.stderr);
  } finally {
    owner.kill('SIGKILL');
    await rm(directory, { recursive: true, force: true });
  }
});
