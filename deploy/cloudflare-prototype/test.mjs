import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Miniflare } from "miniflare";

const origin = "https://howl.test";
const fetchPath = "/v1/mailbox/fetch";
const depositPath = "/v1/mailbox/deposit";
const ackPath = "/v1/mailbox/ack";
const encoder = new TextEncoder();
const firstPage = { after: 0, limit: 16 };

function randomId() {
  return crypto.getRandomValues(Buffer.alloc(32)).toString("hex");
}

function epoch() {
  return Math.floor(Date.now() / 1000);
}

async function digest(bytes) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex");
}

async function proof({ account, device, signingKey }, path, data, expires = epoch() + 45) {
  const nonce = randomId();
  const hash = await digest(encoder.encode(JSON.stringify(data)));
  const payload = encoder.encode(JSON.stringify(["howl-d1-proof-v1", path, account, device, nonce, expires, hash]));
  const signature = await crypto.subtle.sign("Ed25519", signingKey, payload);
  return {
    "Howl-Account": account,
    "Howl-Device": device,
    "Howl-Nonce": nonce,
    "Howl-Expires": String(expires),
    "Howl-Signature": Buffer.from(signature).toString("hex")
  };
}

async function expectStatus(response, status) {
  const value = await response;
  const raw = await value.text();
  assert.equal(value.status, status, raw);
  return raw ? JSON.parse(raw) : undefined;
}

async function migrate(runtime) {
  const db = await runtime.getD1Database("DB");
  const migrations = new URL("./migrations/", import.meta.url);
  for (const file of (await readdir(migrations)).sort()) {
    const schema = await readFile(new URL(file, migrations), "utf8");
    await db.batch(schema.split(";").filter(sql => sql.trim()).map(sql => db.prepare(sql)));
  }
  return db;
}

test("Cloudflare Worker with D1", async t => {
  const runtime = new Miniflare({
    modules: true,
    scriptPath: fileURLToPath(new URL("./worker.mjs", import.meta.url)),
    compatibilityDate: "2026-07-30",
    unsafeTriggerHandlers: true,
    d1Databases: { DB: "00000000-0000-4000-8000-000000000001" }
  });
  t.after(() => runtime.dispose());

  const db = await migrate(runtime);

  function request(path, data, headers) {
    return runtime.dispatchFetch(origin + path, {
      method: data === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: data === undefined ? undefined : JSON.stringify(data)
    });
  }

  async function owner() {
    const account = randomId();
    const token = randomId();
    await db.prepare("INSERT INTO owners (account, token_digest) VALUES (?, ?)")
      .bind(account, await digest(encoder.encode(token))).run();
    return { account, headers: { Authorization: "Bearer " + token } };
  }

  async function link(name) {
    const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const key = Buffer.from(await crypto.subtle.exportKey("raw", keys.publicKey));
    const enrollment = await expectStatus(request("/v1/device-links", { name, public_key: key.toString("hex") }), 201);
    assert.equal(enrollment.fingerprint, await digest(key));
    return { ...enrollment, signingKey: keys.privateKey, name };
  }

  function claim(owner, { secret }) {
    return request("/api/device-links/claim", { secret }, owner.headers);
  }

  function decide(owner, { device, fingerprint }, decision) {
    return request("/api/devices/decide", { device, fingerprint, decision }, owner.headers);
  }

  async function signed(device, path, data) {
    return request(path, data, await proof(device, path, data));
  }

  const alice = await owner();
  const bob = await owner();
  const sender = { ...await link("Laptop"), account: alice.account };
  const recipient = { ...await link("Mini"), account: alice.account };
  const outsider = { ...await link("Other account"), account: bob.account };
  const denied = { ...await link("Unwanted device"), account: alice.account };

  await t.test("owners see fingerprints and decide only for their own devices", async () => {
    await expectStatus(request("/healthz"), 204);
    await expectStatus(request("/api/devices"), 401);
    await expectStatus(decide(alice, recipient, "approve"), 404);
    const pending = await expectStatus(claim(alice, recipient), 200);
    assert.deepEqual(pending, {
      device: recipient.device, name: recipient.name, fingerprint: recipient.fingerprint, state: "pending"
    });
    await expectStatus(claim(bob, recipient), 404);
    assert.deepEqual(await expectStatus(request("/api/devices", undefined, bob.headers), 200), { devices: [] });
    assert.deepEqual(await expectStatus(request("/api/devices", undefined, alice.headers), 200), { devices: [pending] });
    await expectStatus(decide(bob, recipient, "approve"), 404);
    await expectStatus(decide(alice, { ...recipient, fingerprint: randomId() }, "approve"), 404);
    await expectStatus(signed(recipient, fetchPath, firstPage), 401);
    for (const [owner, device] of [[alice, sender], [bob, outsider], [alice, denied]]) {
      await expectStatus(claim(owner, device), 200);
    }
    for (const [owner, device] of [[alice, recipient], [alice, sender], [bob, outsider]]) {
      assert.deepEqual(await expectStatus(decide(owner, device, "approve"), 200), { state: "approved" });
    }
    await expectStatus(decide(alice, recipient, "approve"), 200);
    await expectStatus(decide(alice, recipient, "deny"), 409);
    assert.deepEqual(await expectStatus(decide(alice, denied, "deny"), 200), { state: "denied" });
    await expectStatus(signed(denied, fetchPath, firstPage), 401);
    await expectStatus(signed({ ...recipient, account: bob.account }, fetchPath, firstPage), 401);
    await expectStatus(signed({ ...recipient, signingKey: outsider.signingKey }, fetchPath, firstPage), 401);
  });

  await t.test("a concurrent claim and concurrent decisions each have one winner", async () => {
    const device = await link("Racing enrollment");
    const claims = await Promise.all([claim(alice, device), claim(bob, device)]);
    assert.deepEqual(claims.map(r => r.status).sort(), [200, 404]);
    const winner = claims[0].status === 200 ? alice : bob;
    const loser = claims[0].status === 200 ? bob : alice;
    await expectStatus(decide(loser, device, "approve"), 404);

    const decisions = ["approve", "deny"];
    const results = await Promise.all(decisions.map(decision => decide(winner, device, decision)));
    assert.deepEqual(results.map(r => r.status).sort(), [200, 409]);
    const selected = decisions[results.findIndex(r => r.status === 200)];
    const outcome = await expectStatus(decide(winner, device, selected), 200);
    assert.equal(outcome.state, selected === "approve" ? "approved" : "denied");
    const devices = await expectStatus(request("/api/devices", undefined, winner.headers), 200);
    assert.equal(devices.devices.find(row => row.device === device.device).state, outcome.state);
  });

  await t.test("encrypted delivery can be retried, read only by the recipient, and acknowledged", async () => {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const wrongKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const iv = crypto.getRandomValues(Buffer.alloc(12));
    const plaintext = encoder.encode("Private message for Mini");
    const encrypted = Buffer.from(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
    const ciphertext = iv.toString("hex") + encrypted.toString("hex");
    const body = { recipient: recipient.device, message: randomId(), ciphertext, expires_at: epoch() + 600 };

    await expectStatus(signed(outsider, depositPath, body), 403);
    await expectStatus(signed(sender, depositPath, { ...body, recipient: denied.device }), 403);
    const deposits = await Promise.all([signed(sender, depositPath, body), signed(sender, depositPath, body)]);
    assert.deepEqual(deposits.map(r => r.status).sort(), [201, 204]);

    for (const device of [sender, outsider]) {
      assert.deepEqual(await expectStatus(signed(device, fetchPath, firstPage), 200), { envelopes: [], next: null });
    }

    const { envelopes } = await expectStatus(signed(recipient, fetchPath, firstPage), 200);
    const envelopeDigest = await digest(Buffer.from(ciphertext, "hex"));
    assert.deepEqual(envelopes, [{ cursor: 1, sender: sender.device, message: body.message, digest: envelopeDigest, ciphertext }]);
    const stored = await db.prepare("SELECT typeof(ciphertext) AS type, hex(ciphertext) AS data, digest FROM envelopes WHERE message = ?")
      .bind(body.message).first();
    assert.deepEqual(stored, { type: "blob", data: ciphertext.toUpperCase(), digest: envelopeDigest });

    const received = Buffer.from(envelopes[0].ciphertext, "hex");
    const algorithm = { name: "AES-GCM", iv: received.slice(0, 12) };
    const decrypted = await crypto.subtle.decrypt(algorithm, key, received.slice(12));
    assert.deepEqual(new Uint8Array(decrypted), plaintext);
    await assert.rejects(crypto.subtle.decrypt(algorithm, wrongKey, received.slice(12)));
    received[12] ^= 1;
    await assert.rejects(crypto.subtle.decrypt(algorithm, key, received.slice(12)));

    await expectStatus(signed(sender, depositPath, { ...body, ciphertext: received.toString("hex") }), 409);
    const ack = { cursor: 1, message: body.message, digest: envelopeDigest };
    await expectStatus(signed(sender, ackPath, ack), 404);
    await expectStatus(signed(outsider, ackPath, ack), 404);
    await expectStatus(signed(recipient, ackPath, { ...ack, digest: randomId() }), 404);
    await expectStatus(signed(recipient, ackPath, ack), 204);
    await expectStatus(signed(recipient, ackPath, ack), 204);
    await expectStatus(signed(sender, depositPath, body), 204);

    assert.deepEqual(await expectStatus(signed(recipient, fetchPath, firstPage), 200), { envelopes: [], next: null });
    assert.deepEqual(await db.prepare("SELECT ciphertext, digest FROM envelopes WHERE message = ?").bind(body.message).first(),
      { ciphertext: null, digest: envelopeDigest });
  });

  await t.test("signed requests bind the operation and body, and consume each nonce once", async () => {
    const headers = await proof(recipient, fetchPath, firstPage);
    await expectStatus(request(fetchPath, { after: 1, limit: 16 }, headers), 401);
    await expectStatus(request(ackPath, firstPage, headers), 401);
    const responses = await Promise.all([request(fetchPath, firstPage, headers), request(fetchPath, firstPage, headers)]);
    assert.deepEqual(responses.map(r => r.status).sort(), [200, 409]);
    await expectStatus(request(fetchPath, firstPage, await proof(recipient, fetchPath, firstPage, epoch() - 10)), 401);
  });

  await t.test("Howl encrypted frames survive D1 pagination and expired data is swept", async () => {
    const fixture = JSON.parse(await readFile(new URL("../../spikes/protocol/wake-v1.json", import.meta.url), "utf8"));
    const linkToExpire = await link("Expired pending device");
    await expectStatus(claim(alice, linkToExpire), 200);
    const frame = { recipient: recipient.device, ciphertext: fixture.frame, expires_at: epoch() + 600 };
    const messages = [randomId(), randomId()];
    await Promise.all(messages.map(message => expectStatus(signed(sender, depositPath, { ...frame, message }), 201)));
    const first = await expectStatus(signed(recipient, fetchPath, { after: 0, limit: 1 }), 200);
    assert.equal(first.next, 2);
    const second = await expectStatus(signed(recipient, fetchPath, { after: first.next, limit: 1 }), 200);
    assert.equal(second.next, 3);
    const envelopes = [...first.envelopes, ...second.envelopes];
    assert.deepEqual(envelopes.map(row => row.message).sort(), messages.sort());
    assert.deepEqual(envelopes.map(row => row.ciphertext), [fixture.frame, fixture.frame]);

    await db.batch([
      db.prepare("UPDATE envelopes SET expires_at = unixepoch() - 1 WHERE message = ?").bind(second.envelopes[0].message),
      db.prepare("UPDATE device_links SET expires_at = unixepoch() - 1 WHERE id = ?").bind(linkToExpire.id),
      db.prepare("UPDATE device_proofs SET expires_at = unixepoch() - 1")
    ]);
    const expired = await expectStatus(signed(recipient, fetchPath, { after: 2, limit: 16 }), 200);
    assert.deepEqual(expired, { envelopes: [], next: null });
    await expectStatus(decide(alice, linkToExpire, "approve"), 404);
    await expectStatus(signed(sender, depositPath, { ...frame, message: second.envelopes[0].message }), 410);
    const cleanup = await runtime.dispatchFetch(origin + "/cdn-cgi/handler/scheduled?cron=" + encodeURIComponent("*/5 * * * *"));
    assert.equal(cleanup.status, 200, await cleanup.text());
    assert.equal(await db.prepare("SELECT message FROM envelopes WHERE message = ?").bind(second.envelopes[0].message).first(), null);
    assert.equal(await db.prepare("SELECT id FROM device_links WHERE id = ?").bind(linkToExpire.id).first(), null);
    assert.equal(await db.prepare("SELECT COUNT(*) AS count FROM device_proofs WHERE expires_at <= unixepoch()").first("count"), 0);
    await expectStatus(signed(sender, depositPath, { ...frame, message: randomId() }), 201);
    const next = await expectStatus(signed(recipient, fetchPath, { after: 2, limit: 16 }), 200);
    assert.equal(next.next, 4);
  });

  await t.test("D1 accepts a maximum-size encrypted envelope", async () => {
    const bytes = crypto.getRandomValues(Buffer.alloc(65536));
    const tail = crypto.getRandomValues(Buffer.alloc(77112 - bytes.length));
    const ciphertext = Buffer.concat([bytes, tail]).toString("hex");
    const frame = { recipient: recipient.device, message: randomId(), ciphertext, expires_at: epoch() + 600 };
    await expectStatus(signed(sender, depositPath, { ...frame, ciphertext: ciphertext + "00" }), 400);
    await expectStatus(signed(sender, depositPath, frame), 201);
    const page = await expectStatus(signed(recipient, fetchPath, { after: 4, limit: 1 }), 200);
    assert.equal(page.envelopes[0].ciphertext, ciphertext);
  });
});

test("GitHub owner login and native device enrollment", async t => {
  let githubId = 42;
  let challenge;
  let exchanges = 0;
  let revocations = 0;
  const runtime = new Miniflare({
    modules: true,
    scriptPath: fileURLToPath(new URL("./worker.mjs", import.meta.url)),
    compatibilityDate: "2026-07-30",
    d1Databases: { DB: "00000000-0000-4000-8000-000000000002" },
    bindings: { WEB_ORIGIN: origin, GITHUB_CLIENT_ID: "test-app", GITHUB_CLIENT_SECRET: "fixture", GITHUB_OWNER_ID: "42" },
    outboundService: async request => {
      const url = new URL(request.url);
      switch (url.href) {
        case "https://github.com/login/oauth/access_token": {
          ++exchanges;
          const params = new URLSearchParams(await request.text());
          assert.equal(params.get("redirect_uri"), origin + "/login/github/callback");
          const pkce = Buffer.from(await digest(encoder.encode(params.get("code_verifier"))), "hex").toString("base64url");
          assert.equal(pkce, challenge);
          return Response.json({ access_token: "fixture-access-token" });
        }
        case "https://api.github.com/user":
          assert.equal(request.headers.get("Authorization"), "Bearer fixture-access-token");
          return Response.json({ id: githubId });
        case "https://api.github.com/applications/test-app/token":
          ++revocations;
          assert.equal(request.method, "DELETE");
          assert.deepEqual(await request.json(), { access_token: "fixture-access-token" });
          return new Response(null, { status: 204 });
        default:
          throw new Error("unexpected upstream " + url);
      }
    }
  });
  t.after(() => runtime.dispose());
  await migrate(runtime);

  function request(path, data, headers = {}) {
    return runtime.dispatchFetch(origin + path, {
      redirect: "manual",
      method: data === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: data === undefined ? undefined : JSON.stringify(data)
    });
  }

  async function startLogin() {
    const start = await request("/login/github");
    assert.equal(start.status, 303);
    const location = new URL(start.headers.get("Location"));
    assert.equal(location.origin, "https://github.com");
    assert.equal(location.searchParams.get("code_challenge_method"), "S256");
    challenge = location.searchParams.get("code_challenge");
    const state = location.searchParams.get("state");
    return {
      callback: "/login/github/callback?code=fixture-code&state=" + state,
      verifier: start.headers.get("Set-Cookie").split(";")[0]
    };
  }

  const login = await startLogin();
  await expectStatus(request(login.callback), 401);
  await expectStatus(request(login.callback, undefined, { Cookie: "__Host-howl-login=" + randomId() }), 401);
  assert.equal(exchanges, 0);
  const authenticated = await request(login.callback, undefined, { Cookie: login.verifier });
  assert.equal(authenticated.status, 303);
  const session = authenticated.headers.getSetCookie().find(value => value.startsWith("__Host-howl-owner="));
  assert.match(session, /Secure; HttpOnly; SameSite=Strict/);
  const cookie = session.split(";")[0];
  await expectStatus(request(login.callback, undefined, { Cookie: login.verifier }), 401);
  assert.equal(exchanges, 1);
  assert.equal(revocations, 1);
  const { account } = await expectStatus(request("/api/session", undefined, { Cookie: cookie }), 200);

  githubId = 43;
  const stranger = await startLogin();
  await expectStatus(request(stranger.callback, undefined, { Cookie: stranger.verifier }), 403);
  assert.equal(revocations, 2);
  await expectStatus(request("/api/devices"), 401);

  const signing = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const endpoint = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const rawSigning = Buffer.from(await crypto.subtle.exportKey("raw", signing.publicKey));
  const rawEndpoint = Buffer.from(await crypto.subtle.exportKey("raw", endpoint.publicKey));
  const receiver = await crypto.subtle.generateKey("X25519", true, ["deriveBits"]);
  const rawReceiver = Buffer.from(await crypto.subtle.exportKey("raw", receiver.publicKey));
  const device = randomId();
  const body = Buffer.concat([Buffer.from([1]), Buffer.from(device, "hex"), rawSigning, rawEndpoint, rawReceiver]);
  const scope = Buffer.concat([Buffer.from("howl/manual-peer/v1\0"), body]);
  const sign = async key => Buffer.from(await crypto.subtle.sign("Ed25519", key, scope));
  const peer = Buffer.concat([body, await sign(signing.privateKey), await sign(endpoint.privateKey)]).toString("hex");
  const name = "Native device";
  await expectStatus(request("/v1/device-links", { name, peer: peer.slice(0, -2) + (peer.endsWith("ff") ? "00" : "ff") }), 400);
  const pending = await expectStatus(request("/v1/device-links", { peer, name }), 201);
  assert.equal(pending.device, device);
  assert.equal(pending.fingerprint, await digest(body));
  assert.equal(pending.url, origin + "/link#" + pending.secret);
  await expectStatus(request("/api/device-links/claim", { secret: pending.secret }, { Cookie: cookie, Origin: "https://elsewhere.test" }), 403);
  const headers = { Cookie: cookie, Origin: origin };
  await expectStatus(request("/api/device-links/claim", { secret: pending.secret }, headers), 200);
  const { state, account: pendingAccount } = await expectStatus(request("/v1/device-links/status", { secret: pending.secret }), 200);
  assert.deepEqual({ state, pendingAccount }, { state: "pending", pendingAccount: null });

  const path = "/v1/devices/lookup";
  const signed = async () => request(path, { device }, await proof({ device, account, signingKey: signing.privateKey }, path, { device }));
  await expectStatus(signed(), 401);
  await expectStatus(request("/api/devices/decide", { device, fingerprint: pending.fingerprint, decision: "approve" }, headers), 200);
  assert.deepEqual(await expectStatus(request("/v1/device-links/status", { secret: pending.secret }), 200), { state: "approved", account });
  assert.deepEqual(await expectStatus(signed(), 200), { peer });
  assert.equal((await request("/logout", {}, headers)).status, 303);
  await expectStatus(request("/api/session", undefined, { Cookie: cookie }), 401);
});
