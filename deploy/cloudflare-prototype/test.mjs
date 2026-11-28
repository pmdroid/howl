import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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

test("Cloudflare Worker with D1", async t => {
  const runtime = new Miniflare({
    modules: true,
    scriptPath: fileURLToPath(new URL("./worker.mjs", import.meta.url)),
    compatibilityDate: "2026-07-30",
    unsafeTriggerHandlers: true,
    d1Databases: { DB: "00000000-0000-4000-8000-000000000001" }
  });
  t.after(() => runtime.dispose());

  const db = await runtime.getD1Database("DB");
  const schema = await readFile(new URL("./migrations/0001_control_plane.sql", import.meta.url), "utf8");
  await db.batch(schema.split(";").filter(sql => sql.trim()).map(sql => db.prepare(sql)));

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
