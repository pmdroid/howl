import { HttpError, decodeHex, digest, encodeHex, jsonBody, randomId, reply, requireValue } from "./http.mjs";
import { authenticateOwner, webRoute } from "./web.mjs";

const encoder = new TextEncoder();
const envelopeLimit = 77112;
const mailboxLifetime = 86400;
const word = /^[0-9a-f]{64}$/;
const signature = /^[0-9a-f]{128}$/;
const hasProof = "EXISTS (SELECT 1 FROM device_proofs WHERE attempt = ?)";

async function ownerAccount(db, request) {
  const token = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.get("Authorization") ?? "")?.[1];
  requireValue(token, 401);
  const account = await db.prepare("SELECT account FROM owners WHERE token_digest = ?")
    .bind(await digest(token)).first("account");
  requireValue(account, 401);
  return account;
}

async function verifySignature(key, signed, signedProof) {
  const publicKey = await crypto.subtle.importKey("raw", key, "Ed25519", false, ["verify"]);
  return crypto.subtle.verify("Ed25519", publicKey, signedProof, signed);
}

async function peerIdentity(peer) {
  requireValue(typeof peer === "string" && /^[0-9a-f]{514}$/.test(peer));
  const certificate = decodeHex(peer);
  const device = peer.slice(2, 66);
  const key = peer.slice(66, 130);
  const endpoint = peer.slice(130, 194);
  const encryption = peer.slice(194, 258);
  requireValue(certificate[0] === 1 && /[1-9a-f]/.test(device));
  requireValue(new Set([key, endpoint, encryption]).size === 3 && /[1-9a-f]/.test(encryption));
  const body = certificate.slice(0, 129);
  const domain = encoder.encode("howl/manual-peer/v1\0");
  const signed = new Uint8Array(domain.length + body.length);
  signed.set(domain);
  signed.set(body, domain.length);
  requireValue(await verifySignature(decodeHex(key), signed, certificate.slice(129, 193)));
  requireValue(await verifySignature(decodeHex(endpoint), signed, certificate.slice(193)));
  return { key, device, fingerprint: await digest(body) };
}

async function begin(db, request, origin) {
  const { parsed: { public_key, name, peer } } = await jsonBody(request);
  requireValue(typeof name === "string" && name.trim().length > 0 && Array.from(name.trim()).length <= 80 && !/\p{Cc}/u.test(name));
  if (!origin) requireValue(typeof public_key === "string" && word.test(public_key) && /[1-9a-f]/.test(public_key));
  const { key, device, fingerprint } = origin ? await peerIdentity(peer) : {
    key: public_key,
    device: await digest(JSON.stringify(["howl-d1-device-v1", public_key])),
    fingerprint: await digest(decodeHex(public_key))
  };
  const id = randomId();
  const secret = randomId();
  const created = await db.prepare(`
    INSERT INTO device_links (id, secret_digest, device, public_key, fingerprint, name, peer, expires_at)
    SELECT ?, ?, ?, ?, ?, ?, ?, unixepoch() + 600
    WHERE (SELECT COUNT(*) FROM device_links WHERE account IS NULL AND expires_at > unixepoch()) < 4096`)
    .bind(id, await digest(secret), device, key, fingerprint, name.trim(), origin ? peer : null).run();
  requireValue(created.meta.changes === 1, 429);
  const url = origin ? origin + "/link#" + secret : undefined;
  return reply({ id, secret, device, fingerprint, url }, 201);
}

async function linkStatus(db, request) {
  const { parsed: { secret } } = await jsonBody(request);
  requireValue(typeof secret === "string" && word.test(secret));
  const record = await db.prepare(`
    SELECT state, CASE state WHEN 'approved' THEN account END AS account FROM device_links
    WHERE secret_digest = ? AND (state = 'approved' OR expires_at > unixepoch())`).bind(await digest(secret)).first();
  requireValue(record, 404);
  return reply(record);
}

async function claim(db, request, account) {
  const { parsed: { secret } } = await jsonBody(request);
  requireValue(typeof secret === "string" && word.test(secret));
  const device = await db.prepare(`
    UPDATE device_links AS link SET account = ?
    WHERE secret_digest = ? AND expires_at > unixepoch() AND (account IS NULL OR account = ?)
      AND NOT EXISTS (
        SELECT 1 FROM device_links AS owned
        WHERE owned.account = ? AND owned.device = link.device AND owned.id != link.id
      )
    RETURNING device, name, fingerprint, state`)
    .bind(account, await digest(secret), account, account).first();
  requireValue(device, 404);
  return reply(device);
}

async function listDevices(db, account) {
  const { results } = await db.prepare(`
    SELECT device, name, fingerprint, state FROM device_links
    WHERE account = ? AND (state != 'pending' OR expires_at > unixepoch())
    ORDER BY name, device`).bind(account).all();
  return reply({ devices: results });
}

async function decide(db, request, account) {
  const { parsed: { device, fingerprint, decision } } = await jsonBody(request);
  requireValue(typeof device === "string" && word.test(device));
  requireValue(typeof fingerprint === "string" && word.test(fingerprint));
  requireValue(decision === "approve" || decision === "deny");
  const state = decision === "approve" ? "approved" : "denied";
  const result = await db.prepare(`
    UPDATE device_links SET state = ?
    WHERE account = ? AND device = ? AND fingerprint = ? AND state = 'pending' AND expires_at > unixepoch()
    RETURNING state`).bind(state, account, device, fingerprint).first();
  if (result) return reply(result);
  const existing = await db.prepare(`
    SELECT state FROM device_links WHERE account = ? AND device = ? AND fingerprint = ?
      AND (state != 'pending' OR expires_at > unixepoch())`).bind(account, device, fingerprint).first();
  requireValue(existing, 404);
  requireValue(existing.state === state, 409);
  return reply(existing);
}

async function deviceRequest(db, request, path, raw) {
  const account = request.headers.get("Howl-Account") ?? "";
  const device = request.headers.get("Howl-Device") ?? "";
  const nonce = request.headers.get("Howl-Nonce") ?? "";
  const expires = Number(request.headers.get("Howl-Expires"));
  const proof = request.headers.get("Howl-Signature") ?? "";
  const now = Math.floor(Date.now() / 1000);
  requireValue(word.test(account) && word.test(device) && word.test(nonce) && signature.test(proof)
    && Number.isSafeInteger(expires) && expires > now && expires <= now + 60, 401);
  const key = await db.prepare(`
    SELECT public_key FROM device_links WHERE account = ? AND device = ? AND state = 'approved'`)
    .bind(account, device).first("public_key");
  requireValue(key, 401);
  const message = encoder.encode(JSON.stringify(["howl-d1-proof-v1", path, account, device, nonce, expires, await digest(raw)]));
  requireValue(await verifySignature(decodeHex(key), message, decodeHex(proof)), 401);
  const attempt = randomId();
  return {
    account, device, attempt,
    reserve: db.prepare(`
      INSERT OR IGNORE INTO device_proofs (account, device, nonce, attempt, expires_at)
      SELECT account, device, ?, ?, ? FROM device_links
      WHERE account = ? AND device = ? AND state = 'approved' AND ? > unixepoch()`)
      .bind(nonce, attempt, expires, account, device, expires)
  };
}

async function deposit(db, caller, body) {
  const { recipient, message, ciphertext, expires_at } = body;
  requireValue(typeof recipient === "string" && word.test(recipient) && recipient !== caller.device);
  requireValue(typeof message === "string" && word.test(message));
  requireValue(typeof ciphertext === "string" && ciphertext.length >= 32
    && ciphertext.length <= envelopeLimit * 2 && ciphertext.length % 2 === 0 && !/[^0-9a-f]/.test(ciphertext));
  const now = Math.floor(Date.now() / 1000);
  requireValue(Number.isSafeInteger(expires_at) && expires_at <= now + mailboxLifetime);
  requireValue(expires_at > now, 410);
  const bytes = decodeHex(ciphertext);
  const envelopeDigest = await digest(bytes);
  const { account, device, attempt, reserve } = caller;
  const [proof, inbox, insert, , existing] = await db.batch([
    reserve,
    db.prepare(`
      INSERT INTO inboxes (account, recipient) SELECT account, device FROM device_links
      WHERE account = ? AND device = ? AND state = 'approved' AND ${hasProof}
      ON CONFLICT (account, recipient) DO UPDATE SET last_cursor = inboxes.last_cursor
      RETURNING last_cursor`).bind(account, recipient, attempt),
    db.prepare(`
      INSERT INTO envelopes (account, recipient, cursor, message, sender, digest, ciphertext, expires_at)
      SELECT account, recipient, last_cursor + 1, ?, ?, ?, ?, ?
      FROM inboxes WHERE account = ? AND recipient = ? AND ${hasProof}
        AND EXISTS (SELECT 1 FROM device_links WHERE account = ? AND device = ? AND state = 'approved')
        AND ? > unixepoch()
        AND (SELECT COUNT(*) FROM envelopes WHERE account = ? AND recipient = ? AND expires_at > unixepoch()) < 2048
        AND (SELECT COUNT(*) FROM envelopes WHERE account = ? AND recipient = ?
          AND expires_at > unixepoch() AND ciphertext IS NOT NULL) < 256
      ON CONFLICT (account, recipient, message) DO NOTHING RETURNING cursor`)
      .bind(message, device, envelopeDigest, bytes.buffer, expires_at, account, recipient, attempt,
        account, recipient, expires_at, account, recipient, account, recipient),
    db.prepare(`
      UPDATE inboxes SET last_cursor = MAX(last_cursor, COALESCE(
        (SELECT cursor FROM envelopes WHERE account = ? AND recipient = ? AND message = ?), last_cursor))
      WHERE account = ? AND recipient = ? AND ${hasProof}`)
      .bind(account, recipient, message, account, recipient, attempt),
    db.prepare(`
      SELECT sender, digest, expires_at > unixepoch() AS active FROM envelopes
      WHERE account = ? AND recipient = ? AND message = ? AND ${hasProof}`)
      .bind(account, recipient, message, attempt)
  ]);
  requireValue(proof.meta.changes === 1, 409);
  requireValue(inbox.results.length === 1, 403);
  if (insert.results.length === 1) return reply(null, 201);
  const previous = existing.results[0];
  requireValue(previous, 429);
  requireValue(previous.active, 410);
  requireValue(previous.sender === device && previous.digest === envelopeDigest, 409);
  return reply(null, 204);
}

async function fetchInbox(db, caller, { after, limit }) {
  requireValue(Number.isSafeInteger(after) && after >= 0);
  requireValue(Number.isSafeInteger(limit) && limit >= 1 && limit <= 16);
  const [proof, page] = await db.batch([
    caller.reserve,
    db.prepare(`
      SELECT cursor, message, sender, digest, ciphertext FROM envelopes
      WHERE account = ? AND recipient = ? AND cursor > ? AND ciphertext IS NOT NULL
        AND expires_at > unixepoch() AND ${hasProof}
      ORDER BY cursor LIMIT ?`).bind(caller.account, caller.device, after, caller.attempt, limit)
  ]);
  requireValue(proof.meta.changes === 1, 409);
  const envelopes = page.results.map(row => ({ ...row, ciphertext: encodeHex(row.ciphertext) }));
  return reply({ envelopes, next: envelopes.at(-1)?.cursor ?? null });
}

async function acknowledge(db, caller, { cursor, message, digest }) {
  requireValue(Number.isSafeInteger(cursor) && cursor > 0);
  requireValue(typeof message === "string" && word.test(message));
  requireValue(typeof digest === "string" && word.test(digest));
  const [proof, delivery] = await db.batch([
    caller.reserve,
    db.prepare(`
      UPDATE envelopes SET ciphertext = NULL
      WHERE account = ? AND recipient = ? AND cursor = ? AND message = ? AND digest = ?
        AND expires_at > unixepoch() AND ${hasProof}
      RETURNING cursor`).bind(caller.account, caller.device, cursor, message, digest, caller.attempt)
  ]);
  requireValue(proof.meta.changes === 1, 409);
  requireValue(delivery.results.length === 1, 404);
  return reply(null, 204);
}

async function lookup(db, caller, { device }) {
  requireValue(typeof device === "string" && word.test(device));
  const [proof, found] = await db.batch([
    caller.reserve,
    db.prepare(`
      SELECT peer FROM device_links WHERE account = ? AND device = ? AND state = 'approved'
        AND peer IS NOT NULL AND ${hasProof}`).bind(caller.account, device, caller.attempt)
  ]);
  requireValue(proof.meta.changes === 1, 409);
  requireValue(found.results.length === 1, 404);
  return reply(found.results[0]);
}

const mailboxRoutes = new Map([
  ["/v1/mailbox/deposit", deposit],
  ["/v1/mailbox/fetch", fetchInbox],
  ["/v1/mailbox/ack", acknowledge],
  ["/v1/devices/lookup", lookup]
]);

export default {
  async fetch(request, env) {
    const { DB: db } = env;
    try {
      const { pathname } = new URL(request.url);
      const route = `${request.method} ${pathname}`;
      const web = await webRoute(route, request, env);
      if (web) return web;
      const owner = () => env.WEB_ORIGIN ? authenticateOwner(request, env) : ownerAccount(db, request);
      switch (route) {
        case "GET /healthz": return reply(null, 204);
        case "POST /v1/device-links": return await begin(db, request, env.WEB_ORIGIN);
        case "POST /v1/device-links/status": return await linkStatus(db, request);
        case "POST /api/device-links/claim": return await claim(db, request, await owner());
        case "GET /api/devices": return await listDevices(db, await owner());
        case "POST /api/devices/decide": return await decide(db, request, await owner());
      }
      const mailbox = mailboxRoutes.get(pathname);
      requireValue(request.method === "POST" && mailbox, 404);
      const { raw, parsed } = await jsonBody(request, mailbox === deposit ? envelopeLimit * 2 + 512 : 4096);
      const caller = await deviceRequest(db, request, pathname, raw);
      return await mailbox(db, caller, parsed);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      return reply({ error: status }, status);
    }
  },

  async scheduled(_controller, { DB: db }) {
    await db.batch([
      db.prepare("DELETE FROM web_logins WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM web_sessions WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM envelopes WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM device_proofs WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM device_links WHERE state = 'pending' AND expires_at <= unixepoch()")
    ]);
  }
};
