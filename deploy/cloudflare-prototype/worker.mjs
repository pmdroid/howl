const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const envelopeLimit = 77112;
const mailboxLifetime = 86400;
const word = /^[0-9a-f]{64}$/;
const signature = /^[0-9a-f]{128}$/;
const hasProof = "EXISTS (SELECT 1 FROM device_proofs WHERE attempt = ?)";
const hex = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, "0"));

class HttpError extends Error {
  constructor(status) {
    super(String(status));
    this.status = status;
  }
}

function requireValue(valid, status = 400) {
  if (!valid) throw new HttpError(status);
}

function encodeHex(bytes) {
  let encoded = "";
  for (const byte of bytes) encoded += hex[byte];
  return encoded;
}

function decodeHex(encoded) {
  const bytes = new Uint8Array(encoded.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(encoded.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function randomId() {
  return encodeHex(crypto.getRandomValues(new Uint8Array(32)));
}

async function digest(value) {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  return encodeHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

async function jsonBody(request, limit = 4096) {
  requireValue(request.body, 400);
  const reader = request.body.getReader();
  const bytes = new Uint8Array(limit);
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (length + value.length > limit) {
      await reader.cancel();
      throw new HttpError(413);
    }
    bytes.set(value, length);
    length += value.length;
  }
  const raw = bytes.subarray(0, length);
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(raw));
  } catch {
    throw new HttpError(400);
  }
  requireValue(parsed && typeof parsed === "object" && !Array.isArray(parsed));
  return { parsed, raw };
}

function reply(value, status = 200) {
  const headers = { "Cache-Control": "no-store" };
  return status === 204
    ? new Response(null, { status, headers })
    : Response.json(value, { status, headers });
}

async function ownerAccount(db, request) {
  const token = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.get("Authorization") ?? "")?.[1];
  requireValue(token, 401);
  const account = await db.prepare("SELECT account FROM owners WHERE token_digest = ?")
    .bind(await digest(token)).first("account");
  requireValue(account, 401);
  return account;
}

async function begin(db, request) {
  const { parsed: { public_key, name } } = await jsonBody(request);
  requireValue(typeof public_key === "string" && word.test(public_key) && /[1-9a-f]/.test(public_key));
  requireValue(typeof name === "string" && name.trim().length > 0 && Array.from(name.trim()).length <= 80 && !/\p{Cc}/u.test(name));
  const id = randomId();
  const secret = randomId();
  const fingerprint = await digest(decodeHex(public_key));
  const device = await digest(JSON.stringify(["howl-d1-device-v1", public_key]));
  await db.prepare(`
    INSERT INTO device_links (id, secret_digest, device, public_key, fingerprint, name, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, unixepoch() + 600)`)
    .bind(id, await digest(secret), device, public_key, fingerprint, name.trim()).run();
  return reply({ id, secret, device, fingerprint }, 201);
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
  const publicKey = await crypto.subtle.importKey("raw", decodeHex(key), "Ed25519", false, ["verify"]);
  requireValue(await crypto.subtle.verify("Ed25519", publicKey, decodeHex(proof), message), 401);
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

const mailboxRoutes = new Map([
  ["/v1/mailbox/deposit", deposit],
  ["/v1/mailbox/fetch", fetchInbox],
  ["/v1/mailbox/ack", acknowledge]
]);

export default {
  async fetch(request, { DB: db }) {
    try {
      const { pathname } = new URL(request.url);
      const route = `${request.method} ${pathname}`;
      switch (route) {
        case "GET /healthz": return reply(null, 204);
        case "POST /v1/device-links": return await begin(db, request);
        case "POST /api/device-links/claim": return await claim(db, request, await ownerAccount(db, request));
        case "GET /api/devices": return await listDevices(db, await ownerAccount(db, request));
        case "POST /api/devices/decide": return await decide(db, request, await ownerAccount(db, request));
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
      db.prepare("DELETE FROM envelopes WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM device_proofs WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM device_links WHERE state = 'pending' AND expires_at <= unixepoch()")
    ]);
  }
};
