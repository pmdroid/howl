import { decodeHex, digest, encodeHex, jsonBody, reply, requireValue } from "./http.ts";
import { type Session, authorizeNative, checkSignature, joinBytes, word } from "./native-auth.ts";
import { requireMember } from "./native-network.ts";

type Deposit = { recipient: string; ciphertext: string };
type FetchPage = { after: number; limit: number };
type Range = {
  channel: string;
  epoch: number;
  sender: string;
  first: number;
  last: number;
  limit: number;
};
type Ack = { message: string; digest: string };
type Row = { epoch: string; sequence: string; ciphertext: string; cursor: number };

const encoder = new TextEncoder();
const maxFrame = 77112;
const retention = 86400;
const permitted =
  "EXISTS (SELECT 1 FROM control_policy WHERE github_id = ? AND offline_mailbox = 1)";
const operations = new Map([
  ["/v1/mailbox/deposit", "mailbox-deposit"],
  ["/v1/mailbox/fetch", "mailbox-fetch"],
  ["/v1/mailbox/range", "mailbox-range"],
  ["/v1/mailbox/ack", "mailbox-ack"],
]);

const hexField = (bytes: Uint8Array, from: number, to: number) => encodeHex(bytes.slice(from, to));
const u64 = (value: number) => Number.isSafeInteger(value) && value > 0;
const sequenceHex = (value: number) => value.toString(16).padStart(16, "0");

async function accountId(db: Env["DB"], github: number) {
  const authority = await db
    .prepare(
      "SELECT json_extract(snapshot, '$.authority[0]') AS genesis FROM control_networks WHERE github_id = ?",
    )
    .bind(github)
    .first<string>("genesis");
  requireValue(authority && authority.length > 256, 401);
  return digest(decodeHex(authority.slice(0, -256)));
}

async function keyId(role: string, key: string) {
  return digest(joinBytes(encoder.encode("howl/key/v1/" + role + "\0"), decodeHex(key)));
}

async function inspect(db: Env["DB"], caller: Session, { recipient, ciphertext }: Deposit) {
  requireValue(
    typeof recipient === "string" && word.test(recipient) && recipient !== caller.device_id,
  );
  requireValue(
    typeof ciphertext === "string" &&
      ciphertext.length >= 1024 &&
      ciphertext.length <= maxFrame * 2 &&
      ciphertext.length % 2 === 0 &&
      !/[^0-9a-f]/.test(ciphertext),
  );
  const bytes = decodeHex(ciphertext);
  const view = new DataView(bytes.buffer);
  const count = view.getUint16(226);
  requireValue(bytes[0] === 1 && bytes[1] >= 1 && bytes[1] <= 6 && count > 0 && count <= 64);
  const lengthOffset = 228 + count * (96 + 80);
  requireValue(lengthOffset + 4 + 64 <= bytes.length);
  const payload = view.getUint32(lengthOffset);
  requireValue(
    payload >= 272 &&
      payload <= 65552 &&
      (payload - 16) % 256 === 0 &&
      lengthOffset + 4 + payload + 64 === bytes.length,
  );
  const github = caller.github_id;
  const account = await accountId(db, github);
  const peer = await db
    .prepare("SELECT peer FROM control_members WHERE github_id = ? AND device = ?")
    .bind(github, recipient)
    .first<string>("peer");
  requireValue(peer, 401);
  requireValue(
    hexField(bytes, 34, 66) === account &&
      hexField(bytes, 66, 98) === caller.device_id &&
      hexField(bytes, 98, 130) === (await keyId("device-signing", caller.signing_key)),
    401,
  );
  const desired = account + recipient + (await keyId("device-encryption", peer.slice(194, 258)));
  let previous = "";
  let wrapped = false;
  for (let offset = 228; offset < 228 + count * 96; offset += 96) {
    const address = hexField(bytes, offset, offset + 64);
    requireValue(address > previous);
    previous = address;
    if (hexField(bytes, offset, offset + 96) === desired) wrapped = true;
  }
  requireValue(wrapped, 401);
  const signed = joinBytes(encoder.encode("howl/envelope/v1\0"), bytes.slice(0, -64));
  requireValue(await checkSignature(caller.signing_key, signed, encodeHex(bytes.slice(-64))), 401);
  requireValue(view.getBigUint64(130) > 0n && view.getBigUint64(138) > 0n);
  const sent = Number(view.getBigUint64(146));
  const wake = bytes[1] === 2 || bytes[1] === 5;
  const wakeExpiry = Number(view.getBigUint64(154));
  const now = Math.floor(Date.now() / 1000);
  requireValue(Number.isSafeInteger(sent) && sent > 0 && sent <= now + 120);
  requireValue(
    wake
      ? Number.isSafeInteger(wakeExpiry) && wakeExpiry > sent && wakeExpiry - sent <= 300
      : wakeExpiry === 0,
  );
  const expires = wake ? wakeExpiry : sent + retention;
  requireValue(expires > now, 410);
  return {
    recipient,
    bytes,
    account,
    sent,
    expires,
    channel: hexField(bytes, 2, 34),
    epoch: hexField(bytes, 130, 138),
    sequence: hexField(bytes, 138, 146),
    message: hexField(bytes, 162, 194),
    digest: await digest(bytes),
  };
}

async function deposit(db: Env["DB"], caller: Session, parsed: Deposit) {
  const frame = await inspect(db, caller, parsed);
  const github = caller.github_id;
  const { recipient, channel, epoch, sequence, account, message, sent, expires } = frame;
  const [, inserted, , existing] = await db.batch([
    db
      .prepare(`
      INSERT INTO control_mailbox_inboxes (github_id, recipient)
      SELECT ?, ? WHERE ${permitted} ON CONFLICT (github_id, recipient) DO NOTHING
    `)
      .bind(github, recipient, github),
    db
      .prepare(`
      INSERT INTO control_mailbox_envelopes
        (github_id, recipient, cursor, channel, epoch, sender_account, sender_device, sequence, message,
          sent_at, expires_at, digest, ciphertext)
      SELECT github_id, recipient, cursor + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      FROM control_mailbox_inboxes WHERE github_id = ? AND recipient = ? AND ${permitted}
        AND ? > unixepoch()
        AND (SELECT COUNT(*) FROM control_mailbox_envelopes
          WHERE github_id = ? AND recipient = ? AND expires_at > unixepoch()) < 2048
        AND (SELECT COUNT(*) FROM control_mailbox_envelopes
          WHERE github_id = ? AND recipient = ? AND expires_at > unixepoch() AND ciphertext IS NOT NULL) < 256
        AND (SELECT COALESCE(SUM(length(ciphertext)), 0) FROM control_mailbox_envelopes
          WHERE github_id = ? AND recipient = ? AND expires_at > unixepoch()) + ? <= 16777216
      ON CONFLICT DO NOTHING RETURNING cursor
    `)
      .bind(
        channel,
        epoch,
        account,
        caller.device_id,
        sequence,
        message,
        sent,
        expires,
        frame.digest,
        frame.bytes.buffer,
        github,
        recipient,
        github,
        expires,
        github,
        recipient,
        github,
        recipient,
        github,
        recipient,
        frame.bytes.length,
      ),
    db
      .prepare(`
      UPDATE control_mailbox_inboxes SET cursor = MAX(cursor, COALESCE((
        SELECT cursor FROM control_mailbox_envelopes WHERE github_id = ? AND recipient = ? AND message = ?
      ), cursor)) WHERE github_id = ? AND recipient = ? AND ${permitted}
    `)
      .bind(github, recipient, message, github, recipient, github),
    db
      .prepare(`
      SELECT message, digest, sender_device, expires_at > unixepoch() AS active FROM control_mailbox_envelopes
      WHERE github_id = ? AND recipient = ? AND (message = ? OR
        (channel = ? AND epoch = ? AND sender_account = ? AND sender_device = ? AND sequence = ?))
    `)
      .bind(github, recipient, message, channel, epoch, account, caller.device_id, sequence),
  ]);
  if (inserted.results.length === 1) return reply(null, 201);
  const previous = existing.results[0] as
    | { message: string; digest: string; sender_device: string; active: number }
    | undefined;
  requireValue(previous, 429);
  requireValue(previous.active, 410);
  requireValue(
    previous.message === message &&
      previous.digest === frame.digest &&
      previous.sender_device === caller.device_id,
    409,
  );
  return reply(null, 204);
}

const pageColumns =
  "cursor, channel, epoch, sender_account, sender_device, sequence, message, sent_at, digest, hex(ciphertext) AS ciphertext";

function page(rows: Row[], next: number | null, missing?: [number, number][]) {
  const envelopes = rows.map(({ epoch, sequence, ciphertext, ...row }) => {
    const object = JSON.stringify({ ...row, ciphertext: ciphertext.toLowerCase() });
    return (
      object.slice(0, -1) +
      ',"epoch":' +
      BigInt("0x" + epoch) +
      ',"sequence":' +
      BigInt("0x" + sequence) +
      "}"
    );
  });
  const body =
    '{"envelopes":[' +
    envelopes.join(",") +
    '],"next":' +
    (next ?? "null") +
    (missing ? ',"missing":' + JSON.stringify(missing) : "") +
    "}";
  return new Response(body, {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function limit(value: number) {
  requireValue(Number.isSafeInteger(value) && value >= 1 && value <= 16);
  return value;
}

async function fetchPage(db: Env["DB"], caller: Session, { after, limit: count }: FetchPage) {
  requireValue(Number.isSafeInteger(after) && after >= 0);
  const { results } = await db
    .prepare(`
    SELECT ${pageColumns} FROM control_mailbox_envelopes WHERE github_id = ? AND recipient = ?
      AND cursor > ? AND expires_at > unixepoch() AND ciphertext IS NOT NULL ORDER BY cursor LIMIT ?
  `)
    .bind(caller.github_id, caller.device_id, after, limit(count) + 1)
    .all<Row>();
  return page(results.slice(0, count), results.length > count ? results[count - 1].cursor : null);
}

async function range(
  db: Env["DB"],
  caller: Session,
  { channel, epoch, sender, first, last, limit: count }: Range,
) {
  requireValue(
    word.test(channel ?? "") &&
      word.test(sender ?? "") &&
      u64(epoch) &&
      u64(first) &&
      u64(last) &&
      first <= last &&
      last - first < 4096,
  );
  const { results } = await db
    .prepare(`
    SELECT ${pageColumns} FROM control_mailbox_envelopes WHERE github_id = ? AND recipient = ?
      AND channel = ? AND epoch = ? AND sender_device = ? AND sequence BETWEEN ? AND ?
      AND expires_at > unixepoch() AND ciphertext IS NOT NULL ORDER BY sequence LIMIT ?
  `)
    .bind(
      caller.github_id,
      caller.device_id,
      channel,
      sequenceHex(epoch),
      sender,
      sequenceHex(first),
      sequenceHex(last),
      limit(count) + 1,
    )
    .all<Row>();
  const envelopes = results.slice(0, count);
  const next = results.length > count ? Number.parseInt(envelopes[count - 1].sequence, 16) : null;
  const missing: [number, number][] = [];
  let previous = first;
  for (const entry of envelopes) {
    const sequence = Number.parseInt(entry.sequence, 16);
    if (previous < sequence) missing.push([previous, sequence - 1]);
    previous = sequence + 1;
  }
  if (previous <= (next ?? last)) missing.push([previous, next ?? last]);
  return page(envelopes, next, missing);
}

async function ack(db: Env["DB"], caller: Session, { message, digest }: Ack) {
  requireValue(word.test(message ?? "") && word.test(digest ?? ""));
  const acknowledged = await db
    .prepare(`
    UPDATE control_mailbox_envelopes SET ciphertext = NULL WHERE github_id = ? AND recipient = ?
      AND message = ? AND digest = ? AND expires_at > unixepoch()
  `)
    .bind(caller.github_id, caller.device_id, message, digest)
    .run();
  requireValue(acknowledged.meta.changes === 1, 404);
  return reply(null, 204);
}

export async function mailboxSetting(env: Env, request: Request, github: number) {
  const db = env.DB;
  if (request.method === "GET") {
    const enabled = await db
      .prepare("SELECT offline_mailbox FROM control_policy WHERE github_id = ?")
      .bind(github)
      .first("offline_mailbox");
    return reply({ enabled: Boolean(enabled) });
  }
  const {
    parsed: { enabled },
  } = await jsonBody<{ enabled: boolean }>(request);
  requireValue(typeof enabled === "boolean");
  await db
    .prepare(`
    INSERT INTO control_policy (github_id, offline_mailbox) VALUES (?, ?)
    ON CONFLICT (github_id) DO UPDATE SET offline_mailbox = excluded.offline_mailbox
  `)
    .bind(github, Number(enabled))
    .run();
  return reply({ enabled });
}

export async function nativeMailboxRoute(route: string, request: Request, env: Env) {
  if (!env.CONTROL_AUDIENCE || request.method !== "POST") return null;
  const path = route.slice(5);
  const operation = operations.get(path);
  if (!operation) return null;
  const { raw, parsed } = await jsonBody(
    request,
    operation === "mailbox-deposit" ? 2 * maxFrame + 512 : 4096,
  );
  const caller = await authorizeNative(env, request, operation, raw);
  await requireMember(env, caller);
  const enabled = await env.DB.prepare(
    "SELECT offline_mailbox FROM control_policy WHERE github_id = ?",
  )
    .bind(caller.github_id)
    .first("offline_mailbox");
  requireValue(enabled, 403);
  switch (operation) {
    case "mailbox-deposit":
      return deposit(env.DB, caller, parsed as Deposit);
    case "mailbox-fetch":
      return fetchPage(env.DB, caller, parsed as FetchPage);
    case "mailbox-range":
      return range(env.DB, caller, parsed as Range);
    case "mailbox-ack":
      return ack(env.DB, caller, parsed as Ack);
  }
}
