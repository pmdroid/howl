import { decodeHex, digest, encodeHex, jsonBody, reply, requireValue } from "./http.ts";
import { authorizeNative, checkSignature, joinBytes, word } from "./native-auth.ts";
import { requireMember } from "./native-network.ts";

const hintLength = 164;
const certificateLength = 257;
const hintDomain = new TextEncoder().encode("howl/peer-address/v1\0");
const setDomain = new TextEncoder().encode("howl/peer-routes/v2\0");
const setLimit = 82 + 8 * 19 + 2 + 255 + 64;

function validAddress(bytes: Uint8Array) {
  const ip = bytes.slice(1, 17);
  const v4 =
    bytes[0] === 4 &&
    ip.slice(4).every((value) => value === 0) &&
    ip.slice(0, 4).some((value) => value !== 0) &&
    ip[0] < 224;
  const v6 =
    bytes[0] === 6 &&
    ip.some((value) => value !== 0) &&
    ip[0] !== 0xff &&
    !(ip[0] === 0xfe && (ip[1] & 0xc0) === 0x80) &&
    !(ip.slice(0, 10).every((value) => value === 0) && ip[10] === 255 && ip[11] === 255);
  return (v4 || v6) && (bytes[17] !== 0 || bytes[18] !== 0);
}

function validSet(body: Uint8Array) {
  const count = body[81];
  const relayOffset = 82 + count * 19;
  if (count > 8 || body.length < relayOffset + 2) return false;
  for (let offset = 82; offset < relayOffset; offset += 19) {
    if (!validAddress(body.slice(offset, offset + 19))) return false;
  }
  const relay = body.slice(relayOffset + 2);
  const claimedLength = (body[relayOffset] << 8) | body[relayOffset + 1];
  if (relay.length !== claimedLength || relay.length > 255) return false;
  if (relay.length === 0) return count > 0;
  return (
    relay.every((byte) => byte >= 33 && byte <= 126) &&
    new TextDecoder().decode(relay).startsWith("https://")
  );
}

function routeTable(version: number) {
  return version === 1 ? "control_route_hints" : "control_route_sets";
}

async function publish(env: Env, request: Request, version: number) {
  requireValue(request.body, 400);
  const reader = request.body.getReader();
  const buffer = new Uint8Array(certificateLength + (version === 1 ? hintLength : setLimit));
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.length > buffer.length) {
      await reader.cancel();
      requireValue(false, 413);
    }
    buffer.set(value, size);
    size += value.length;
  }
  requireValue(size >= certificateLength + (version === 1 ? hintLength : 82 + 2 + 64));
  const bytes = buffer.slice(0, size);
  const caller = await authorizeNative(env, request, "discovery-write", bytes);
  const peer = await requireMember(env, caller);
  const cert = bytes.slice(0, certificateLength);
  requireValue(encodeHex(cert) === peer, 401);
  const hint = bytes.slice(certificateLength);
  const view = new DataView(hint.buffer);
  const issued = Number(view.getBigUint64(65));
  const expires = Number(view.getBigUint64(73));
  const now = Date.now();
  requireValue(
    hint[0] === version &&
      encodeHex(hint.slice(1, 33)) === caller.device_id &&
      encodeHex(hint.slice(33, 65)) === (await digest(cert.slice(0, 129))),
  );
  requireValue(
    Number.isSafeInteger(issued) &&
      Number.isSafeInteger(expires) &&
      issued <= now + 120000 &&
      expires > now &&
      expires > issued &&
      expires - issued <= 86400000,
  );
  const body = hint.slice(0, -64);
  requireValue(version === 1 ? validAddress(body.slice(81)) : validSet(body));
  requireValue(
    await checkSignature(
      caller.signing_key,
      joinBytes(version === 1 ? hintDomain : setDomain, body),
      encodeHex(hint.slice(-64)),
    ),
    401,
  );
  const table = routeTable(version);
  const stored = await env.DB.prepare(`
    INSERT INTO ${table} (github_id, device, payload, issued_at, expires_at)
    SELECT github_id, device, ?, ?, ? FROM control_members WHERE github_id = ? AND device = ? AND peer = ?
    ON CONFLICT (github_id, device) DO UPDATE SET
      payload = excluded.payload, issued_at = excluded.issued_at, expires_at = excluded.expires_at
    WHERE ${table}.issued_at < excluded.issued_at OR ${table}.payload = excluded.payload
  `)
    .bind(hint.buffer, issued, expires, caller.github_id, caller.device_id, peer)
    .run();
  requireValue(stored.meta.changes === 1, 401);
  return reply(null, 204);
}

async function lookup(env: Env, request: Request, target: string, version: number) {
  const caller = await authorizeNative(env, request, "discovery-read", decodeHex(target));
  await requireMember(env, caller);
  const row = await env.DB.prepare(`
    SELECT payload FROM ${routeTable(version)} WHERE github_id = ? AND device = ? AND expires_at > ?
  `)
    .bind(caller.github_id, target, Date.now())
    .first<{ payload: number[] }>();
  requireValue(row, 401);
  return new Response(new Uint8Array(row.payload), {
    headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" },
  });
}

async function status(env: Env, request: Request) {
  const { raw, parsed } = await jsonBody<{ device: string; kind: string }[]>(request, 8192, true);
  const caller = await authorizeNative(env, request, "mesh-status", raw);
  await requireMember(env, caller);
  requireValue(
    Array.isArray(parsed) &&
      parsed.length <= 64 &&
      parsed.every(
        (peer) =>
          peer &&
          word.test(peer.device ?? "") &&
          peer.device !== caller.device_id &&
          (peer.kind === "direct" || peer.kind === "relay"),
      ),
  );
  await env.DB.prepare(`
    INSERT INTO control_mesh_status (github_id, device, seen_at, paths) VALUES (?, ?, unixepoch(), ?)
    ON CONFLICT (github_id, device) DO UPDATE SET seen_at = excluded.seen_at, paths = excluded.paths
  `)
    .bind(caller.github_id, caller.device_id, JSON.stringify(parsed))
    .run();
  return reply(null, 204);
}

export async function nativeDiscoveryRoute(route: string, request: Request, env: Env) {
  if (!env.CONTROL_AUDIENCE) return null;
  if (route === "POST /v1/discovery/hints") return publish(env, request, 1);
  if (route === "POST /v2/discovery/hints") return publish(env, request, 2);
  if (route === "POST /v1/discovery/status") return status(env, request);
  const match = /^GET \/v([12])\/discovery\/hints\/([0-9a-f]{64})$/.exec(route);
  if (match) return lookup(env, request, match[2], Number(match[1]));
  return null;
}
