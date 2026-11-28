import { decodeHex, digest, encodeHex, jsonBody, reply, requireValue } from "./http.ts";
import { authorizeNative, checkSignature, joinBytes, word } from "./native-auth.ts";
import { requireMember } from "./native-network.ts";

const hintLength = 164;
const certificateLength = 257;
const hintDomain = new TextEncoder().encode("howl/peer-address/v1\0");

async function publish(env: Env, request: Request) {
  requireValue(request.body, 400);
  const reader = request.body.getReader();
  const bytes = new Uint8Array(certificateLength + hintLength);
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.length > bytes.length) {
      await reader.cancel();
      requireValue(false, 413);
    }
    bytes.set(value, size);
    size += value.length;
  }
  requireValue(size === bytes.length);
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
    hint[0] === 1 &&
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
  const ip = hint.slice(82, 98);
  const v4 =
    hint[81] === 4 &&
    ip.slice(4).every((value) => value === 0) &&
    ip.slice(0, 4).some((value) => value !== 0) &&
    ip[0] < 224;
  const v6 =
    hint[81] === 6 &&
    ip.some((value) => value !== 0) &&
    ip[0] !== 0xff &&
    !(ip[0] === 0xfe && (ip[1] & 0xc0) === 0x80) &&
    !(ip.slice(0, 10).every((value) => value === 0) && ip[10] === 255 && ip[11] === 255);
  requireValue((v4 || v6) && view.getUint16(98) > 0);
  requireValue(
    await checkSignature(
      caller.signing_key,
      joinBytes(hintDomain, hint.slice(0, 100)),
      encodeHex(hint.slice(100)),
    ),
    401,
  );
  const stored = await env.DB.prepare(`
    INSERT INTO control_route_hints (github_id, device, payload, issued_at, expires_at)
    SELECT github_id, device, ?, ?, ? FROM control_members WHERE github_id = ? AND device = ? AND peer = ?
    ON CONFLICT (github_id, device) DO UPDATE SET
      payload = excluded.payload, issued_at = excluded.issued_at, expires_at = excluded.expires_at
    WHERE control_route_hints.issued_at < excluded.issued_at OR control_route_hints.payload = excluded.payload
  `)
    .bind(hint.buffer, issued, expires, caller.github_id, caller.device_id, peer)
    .run();
  requireValue(stored.meta.changes === 1, 401);
  return reply(null, 204);
}

async function lookup(env: Env, request: Request, target: string) {
  const caller = await authorizeNative(env, request, "discovery-read", decodeHex(target));
  await requireMember(env, caller);
  const row = await env.DB.prepare(`
    SELECT payload FROM control_route_hints WHERE github_id = ? AND device = ? AND expires_at > ?
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
  if (route === "POST /v1/discovery/hints") return publish(env, request);
  if (route === "POST /v1/discovery/status") return status(env, request);
  const match = /^GET \/v1\/discovery\/hints\/([0-9a-f]{64})$/.exec(route);
  if (match) return lookup(env, request, match[1]);
  return null;
}
