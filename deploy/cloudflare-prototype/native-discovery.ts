import { decodeHex, digest, encodeHex, jsonBody, reply, requireValue } from "./http.ts";
import { authorizeNative, checkSignature, joinBytes, word } from "./native-auth.ts";
import { requireMember } from "./native-network.ts";

const hintLength = 164;
const certificateLength = 257;
const hintDomain = new TextEncoder().encode("howl/peer-address/v1\0");
const setDomain = new TextEncoder().encode("howl/peer-routes/v2\0");
const setLimit = 82 + 8 * 19 + 2 + 255 + 64;

export type MeshPath = {
  device: string;
  kind: "direct" | "relay";
  direct_rtt_us?: number;
  relay_rtt_us?: number;
  relay?: string;
};

function relayUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 255) return false;
  const parsed = URL.parse(value);
  return parsed?.protocol === "https:" && parsed.href === value;
}

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

function readSet(body: Uint8Array): { addresses: Uint8Array[]; relay?: string } | undefined {
  if (body.length < 84) return;
  const count = body[81];
  const relayOffset = 82 + count * 19;
  if (count > 8 || body.length < relayOffset + 2) return;
  const addresses = [];
  for (let offset = 82; offset < relayOffset; offset += 19) {
    const address = body.subarray(offset, offset + 19);
    if (!validAddress(address)) return;
    addresses.push(address);
  }
  const relay = body.subarray(relayOffset + 2);
  const claimedLength = (body[relayOffset] << 8) | body[relayOffset + 1];
  if (relay.length !== claimedLength || relay.length > 255) return;
  if (relay.length === 0) return count > 0 ? { addresses } : undefined;
  if (!relay.every((byte) => byte >= 33 && byte <= 126)) return;
  const address = new TextDecoder().decode(relay);
  if (relayUrl(address)) return { addresses, relay: address };
}

function decodeAddress(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const port = view.getUint16(17);
  if (bytes[0] === 4) return { ip: bytes.subarray(1, 5).join("."), port };
  const words = Array.from({ length: 8 }, (_, i) => view.getUint16(1 + 2 * i).toString(16));
  const ip = new URL(`http://[${words.join(":")}]/`).hostname.slice(1, -1);
  return { ip, port };
}

export function decodeDiscovery(payload: number[]) {
  const body = Uint8Array.from(payload).subarray(0, -64);
  if (payload[0] === 1 && payload.length === hintLength && validAddress(body.subarray(81))) {
    return { addresses: [decodeAddress(body.subarray(81))] };
  }
  if (payload[0] === 2 && payload.length <= setLimit) {
    const set = readSet(body);
    if (set) return { addresses: set.addresses.map(decodeAddress), relay: set.relay };
  }
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
  requireValue(version === 1 ? validAddress(body.slice(81)) : readSet(body));
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

function validRtt(value: number | undefined) {
  return value === undefined || (Number.isInteger(value) && value >= 1 && value <= 0xffffffff);
}

async function status(env: Env, request: Request, legacy: boolean) {
  const { raw, parsed } = await jsonBody<
    MeshPath[] | { paths: MeshPath[]; home_relay?: string | null }
  >(request, legacy ? 8192 : 32768, legacy);
  const caller = await authorizeNative(env, request, "mesh-status", raw);
  await requireMember(env, caller);
  const paths = Array.isArray(parsed) ? parsed : parsed.paths;
  const homeRelay = Array.isArray(parsed) ? undefined : (parsed.home_relay ?? undefined);
  requireValue(
    (homeRelay === undefined || relayUrl(homeRelay)) &&
      Array.isArray(paths) &&
      paths.length <= 64 &&
      paths.every(
        (peer) =>
          peer &&
          typeof peer.device === "string" &&
          word.test(peer.device) &&
          peer.device !== caller.device_id &&
          (peer.kind === "direct" || peer.kind === "relay") &&
          validRtt(peer.direct_rtt_us) &&
          validRtt(peer.relay_rtt_us) &&
          (peer.relay === undefined || relayUrl(peer.relay)),
      ),
  );
  const report = paths.map(({ device, kind, direct_rtt_us, relay_rtt_us, relay }) => ({
    device,
    kind,
    direct_rtt_us,
    relay_rtt_us,
    relay,
  }));
  await env.DB.prepare(`
    INSERT INTO control_mesh_status (github_id, device, seen_at, paths, home_relay) VALUES (?, ?, unixepoch(), ?, ?)
    ON CONFLICT (github_id, device) DO UPDATE SET
      seen_at = excluded.seen_at, paths = excluded.paths, home_relay = excluded.home_relay
  `)
    .bind(caller.github_id, caller.device_id, JSON.stringify(report), homeRelay ?? null)
    .run();
  return reply(null, 204);
}

export async function nativeDiscoveryRoute(route: string, request: Request, env: Env) {
  if (!env.CONTROL_AUDIENCE) return null;
  if (route === "POST /v1/discovery/hints") return publish(env, request, 1);
  if (route === "POST /v2/discovery/hints") return publish(env, request, 2);
  if (route === "POST /v1/discovery/status") return status(env, request, true);
  if (route === "POST /v2/discovery/status") return status(env, request, false);
  const match = /^GET \/v([12])\/discovery\/hints\/([0-9a-f]{64})$/.exec(route);
  if (match) return lookup(env, request, match[2], Number(match[1]));
  return null;
}
