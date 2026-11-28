import { HttpError, digest, jsonBody, randomId, reply, requireValue } from "./http.ts";
import { authenticateOwner, webRoute } from "./web.ts";
import { nativeAuthRoute, word } from "./native-auth.ts";
import { nativeDiscoveryRoute } from "./native-discovery.ts";
import { mailboxSetting, nativeMailboxRoute } from "./native-mailbox.ts";
import { nativeNetworkRoute, ownerGitHub, peerIdentity } from "./native-network.ts";
import { accountDevices, deviceDetails } from "./account-ui.ts";

async function begin(env: Env, request: Request) {
  const {
    parsed: { name = "Howl device", peer },
  } = await jsonBody<{ name?: string; peer: string }>(request);
  requireValue(
    typeof name === "string" &&
      name.trim().length > 0 &&
      Array.from(name.trim()).length <= 80 &&
      !/\p{Cc}/u.test(name),
  );
  const { key, device, fingerprint } = await peerIdentity(peer);
  const id = randomId();
  const secret = randomId();
  const nonce = randomId();
  const created = await env.DB.prepare(`
    INSERT INTO device_links (id, secret_digest, device, public_key, fingerprint, name, peer, native_nonce, expires_at, requested_at)
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, unixepoch() + 600, unixepoch()
    WHERE (SELECT COUNT(*) FROM device_links WHERE native_account IS NULL AND expires_at > unixepoch()) < 4096
  `)
    .bind(id, await digest(secret), device, key, fingerprint, name.trim(), peer, nonce)
    .run();
  requireValue(created.meta.changes === 1, 429);
  return reply({ id, secret, nonce, expires_in: 600 }, 201);
}

async function claim(env: Env, request: Request, account: string) {
  const {
    parsed: { secret },
  } = await jsonBody<{ secret: string }>(request);
  requireValue(typeof secret === "string" && word.test(secret));
  const github = await ownerGitHub(env, account);
  const link = await env.DB.prepare(`
    UPDATE device_links AS link SET native_account = ?, state = CASE
      WHEN EXISTS (SELECT 1 FROM control_members WHERE github_id = ? AND device = link.device AND peer = link.peer)
        THEN 'approved'
      WHEN EXISTS (SELECT 1 FROM device_links AS denied
        WHERE denied.native_account = ? AND denied.device = link.device AND denied.state = 'denied')
        THEN 'denied'
      ELSE state END
    WHERE secret_digest = ? AND expires_at > unixepoch() AND native_nonce IS NOT NULL
      AND (native_account IS NULL OR native_account = ?)
    RETURNING device, name, fingerprint, state
  `)
    .bind(account, github, account, await digest(secret), account)
    .first();
  requireValue(link, 404);
  const network = await env.DB.prepare("SELECT channel FROM control_networks WHERE github_id = ?")
    .bind(github)
    .first("channel");
  return reply({ ...link, network });
}

async function decide(env: Env, request: Request, account: string, fixed?: "approve" | "deny") {
  const {
    parsed: { device, fingerprint, decision = fixed, secret },
  } = await jsonBody<{
    device: string;
    fingerprint: string;
    decision?: string;
    secret?: string;
  }>(request);
  requireValue(typeof device === "string" && word.test(device));
  requireValue(typeof fingerprint === "string" && word.test(fingerprint));
  requireValue(decision === "approve" || decision === "deny");
  if (!fixed) requireValue(typeof secret === "string" && word.test(secret));
  const secretDigest = secret ? await digest(secret) : null;
  const state = decision === "approve" ? "approved" : "denied";
  const result = await env.DB.prepare(`
    UPDATE device_links SET state = ?, approved_at = CASE WHEN ? = 'approved' THEN unixepoch() END
    WHERE native_account = ? AND device = ? AND fingerprint = ? AND state = 'pending'
      AND expires_at > unixepoch() AND (? IS NULL OR secret_digest = ?)
    RETURNING state
  `)
    .bind(state, state, account, device, fingerprint, secretDigest, secretDigest)
    .first();
  if (result) return reply(result);
  const existing = await env.DB.prepare(`
    SELECT state FROM device_links WHERE native_account = ? AND device = ? AND fingerprint = ?
      AND (state = 'denied' OR expires_at > unixepoch()) AND (? IS NULL OR secret_digest = ?)
    ORDER BY expires_at DESC LIMIT 1
  `)
    .bind(account, device, fingerprint, secretDigest, secretDigest)
    .first<{ state: string }>();
  requireValue(existing, 404);
  requireValue(existing.state === state, 409);
  return reply(existing);
}

export default {
  async fetch(request: Request, env: Env) {
    try {
      const { pathname } = new URL(request.url);
      const route = `${request.method} ${pathname}`;
      const web = await webRoute(route, request, env);
      if (web) return web;
      const native =
        (await nativeAuthRoute(route, request, env)) ??
        (await nativeNetworkRoute(route, request, env)) ??
        (await nativeDiscoveryRoute(route, request, env)) ??
        (await nativeMailboxRoute(route, request, env));
      if (native) return native;
      const owner = () => authenticateOwner(request, env);
      const details = /^(GET|POST) \/api\/devices\/([0-9a-f]{64})(\/name)?$/.exec(route);
      if (details && (request.method === "POST") === Boolean(details[3])) {
        return await deviceDetails(env, await owner(), details[2], Boolean(details[3]), request);
      }
      switch (route) {
        case "GET /healthz":
          return reply(null, 204);
        case "POST /v1/device-links":
          return await begin(env, request);
        case "POST /api/device-links/view":
          return await claim(env, request, await owner());
        case "GET /api/devices":
          return await accountDevices(env, await owner());
        case "POST /api/devices/approve":
          return await decide(env, request, await owner(), "approve");
        case "POST /api/devices/deny":
          return await decide(env, request, await owner(), "deny");
        case "POST /api/device-links/decide":
          return await decide(env, request, await owner());
        case "GET /api/mailbox/settings":
        case "POST /api/mailbox/settings":
          return await mailboxSetting(env, request, await ownerGitHub(env, await owner()));
        default:
          return reply({ error: 404 }, 404);
      }
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      return reply({ error: status }, status);
    }
  },

  async scheduled(_controller: unknown, { DB: db }: Env) {
    await db.batch([
      db.prepare("DELETE FROM web_logins WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM web_sessions WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM control_challenges WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM control_tokens WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM control_sessions WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM control_mailbox_envelopes WHERE expires_at <= unixepoch()"),
      db.prepare("DELETE FROM device_links WHERE state != 'denied' AND expires_at <= unixepoch()"),
    ]);
  },
};
