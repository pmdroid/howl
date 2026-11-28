import devicePage from "./web/devices.html";
import detailsPage from "./web/device-details.html";
import styles from "./web/devices.css";
import deviceScript from "./.build/ui/devices.txt";
import detailsScript from "./.build/ui/device-details.txt";
import { decodeHex, digest, jsonBody, reply, requireValue } from "./http.ts";
import { decodeDiscovery, type MeshPath } from "./native-discovery.ts";
import { ownerGitHub } from "./native-network.ts";

const assets = new Map<string, [string, string]>([
  ["/", ["text/html", devicePage]],
  ["/devices", ["text/html", devicePage]],
  ["/link", ["text/html", devicePage]],
  ["/assets/devices.css", ["text/css", styles]],
  ["/assets/devices.js", ["text/javascript", deviceScript]],
  ["/assets/device-details.js", ["text/javascript", detailsScript]],
]);

export function pageRoute(path: string) {
  const asset =
    assets.get(path) ??
    (/^\/devices\/[0-9a-f]{64}$/.test(path) ? ["text/html", detailsPage] : null);
  if (!asset) return null;
  return new Response(asset[1], {
    headers: {
      "Content-Type": asset[0] + "; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

type DeviceRow = {
  device: string;
  peer: string;
  name: string;
  fingerprint?: string;
  state: "approved" | "denied" | "pending";
  requested_at: number | null;
  approved_at: number | null;
};
type RouteRow = { payload: number[]; issued_at: number; expires_at: number };

function timestamp(seconds: number | null | undefined) {
  return seconds == null ? undefined : new Date(seconds * 1000).toISOString();
}

export async function accountDevices(env: Env, account: string) {
  const github = await ownerGitHub(env, account);
  const network = await env.DB.prepare("SELECT channel FROM control_networks WHERE github_id = ?")
    .bind(github)
    .first<string>("channel");
  const { results: links } = await env.DB.prepare(`
    SELECT device, name, fingerprint, state FROM device_links
    WHERE native_account = ? AND (state = 'denied' OR expires_at > unixepoch())
    ORDER BY expires_at, id`)
    .bind(account)
    .all<DeviceRow>();
  const { results: members } = await env.DB.prepare(`
    SELECT device, peer, name, 'approved' AS state FROM control_members WHERE github_id = ? ORDER BY name, device
  `)
    .bind(github)
    .all<DeviceRow>();
  const entries = new Map(links.map((row) => [row.device, row]));
  for (const member of members) entries.set(member.device, member);
  const devices = await Promise.all(
    [...entries.values()].map(async (entry) => ({
      id: entry.device,
      name: entry.name,
      state: entry.state,
      fingerprint: entry.fingerprint ?? (await digest(decodeHex(entry.peer.slice(0, 258)))),
    })),
  );
  const enabled = await env.DB.prepare(
    "SELECT offline_mailbox FROM control_policy WHERE github_id = ?",
  )
    .bind(github)
    .first<number>("offline_mailbox");
  return reply({
    network,
    account_managed: true,
    pending: devices.filter((row) => row.state === "pending"),
    approved: devices.filter((row) => row.state === "approved"),
    offline_mailbox: Boolean(enabled),
  });
}

async function details(env: Env, account: string, device: string) {
  const github = await ownerGitHub(env, account);
  const [member, link, profile, hint, routeSet, status] = await Promise.all([
    env.DB.prepare(
      "SELECT *, 'approved' AS state FROM control_members WHERE github_id = ? AND device = ?",
    )
      .bind(github, device)
      .first<DeviceRow>(),
    env.DB.prepare(`
      SELECT device, name, peer, state, requested_at, approved_at FROM device_links
      WHERE native_account = ? AND device = ? AND (expires_at > unixepoch() OR state = 'denied')
      ORDER BY expires_at DESC, id LIMIT 1
    `)
      .bind(account, device)
      .first<DeviceRow>(),
    env.DB.prepare(`
      SELECT n.channel, o.github_login FROM control_networks n JOIN owners o USING (github_id) WHERE n.github_id = ?
    `)
      .bind(github)
      .first<{ channel: string; github_login: string | null }>(),
    env.DB.prepare(
      "SELECT payload, issued_at, expires_at FROM control_route_hints WHERE github_id = ? AND device = ?",
    )
      .bind(github, device)
      .first<RouteRow>(),
    env.DB.prepare(
      "SELECT payload, issued_at, expires_at FROM control_route_sets WHERE github_id = ? AND device = ?",
    )
      .bind(github, device)
      .first<RouteRow>(),
    env.DB.prepare(
      "SELECT seen_at, paths, home_relay FROM control_mesh_status WHERE github_id = ? AND device = ?",
    )
      .bind(github, device)
      .first<{ seen_at: number; paths: string; home_relay: string | null }>(),
  ]);
  const row = member ?? link;
  requireValue(row && profile, 404);
  const now = Date.now();
  const online = status ? now < (status.seen_at + 35) * 1000 : undefined;
  const paths: MeshPath[] = online && status ? JSON.parse(status.paths) : [];
  const { results: peers } = await env.DB.prepare(
    "SELECT device, name FROM control_members WHERE github_id = ?",
  )
    .bind(github)
    .all<{ device: string; name: string }>();
  const names = new Map(peers.map((peer) => [peer.device, peer.name]));
  const connections = paths
    .filter((path) => names.has(path.device))
    .map((path) => ({
      ...path,
      name: names.get(path.device),
    }));
  const legacyDiscovery = hint && hint.expires_at > now ? decodeDiscovery(hint.payload) : undefined;
  const route = legacyDiscovery?.addresses[0];
  const discovery =
    routeSet && routeSet.expires_at > now ? decodeDiscovery(routeSet.payload) : undefined;
  const current = discovery ? routeSet : legacyDiscovery ? hint : null;
  const last = current ?? routeSet ?? hint;
  return {
    id: device,
    fingerprint: await digest(decodeHex(row.peer.slice(0, 258))),
    name: row.name,
    state: row.state,
    network_id: profile.channel,
    network_name: profile.github_login,
    endpoint_id: row.peer.slice(130, 194),
    requested_at: timestamp(row.requested_at ?? link?.requested_at),
    approved_at: timestamp(row.approved_at ?? link?.approved_at),
    online,
    last_seen_at: timestamp(status?.seen_at),
    home_relay: online ? (status?.home_relay ?? undefined) : undefined,
    connections,
    last_route_at: timestamp(last && last.issued_at / 1000),
    route: route && hint ? { ...route, expires_at: timestamp(hint.expires_at / 1000) } : undefined,
    discovery: current
      ? { ...(discovery ?? legacyDiscovery), expires_at: timestamp(current.expires_at / 1000) }
      : undefined,
  };
}

export async function deviceDetails(
  env: Env,
  account: string,
  device: string,
  rename: boolean,
  request: Request,
) {
  const before = await details(env, account, device);
  if (!rename) return reply(before);
  const {
    parsed: { name, fingerprint },
  } = await jsonBody<{ name: string; fingerprint: string }>(request);
  requireValue(
    typeof name === "string" &&
      name.trim().length > 0 &&
      Array.from(name.trim()).length <= 80 &&
      !/\p{Cc}/u.test(name),
  );
  requireValue(before.fingerprint === fingerprint, 404);
  const github = await ownerGitHub(env, account);
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE control_members SET name = ? WHERE github_id = ? AND device = ? AND substr(peer, 1, 258) IS NOT NULL",
    ).bind(name.trim(), github, device),
    env.DB.prepare(
      "UPDATE device_links SET name = ? WHERE native_account = ? AND device = ? AND fingerprint = ?",
    ).bind(name.trim(), account, device, fingerprint),
  ]);
  return reply(await details(env, account, device));
}
