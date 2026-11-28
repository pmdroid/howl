import { decodeHex, digest, randomId, reply, requireValue } from "./http.mjs";
import { dashboard } from "./dashboard.mjs";

const loginCookie = "__Host-howl-login";
const sessionCookie = "__Host-howl-owner";
const callbackPath = "/login/github/callback";
const word = /^[0-9a-f]{64}$/;

function cookie(request, name) {
  const values = (request.headers.get("Cookie") ?? "").split(";")
    .map(item => item.trim().split("="))
    .filter(([key]) => key === name);
  return values.length === 1 && word.test(values[0][1]) ? values[0][1] : null;
}

function redirect(location, cookies = []) {
  const headers = new Headers({ Location: location, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
  for (const [name, value, age, policy] of cookies) {
    headers.append("Set-Cookie", `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${policy}; Max-Age=${age}`);
  }
  return new Response(null, { status: 303, headers });
}

export async function authenticateOwner(request, env) {
  if (request.method !== "GET") requireValue(request.headers.get("Origin") === env.WEB_ORIGIN, 403);
  const token = cookie(request, sessionCookie);
  requireValue(token, 401);
  const account = await env.DB.prepare("SELECT account FROM web_sessions WHERE token_digest = ? AND expires_at > unixepoch()")
    .bind(await digest(token)).first("account");
  requireValue(account, 401);
  return account;
}

async function beginLogin(env) {
  const { DB: db, WEB_ORIGIN: origin, GITHUB_CLIENT_ID: clientId } = env;
  requireValue(clientId && env.GITHUB_CLIENT_SECRET && env.GITHUB_OWNER_ID, 503);
  const state = randomId();
  const verifier = randomId();
  const hash = await digest(verifier);
  const challenge = btoa(String.fromCharCode(...decodeHex(hash))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  const stored = await db.prepare(`
    INSERT INTO web_logins (state_digest, verifier_digest, expires_at)
    SELECT ?, ?, unixepoch() + 600 WHERE (SELECT COUNT(*) FROM web_logins WHERE expires_at > unixepoch()) < 4096`)
    .bind(await digest(state), hash).run();
  requireValue(stored.meta.changes === 1, 429);
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: origin + callbackPath,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
    scope: ""
  });
  return redirect("https://github.com/login/oauth/authorize?" + query, [[loginCookie, verifier, 600, "Lax"]]);
}

async function finishLogin(request, env) {
  const { DB: db, WEB_ORIGIN: origin, GITHUB_CLIENT_ID: clientId, GITHUB_CLIENT_SECRET: secret } = env;
  const { searchParams } = new URL(request.url);
  const state = searchParams.get("state");
  const code = searchParams.get("code");
  const verifier = cookie(request, loginCookie);
  requireValue(word.test(state ?? "") && verifier, 401);
  const consumed = await db.prepare(`
    DELETE FROM web_logins WHERE state_digest = ? AND verifier_digest = ? AND expires_at > unixepoch()`)
    .bind(await digest(state), await digest(verifier)).run();
  requireValue(consumed.meta.changes === 1, 401);
  const clearLogin = [loginCookie, "", 0, "Lax"];
  if (!code || code.length > 256) return redirect("/", [clearLogin]);

  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    redirect: "manual",
    headers: { Accept: "application/json" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: secret,
      code,
      code_verifier: verifier,
      redirect_uri: origin + callbackPath
    })
  });
  requireValue(tokenResponse.ok, 502);
  const { access_token: accessToken } = await tokenResponse.json();
  requireValue(typeof accessToken === "string" && accessToken.length <= 512 && accessToken.length > 0, 401);
  const apiHeaders = { Accept: "application/vnd.github+json", "User-Agent": "Howl-Control-Plane", "X-GitHub-Api-Version": "2026-03-10" };
  let id;
  try {
    const userResponse = await fetch("https://api.github.com/user", {
      redirect: "manual",
      headers: { ...apiHeaders, Authorization: "Bearer " + accessToken }
    });
    requireValue(userResponse.ok, 502);
    ({ id } = await userResponse.json());
  } finally {
    const revoked = await fetch("https://api.github.com/applications/" + encodeURIComponent(clientId) + "/token", {
      method: "DELETE",
      redirect: "manual",
      headers: { ...apiHeaders, Authorization: "Basic " + btoa(clientId + ":" + secret), "Content-Type": "application/json" },
      body: JSON.stringify({ access_token: accessToken })
    });
    requireValue(revoked.status === 204, 502);
  }
  requireValue(Number.isSafeInteger(id) && String(id) === env.GITHUB_OWNER_ID, 403);
  const account = await digest(JSON.stringify(["howl-d1-github-account-v1", id]));
  const token = randomId();
  const previous = cookie(request, sessionCookie);
  await db.batch([
    db.prepare("INSERT INTO owners (account, token_digest) VALUES (?, ?) ON CONFLICT (account) DO NOTHING")
      .bind(account, await digest(randomId())),
    db.prepare("DELETE FROM web_sessions WHERE token_digest = ?").bind(previous ? await digest(previous) : null),
    db.prepare("INSERT INTO web_sessions (token_digest, account, expires_at) VALUES (?, ?, unixepoch() + 43200)")
      .bind(await digest(token), account)
  ]);
  return redirect("/", [clearLogin, [sessionCookie, token, 43200, "Strict"]]);
}

export async function webRoute(route, request, env) {
  if (!env.WEB_ORIGIN) return null;
  requireValue(new URL(request.url).origin === env.WEB_ORIGIN, 404);
  switch (route) {
    case "GET /":
    case "GET /link":
      return dashboard(randomId());
    case "GET /login/github":
      return beginLogin(env);
    case "GET /login/github/callback":
      return finishLogin(request, env);
    case "GET /api/session":
      return reply({ account: await authenticateOwner(request, env) });
    case "POST /logout":
      await authenticateOwner(request, env);
      await env.DB.prepare("DELETE FROM web_sessions WHERE token_digest = ?")
        .bind(await digest(cookie(request, sessionCookie))).run();
      return redirect("/", [[sessionCookie, "", 0, "Strict"]]);
    default:
      return null;
  }
}
