import { decodeHex, digest, jsonBody, randomId, reply, requireValue } from "./http.ts";

export type Session = { id: string; github_id: number; device_id: string; signing_key: string };
type TokenSession = Session & { tokenDigest: string };
type Proof = { nonce: string; signature: string };

const encoder = new TextEncoder();
export const word = /^[0-9a-f]{64}$/;
const signature = /^[0-9a-f]{128}$/;
const operations = new Set([
  "session",
  "refresh",
  "revoke",
  "network-read",
  "network-register",
  "network-approve",
  "network-deny",
  "network-transfer",
  "discovery-read",
  "discovery-write",
  "mesh-status",
  "mailbox-deposit",
  "mailbox-fetch",
  "mailbox-ack",
  "mailbox-range",
  "enrollment-read",
  "enrollment-write",
]);

export function joinBytes(...fields: Uint8Array[]) {
  const bytes = new Uint8Array(fields.reduce((size, field) => size + field.length, 0));
  let offset = 0;
  for (const field of fields) {
    bytes.set(field, offset);
    offset += field.length;
  }
  return bytes;
}

export async function checkSignature(key: string, signed: Uint8Array<ArrayBuffer>, proof: string) {
  if (!word.test(key) || !signature.test(proof)) return false;
  const publicKey = await crypto.subtle.importKey("raw", decodeHex(key), "Ed25519", false, [
    "verify",
  ]);
  return crypto.subtle.verify("Ed25519", publicKey, decodeHex(proof), signed);
}

export async function proofBytes(
  audience: string,
  subject: string,
  operation: string,
  nonce: string,
  token: string | null,
  raw: Uint8Array<ArrayBuffer>,
) {
  return joinBytes(
    encoder.encode("howl/control-proof/v1\0"),
    decodeHex(audience),
    decodeHex(subject),
    decodeHex(await digest(operation)),
    decodeHex(nonce),
    token ? decodeHex(token) : new Uint8Array(32),
    decodeHex(await digest(raw)),
  );
}

function describe(session: Session) {
  const { id, github_id, device_id, signing_key } = session;
  return { id, github_id, device_id, signing_key };
}

async function credential(
  db: Env["DB"],
  request: Request,
  refresh: boolean,
): Promise<TokenSession> {
  const token = /^Bearer ([0-9a-f]{64})$/.exec(request.headers.get("Authorization") ?? "")?.[1];
  requireValue(token, 401);
  const tokenDigest = await digest(decodeHex(token));
  const row = await db
    .prepare(`
    SELECT session.*, token.rotation
    FROM control_tokens AS token JOIN control_sessions AS session ON session.id = token.session_id
    WHERE token.digest = ? AND token.refresh = ? AND token.expires_at > unixepoch()
      AND session.expires_at > unixepoch() AND session.revoked = 0`)
    .bind(tokenDigest, Number(refresh))
    .first<Session>();
  requireValue(row, 401);
  return { ...row, tokenDigest };
}

export function protect(env: Env) {
  requireValue(word.test(env.CONTROL_AUDIENCE ?? "") && !/^0+$/.test(env.CONTROL_AUDIENCE), 503);
}

export async function authorizeNative(
  env: Env,
  request: Request,
  operation: string,
  raw = new Uint8Array(),
  proof?: Proof,
) {
  protect(env);
  const refresh = operation === "refresh" || operation === "revoke";
  const session = await credential(env.DB, request, refresh);
  const nonce = proof?.nonce ?? request.headers.get("Howl-Nonce") ?? "";
  const signature = proof?.signature ?? request.headers.get("Howl-Signature") ?? "";
  requireValue(word.test(nonce), 401);
  const payload = await proofBytes(
    env.CONTROL_AUDIENCE,
    session.id,
    operation,
    nonce,
    session.tokenDigest,
    raw,
  );
  requireValue(await checkSignature(session.signing_key, payload, signature), 401);
  const consumed = await env.DB.prepare(`
    DELETE FROM control_challenges WHERE nonce = ? AND session_id = ? AND operation = ? AND token_digest = ?
      AND expires_at > unixepoch() AND EXISTS (
        SELECT 1 FROM control_sessions WHERE id = ? AND revoked = 0 AND expires_at > unixepoch()
      )`)
    .bind(nonce, session.id, operation, session.tokenDigest, session.id)
    .run();
  requireValue(consumed.meta.changes === 1, 401);
  return session;
}

async function challenge(env: Env, request: Request) {
  protect(env);
  const {
    parsed: { operation },
  } = await jsonBody<{ operation: string }>(request);
  requireValue(operations.has(operation));
  const session = await credential(
    env.DB,
    request,
    operation === "refresh" || operation === "revoke",
  );
  const nonce = randomId();
  const inserted = await env.DB.prepare(`
    INSERT INTO control_challenges (nonce, session_id, operation, token_digest, expires_at)
    SELECT ?, ?, ?, ?, unixepoch() + 60
    WHERE (SELECT COUNT(*) FROM control_challenges WHERE session_id = ? AND expires_at > unixepoch()) < 128`)
    .bind(nonce, session.id, operation, session.tokenDigest, session.id)
    .run();
  requireValue(inserted.meta.changes === 1, 429);
  return reply({ nonce });
}

export async function prepareCredentials(
  db: Env["DB"],
  session: Session,
  condition: string,
  inputs: string[],
) {
  const access = randomId();
  const refresh = randomId();
  const statements = [];
  for (const [token, kind] of [
    [access, 0],
    [refresh, 1],
  ] as const) {
    statements.push(
      db
        .prepare(`
      INSERT INTO control_tokens (digest, session_id, refresh, expires_at)
      SELECT ?, id, ?, CASE WHEN ? = 1 THEN expires_at ELSE MIN(expires_at, unixepoch() + 300) END
      FROM control_sessions WHERE id = ? AND (${condition})`)
        .bind(await digest(decodeHex(token)), kind, kind, session.id, ...inputs),
    );
  }
  return {
    value: {
      access_token: access,
      refresh_token: refresh,
      expires_in: 300,
      session: describe(session),
    },
    statements,
  };
}

async function refresh(env: Env, request: Request) {
  const { parsed } = await jsonBody<Proof>(request);
  const session = await authorizeNative(env, request, "refresh", undefined, parsed);
  const { DB: db } = env;
  const rotation = randomId();
  const tokens = await prepareCredentials(
    db,
    session,
    "revoked = 0 AND EXISTS (SELECT 1 FROM control_tokens WHERE digest = ? AND rotation = ?)",
    [session.tokenDigest, rotation],
  );
  const [used] = await db.batch([
    db
      .prepare(`
      UPDATE control_tokens SET rotation = ?
      WHERE digest = ? AND rotation IS NULL AND EXISTS (
        SELECT 1 FROM control_sessions WHERE id = ? AND revoked = 0 AND expires_at > unixepoch()
      )`)
      .bind(rotation, session.tokenDigest, session.id),
    db
      .prepare(`
      UPDATE control_sessions SET revoked = 1 WHERE id = ? AND EXISTS (
        SELECT 1 FROM control_tokens WHERE digest = ? AND rotation IS NOT NULL AND rotation != ?
      )`)
      .bind(session.id, session.tokenDigest, rotation),
    ...tokens.statements,
  ]);
  requireValue(used.meta.changes === 1, 401);
  return reply(tokens.value);
}

export async function nativeAuthRoute(route: string, request: Request, env: Env) {
  switch (route) {
    case "GET /v1/auth/config":
      protect(env);
      return reply({
        audience: env.CONTROL_AUDIENCE,
        browser_link_origin: env.WEB_ORIGIN ?? null,
        device_names: true,
      });
    case "POST /v1/auth/challenge":
      return challenge(env, request);
    case "GET /v1/auth/session":
      return reply(describe(await authorizeNative(env, request, "session")));
    case "POST /v1/auth/refresh":
      return refresh(env, request);
    case "POST /v1/auth/revoke": {
      const { parsed } = await jsonBody<Proof>(request);
      const session = await authorizeNative(env, request, "revoke", undefined, parsed);
      await env.DB.prepare("UPDATE control_sessions SET revoked = 1 WHERE id = ?")
        .bind(session.id)
        .run();
      return reply(null, 204);
    }
    default:
      return null;
  }
}
