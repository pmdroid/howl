import { decodeHex, digest, encodeHex, jsonBody, randomId, reply, requireValue } from "./http.ts";
import {
  type Session,
  authorizeNative,
  checkSignature,
  joinBytes,
  prepareCredentials,
  proofBytes,
  word,
} from "./native-auth.ts";

type Candidate = { peer: string; proof: string };
type Snapshot = {
  authority: string[];
  designation: string;
  devices: { peer: string; certificate: string }[];
  rosters: string[];
};
type Network = {
  github_id: number;
  channel: string;
  founder: string;
  snapshot: Snapshot;
  signer: string;
  revision: number;
};
type Link = {
  account: string | null;
  native_account: string | null;
  native_nonce: string;
  native_credentials: string | null;
  device: string;
  peer: string;
  public_key: string;
  name: string;
  state: string;
};
type PollInput = { nonce: string; signature: string; candidate?: Candidate };

const encoder = new TextEncoder();
const genesisDomain = encoder.encode("howl/identity/v1/genesis\0");
const designateDomain = encoder.encode("howl/identity/v1/membership-signer\0");
const deviceDomain = encoder.encode("howl/identity/v1/device\0");
const rosterDomain = encoder.encode("howl/identity/v1/roster\0");
const peerDomain = encoder.encode("howl/manual-peer/v1\0");

function bigEndian(value: number, size: number) {
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  if (size === 8) view.setBigUint64(0, BigInt(value));
  else view.setUint16(0, value);
  return bytes;
}

async function sign(key: CryptoKey, body: Uint8Array<ArrayBuffer>) {
  return new Uint8Array(await crypto.subtle.sign("Ed25519", key, body));
}

export async function peerIdentity(peer: string) {
  requireValue(typeof peer === "string" && /^[0-9a-f]{514}$/.test(peer));
  const bytes = decodeHex(peer);
  const device = peer.slice(2, 66);
  const key = peer.slice(66, 130);
  const endpoint = peer.slice(130, 194);
  const encryption = peer.slice(194, 258);
  requireValue(bytes[0] === 1 && /[1-9a-f]/.test(device));
  requireValue(new Set([key, endpoint, encryption]).size === 3 && /[1-9a-f]/.test(encryption));
  const body = bytes.slice(0, 129);
  const signed = joinBytes(peerDomain, body);
  requireValue(await checkSignature(key, signed, peer.slice(258, 386)));
  requireValue(await checkSignature(endpoint, signed, peer.slice(386)));
  return { key, device, endpoint, encryption, fingerprint: await digest(body) };
}

async function stateKey(env: Env) {
  requireValue(word.test(env.CONTROL_STATE_KEY ?? "") && !/^0+$/.test(env.CONTROL_STATE_KEY), 503);
  return crypto.subtle.importKey("raw", decodeHex(env.CONTROL_STATE_KEY), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function seal(env: Env, context: string, bytes: Uint8Array<ArrayBuffer>) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode(context),
    },
    await stateKey(env),
    bytes,
  );
  return encodeHex(joinBytes(nonce, new Uint8Array(cipher)));
}

async function unseal(env: Env, context: string, text: string) {
  const bytes = decodeHex(text);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: bytes.slice(0, 12),
        additionalData: encoder.encode(context),
      },
      await stateKey(env),
      bytes.slice(12),
    ),
  );
}

export function signerContext(github: number, channel: string) {
  return "howl/d1/signer/v1:" + github + ":" + channel;
}

async function signingKey(seed: Uint8Array) {
  const pkcs8 = joinBytes(decodeHex("302e020100300506032b657004220420"), seed);
  return crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
}

async function keyPair() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  const secret = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey)).slice(-32);
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  return { privateKey, publicBytes, secret };
}

export async function ensureNativeNetwork(env: Env, github: number) {
  const current = await network(env, github);
  if (current) return current;
  const [root, recovery, delegated] = await Promise.all([keyPair(), keyPair(), keyPair()]);
  const genesis = joinBytes(genesisDomain, root.publicBytes, recovery.publicBytes);
  const account = await digest(genesis);
  const designation = joinBytes(
    designateDomain,
    decodeHex(account),
    decodeHex(account),
    bigEndian(1, 8),
    delegated.publicBytes,
    bigEndian(0, 2),
  );
  const snapshot = {
    authority: [
      encodeHex(
        joinBytes(
          genesis,
          await sign(root.privateKey, genesis),
          await sign(recovery.privateKey, genesis),
        ),
      ),
    ],
    designation: encodeHex(
      joinBytes(
        designation,
        await sign(root.privateKey, designation),
        await sign(delegated.privateKey, designation),
      ),
    ),
    devices: [],
    rosters: [],
  };
  const channel = randomId();
  const sealed = await seal(env, signerContext(github, channel), delegated.secret);
  await env.DB.prepare(`
    INSERT INTO control_networks (github_id, channel, founder, snapshot, signer) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (github_id) DO NOTHING`)
    .bind(github, channel, account, JSON.stringify(snapshot), sealed)
    .run();
  return network(env, github);
}

async function network(env: Env, github: number): Promise<Network | null> {
  const record = await env.DB.prepare("SELECT * FROM control_networks WHERE github_id = ?")
    .bind(github)
    .first<Omit<Network, "snapshot"> & { snapshot: string }>();
  return record && { ...record, snapshot: JSON.parse(record.snapshot) as Snapshot };
}

async function approvedPeer(env: Env, session: Session) {
  const peer = await env.DB.prepare(
    "SELECT peer FROM control_members WHERE github_id = ? AND device = ?",
  )
    .bind(session.github_id, session.device_id)
    .first<string>("peer");
  return peer && peer.slice(66, 130) === session.signing_key ? peer : null;
}

export async function requireMember(env: Env, session: Session) {
  const peer = await approvedPeer(env, session);
  requireValue(peer, 401);
  return peer;
}

export async function ownerGitHub(env: Env, account: string) {
  const id = await env.DB.prepare("SELECT github_id FROM owners WHERE account = ?")
    .bind(account)
    .first<number>("github_id");
  requireValue(id !== null && Number.isSafeInteger(id) && id > 0, 401);
  return id;
}

function designationBody(snapshot: Snapshot) {
  const record = decodeHex(snapshot.designation);
  requireValue(record.length >= designateDomain.length + 106 + 128, 409);
  return record.slice(0, -128);
}

async function candidateBody(snapshot: Snapshot, candidate: Candidate, peer: string) {
  requireValue(candidate?.peer === peer && /^[0-9a-f]{128}$/.test(candidate?.proof ?? ""), 401);
  const designation = designationBody(snapshot);
  const record = decodeHex(peer);
  const account = designation.slice(designateDomain.length, designateDomain.length + 32);
  const body = joinBytes(
    deviceDomain,
    account,
    decodeHex(await digest(designation)),
    record.slice(1, 33),
    bigEndian(1, 8),
    record.slice(33, 129),
  );
  requireValue(await checkSignature(peer.slice(66, 130), body, candidate.proof), 401);
  return body;
}

async function admit(env: Env, target: Network, candidate: Candidate) {
  const { github_id: github, channel, snapshot } = target;
  requireValue(snapshot && target.signer && snapshot.devices.length < 64, 409);
  const body = await candidateBody(snapshot, candidate, candidate.peer);
  const key = await signingKey(await unseal(env, signerContext(github, channel), target.signer));
  const certificate = encodeHex(joinBytes(body, await sign(key, body), decodeHex(candidate.proof)));
  const devices = [...snapshot.devices, { peer: candidate.peer, certificate }];
  const roster = await rosterBody(snapshot, devices, channel);
  const signed = encodeHex(joinBytes(roster, await sign(key, roster)));
  return { ...snapshot, devices, rosters: [...snapshot.rosters, signed] };
}

async function rosterBody(snapshot: Snapshot, devices: Snapshot["devices"], channel: string) {
  const designation = designationBody(snapshot);
  const account = designation.slice(designateDomain.length, designateDomain.length + 32);
  const members = await Promise.all(
    devices.map(async (device) =>
      joinBytes(
        account,
        decodeHex(device.peer.slice(2, 66)),
        decodeHex(await digest(decodeHex(device.certificate).slice(0, -128))),
        new Uint8Array([3]),
      ),
    ),
  );
  members.sort((a, b) => {
    for (let i = 32; i < 64; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return 0;
  });
  const last = snapshot.rosters.at(-1);
  const previous = last
    ? decodeHex(await digest(decodeHex(last).slice(0, -64)))
    : new Uint8Array(32);
  return joinBytes(
    rosterDomain,
    account,
    decodeHex(await digest(designation)),
    decodeHex(channel),
    previous,
    bigEndian(devices.length, 8),
    new Uint8Array([0]),
    bigEndian(devices.length, 2),
    ...members,
  );
}

async function readNetwork(request: Request, env: Env) {
  const session = await authorizeNative(env, request, "network-read");
  const current = await network(env, session.github_id);
  if (!current) return reply(null, 409);
  const member = await approvedPeer(env, session);
  return reply({
    state: member ? "approved" : "pending",
    account_managed: true,
    network: current.channel,
    founder: current.founder,
    snapshot: member ? current.snapshot : null,
    authority: current.snapshot?.authority ?? [],
    designation: current.snapshot?.designation ?? null,
    pending: [],
  });
}

async function pollNative(env: Env, request: Request, id: string) {
  const {
    parsed: { nonce, signature, candidate },
  } = await jsonBody<PollInput>(request);
  requireValue(word.test(nonce ?? ""), 401);
  const { DB: db } = env;
  const link = await db
    .prepare("SELECT * FROM device_links WHERE id = ? AND expires_at > unixepoch()")
    .bind(id)
    .first<Link>();
  requireValue(link, 404);
  requireValue(link.native_nonce === nonce, 401);
  const candidateBytes = candidate
    ? encoder.encode(JSON.stringify({ peer: candidate.peer, proof: candidate.proof }))
    : new Uint8Array();
  const proof = await proofBytes(
    env.CONTROL_AUDIENCE,
    id,
    "device-link",
    nonce,
    null,
    candidateBytes,
  );
  requireValue(await checkSignature(link.public_key, proof, signature), 401);
  const nextNonce = randomId();
  const updated = await db
    .prepare(
      "UPDATE device_links SET native_nonce = ? WHERE id = ? AND native_nonce = ? AND expires_at > unixepoch()",
    )
    .bind(nextNonce, id, nonce)
    .run();
  requireValue(updated.meta.changes === 1, 401);
  const pending: {
    state: string;
    nonce: string;
    network?: string;
    authority?: string[];
    designation?: string;
  } = {
    state: "waiting",
    nonce: nextNonce,
  };
  if (!link.native_account) return reply(pending);
  const github = await ownerGitHub(env, link.native_account);
  const target = await network(env, github);
  if (link.state === "denied") return reply({ state: "denied" });
  requireValue(target?.snapshot, 409);
  pending.network = target.channel;
  pending.authority = target.snapshot.authority;
  pending.designation = target.snapshot.designation;
  if (link.state !== "approved" || !candidate) return reply(pending);
  await candidateBody(target.snapshot, candidate, link.peer);
  const linkContext = "howl/d1/link/v1:" + id;
  if (link.native_credentials) {
    return reply({
      state: "approved",
      credentials: JSON.parse(
        new TextDecoder().decode(await unseal(env, linkContext, link.native_credentials)),
      ),
    });
  }
  const existing = target.snapshot.devices.find(
    (device) => device.peer.slice(2, 66) === link.device,
  );
  requireValue(!existing || existing.peer === link.peer, 409);
  const addsMember = !existing;
  const snapshot = addsMember ? await admit(env, target, candidate) : target.snapshot;
  const session = {
    id: randomId(),
    github_id: github,
    device_id: link.device,
    signing_key: link.public_key,
  };
  const tokens = await prepareCredentials(db, session, "1", []);
  const sealed = await seal(env, linkContext, encoder.encode(JSON.stringify(tokens.value)));
  const [lock] = await db.batch([
    db
      .prepare(`
      UPDATE device_links SET native_credentials = ? WHERE id = ? AND native_nonce = ?
        AND native_credentials IS NULL AND state = 'approved' AND expires_at > unixepoch()
        AND EXISTS (SELECT 1 FROM control_networks WHERE github_id = ? AND revision = ?)
    `)
      .bind(sealed, id, nextNonce, github, target.revision),
    db
      .prepare(`
      UPDATE control_networks SET snapshot = ?, revision = revision + ? WHERE github_id = ?
      AND EXISTS (SELECT 1 FROM device_links WHERE id = ? AND native_credentials = ?)
    `)
      .bind(JSON.stringify(snapshot), addsMember ? 1 : 0, github, id, sealed),
    db
      .prepare(`
      INSERT INTO control_members (github_id, device, peer, name, requested_at, approved_at)
      SELECT ?, ?, ?, ?, requested_at, approved_at FROM device_links WHERE ? = 1 AND id = ? AND native_credentials = ?
      ON CONFLICT (github_id, device) DO NOTHING
    `)
      .bind(github, link.device, link.peer, link.name, Number(addsMember), id, sealed),
    db
      .prepare(`
      INSERT INTO control_sessions (id, github_id, device_id, signing_key, expires_at)
      SELECT ?, ?, ?, ?, unixepoch() + 2592000 WHERE EXISTS (
        SELECT 1 FROM device_links WHERE id = ? AND native_credentials = ?
      )
    `)
      .bind(session.id, github, link.device, link.public_key, id, sealed),
    ...tokens.statements,
  ]);
  return reply(
    lock.meta.changes === 1 ? { state: "approved", credentials: tokens.value } : pending,
  );
}

export async function nativeNetworkRoute(route: string, request: Request, env: Env) {
  if (!env.CONTROL_AUDIENCE) return null;
  switch (route) {
    case "GET /v1/network":
      return readNetwork(request, env);
  }
  const link = /^(GET|POST) \/v1\/device-links\/([0-9a-f]{64})\/(challenge|poll)$/.exec(route);
  if (!link) return null;
  if (link[1] === "POST" && link[3] === "poll") return pollNative(env, request, link[2]);
  requireValue(link[1] === "GET" && link[3] === "challenge", 404);
  const nonce = await env.DB.prepare(
    "SELECT native_nonce FROM device_links WHERE id = ? AND expires_at > unixepoch()",
  )
    .bind(link[2])
    .first("native_nonce");
  requireValue(nonce, 404);
  return reply({ nonce });
}
