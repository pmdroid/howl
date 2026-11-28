import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Miniflare } from "miniflare";

const origin = "https://howl.test";
const audience = randomBytes(32);
const hash = (data) => createHash("sha256").update(data).digest();
const randomId = () => randomBytes(32).toString("hex");
const empty = Buffer.alloc(0);
const hex = (bytes) => bytes.toString("hex");
const bytes = (value) => Buffer.from(value, "hex");

function u64(number) {
  const value = Buffer.alloc(8);
  value.writeBigUInt64BE(BigInt(number));
  return value;
}

function device() {
  const signing = generateKeyPairSync("ed25519");
  const endpoint = generateKeyPairSync("ed25519");
  const encryption = generateKeyPairSync("x25519");
  const raw = (key) => key.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const id = randomBytes(32);
  const body = Buffer.concat([Buffer.from([1]), id, raw(signing), raw(endpoint), raw(encryption)]);
  const payload = Buffer.concat([Buffer.from("howl/manual-peer/v1\0"), body]);
  return {
    id: hex(id),
    peer: hex(
      Buffer.concat([
        body,
        sign(null, payload, signing.privateKey),
        sign(null, payload, endpoint.privateKey),
      ]),
    ),
    fingerprint: hex(hash(body)),
    sign: (body) => sign(null, body, signing.privateKey),
  };
}

function proof(identity, subject, operation, nonce, token, body = empty) {
  return hex(
    identity.sign(
      Buffer.concat([
        Buffer.from("howl/control-proof/v1\0"),
        audience,
        bytes(subject),
        hash(operation),
        bytes(nonce),
        token ? hash(bytes(token)) : Buffer.alloc(32),
        hash(body),
      ]),
    ),
  );
}

function hint(identity, time) {
  const body = Buffer.concat([
    Buffer.from([1]),
    bytes(identity.id),
    bytes(identity.fingerprint),
    u64(time),
    u64(time + 3600_000),
    Buffer.from([4, 100, 64, 1, 5]),
    Buffer.alloc(12),
    Buffer.from([0xa0, 0x3b]),
  ]);
  return Buffer.concat([
    body,
    identity.sign(Buffer.concat([Buffer.from("howl/peer-address/v1\0"), body])),
  ]);
}

function routeSet(identity, legacy, relay) {
  const prefix = Buffer.from(legacy.subarray(0, 81));
  prefix[0] = 2;
  const body = Buffer.concat([
    prefix,
    Buffer.from([2]),
    legacy.subarray(81, 100),
    Buffer.from([4, 192, 168, 8, 4, ...Buffer.alloc(12), 0xa0, 0x3b]),
    Buffer.from([0, Buffer.byteLength(relay)]),
    Buffer.from(relay),
  ]);
  return Buffer.concat([
    body,
    identity.sign(Buffer.concat([Buffer.from("howl/peer-routes/v2\0"), body])),
  ]);
}

function signedFrame(sender, recipient, snapshot) {
  const genesis = bytes(snapshot.authority[0]).subarray(0, -128);
  const account = hash(genesis);
  const channel = bytes(snapshot.channel);
  const now = Math.floor(Date.now() / 1000);
  const senderKey = bytes(sender.peer.slice(66, 130));
  const recipientKey = bytes(recipient.peer.slice(194, 258));
  const keyId = (label, key) =>
    hash(Buffer.concat([Buffer.from("howl/key/v1/" + label + "\0"), key]));
  const message = randomBytes(32);
  const payload = randomBytes(272);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length);
  const body = Buffer.concat([
    Buffer.from([1, 1]),
    channel,
    account,
    bytes(sender.id),
    keyId("device-signing", senderKey),
    u64(1),
    u64(1),
    u64(now),
    u64(0),
    message,
    randomBytes(32),
    Buffer.from([0, 1]),
    account,
    bytes(recipient.id),
    keyId("device-encryption", recipientKey),
    randomBytes(80),
    length,
    payload,
  ]);
  return {
    ciphertext: hex(
      Buffer.concat([body, sender.sign(Buffer.concat([Buffer.from("howl/envelope/v1\0"), body]))]),
    ),
    message: hex(message),
  };
}

async function status(response, expected) {
  const result = await response;
  const raw = await result.text();
  assert.equal(result.status, expected, raw);
  return raw ? JSON.parse(raw) : null;
}

test("Native publishing Worker", async (t) => {
  let githubId = 42;
  let challenge;
  let revoked = 0;
  const runtime = new Miniflare({
    modules: true,
    scriptPath: fileURLToPath(new URL("./.build/worker.mjs", import.meta.url)),
    compatibilityDate: "2026-07-30",
    d1Databases: { DB: "00000000-0000-4000-8000-000000000001" },
    bindings: {
      WEB_ORIGIN: origin,
      GITHUB_CLIENT_ID: "fixture",
      GITHUB_CLIENT_SECRET: "fixture-secret",
      CONTROL_AUDIENCE: hex(audience),
      CONTROL_STATE_KEY: randomId(),
    },
    outboundService: async (request) => {
      switch (request.url) {
        case "https://github.com/login/oauth/access_token": {
          const form = new URLSearchParams(await request.text());
          assert.equal(form.get("redirect_uri"), origin + "/login/github/callback");
          assert.equal(hash(form.get("code_verifier")).toString("base64url"), challenge);
          return Response.json({ access_token: "fixture-token" });
        }
        case "https://api.github.com/user":
          assert.equal(request.headers.get("Authorization"), "Bearer fixture-token");
          return Response.json({ id: githubId, login: "owner-" + githubId });
        case "https://api.github.com/applications/fixture/token":
          assert.equal(request.method, "DELETE");
          assert.deepEqual(await request.json(), { access_token: "fixture-token" });
          revoked++;
          return new Response(null, { status: 204 });
        default:
          throw Error("Unexpected upstream " + request.url);
      }
    },
  });
  t.after(() => runtime.dispose());

  const db = await runtime.getD1Database("DB");
  const migrations = new URL("./migrations/", import.meta.url);
  for (const file of (await readdir(migrations)).sort()) {
    const schema = await readFile(new URL(file, migrations), "utf8");
    await db.batch(
      schema
        .split(";")
        .filter((sql) => sql.trim())
        .map((sql) => db.prepare(sql)),
    );
  }

  function http(path, options = {}) {
    return runtime.dispatchFetch(origin + path, { redirect: "manual", ...options });
  }

  function post(path, data, headers = {}) {
    return http(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(data),
    });
  }

  async function owner(id) {
    githubId = id;
    const start = await http("/login/github");
    assert.equal(start.status, 303);
    const target = new URL(start.headers.get("location"));
    assert.equal(target.searchParams.get("code_challenge_method"), "S256");
    challenge = target.searchParams.get("code_challenge");
    const url = "/login/github/callback?code=fixture&state=" + target.searchParams.get("state");
    await status(http(url), 401);
    const finish = await http(url, {
      headers: { Cookie: start.headers.getSetCookie()[0].split(";")[0] },
    });
    assert.equal(finish.status, 303, await finish.text());
    assert.equal(finish.headers.get("location"), "/devices");
    await status(
      http(url, { headers: { Cookie: start.headers.getSetCookie()[0].split(";")[0] } }),
      401,
    );
    const cookie = finish.headers
      .getSetCookie()
      .find((value) => value.startsWith("__Host-howl-owner="));
    assert.match(cookie, /Secure; HttpOnly; SameSite=Strict/);
    return { Cookie: cookie.split(";")[0], Origin: origin };
  }

  async function link(identity, name, headers) {
    const link = await status(post("/v1/device-links", { peer: identity.peer, name }), 201);
    const viewed = await status(
      post("/api/device-links/view", { secret: link.secret }, headers),
      200,
    );
    assert.equal(viewed.fingerprint, identity.fingerprint);
    return link;
  }

  async function poll(identity, link, state, candidate) {
    const value = candidate ? Buffer.from(JSON.stringify(candidate)) : empty;
    const result = await status(
      post("/v1/device-links/" + link.id + "/poll", {
        nonce: link.nonce,
        signature: proof(identity, link.id, "device-link", link.nonce, null, value),
        candidate,
      }),
      200,
    );
    assert.equal(result.state, state);
    link.nonce = result.nonce ?? link.nonce;
    return result;
  }

  async function approve(identity, link, headers) {
    const waiting = await poll(identity, link, "waiting");
    const genesis = bytes(waiting.authority[0]).subarray(0, -128);
    const designation = bytes(waiting.designation).subarray(0, -128);
    const cert = bytes(identity.peer);
    const body = Buffer.concat([
      Buffer.from("howl/identity/v1/device\0"),
      hash(genesis),
      hash(designation),
      bytes(identity.id),
      u64(1),
      cert.subarray(33, 129),
    ]);
    await status(
      post(
        "/api/device-links/decide",
        {
          secret: link.secret,
          device: identity.id,
          fingerprint: identity.fingerprint,
          decision: "approve",
        },
        headers,
      ),
      200,
    );
    identity.credentials = (
      await poll(identity, link, "approved", {
        peer: identity.peer,
        proof: hex(identity.sign(body)),
      })
    ).credentials;
  }

  async function signed(identity, path, operation, params, { token, nonce, proofBody } = {}) {
    const creds = identity.credentials;
    const access = token ?? creds.access_token;
    const auth = { Authorization: "Bearer " + access };
    const challenge =
      nonce ?? (await status(post("/v1/auth/challenge", { operation }, auth), 200)).nonce;
    const raw =
      params === undefined
        ? empty
        : Buffer.isBuffer(params)
          ? params
          : Buffer.from(JSON.stringify(params));
    const sig = proof(identity, creds.session.id, operation, challenge, access, proofBody ?? raw);
    return http(path, {
      method: params === undefined ? "GET" : "POST",
      headers: {
        ...auth,
        "Howl-Nonce": challenge,
        "Howl-Signature": sig,
        "Content-Type": Buffer.isBuffer(params) ? "application/octet-stream" : "application/json",
      },
      ...(params === undefined ? {} : { body: raw }),
    });
  }

  const ownerHeaders = await owner(42);
  const anotherHeaders = await owner(43);
  assert.equal(revoked, 2);
  const alice = device();
  const bob = device();
  const stranger = device();

  await t.test(
    "real dashboard routes, scoped approvals and signed network enrollment",
    async () => {
      const home = await http("/devices");
      assert.match(await home.text(), /Pending requests/);
      assert.equal((await http("/assets/devices.js")).status, 200);
      const aliceLink = await link(alice, "Mac mini", ownerHeaders);
      const bobLink = await link(bob, "Agentbox", ownerHeaders);
      const strangerLink = await link(stranger, "Outside network", anotherHeaders);
      await status(
        post("/api/device-links/view", { secret: aliceLink.secret }, anotherHeaders),
        404,
      );
      await status(
        post(
          "/api/devices/approve",
          { device: alice.id, fingerprint: alice.fingerprint },
          anotherHeaders,
        ),
        404,
      );
      await status(
        post(
          "/api/devices/approve",
          { device: alice.id, fingerprint: alice.fingerprint },
          { ...ownerHeaders, Origin: "https://other.test" },
        ),
        403,
      );
      assert.deepEqual(
        (await status(http("/api/devices", { headers: ownerHeaders }), 200)).pending
          .map((device) => device.name)
          .sort(),
        ["Agentbox", "Mac mini"],
      );
      await approve(alice, aliceLink, ownerHeaders);
      await approve(bob, bobLink, ownerHeaders);
      await approve(stranger, strangerLink, anotherHeaders);
      const { snapshot, network } = await status(signed(alice, "/v1/network", "network-read"), 200);
      assert.equal(snapshot.devices.length, 2);
      assert.equal(snapshot.rosters.length, 2);
      assert.deepEqual(
        snapshot.devices.map((device) => device.peer),
        [alice.peer, bob.peer],
      );
      alice.network = { ...snapshot, channel: network };
      const details = await status(http("/api/devices/" + bob.id, { headers: ownerHeaders }), 200);
      assert.equal(details.endpoint_id, bob.peer.slice(130, 194));
      assert.equal(details.network_name, "owner-42");
      await status(http("/api/devices/" + bob.id, { headers: anotherHeaders }), 404);
      await status(
        post(
          "/api/devices/" + bob.id + "/name",
          { name: "Wrong", fingerprint: alice.fingerprint },
          ownerHeaders,
        ),
        404,
      );
      const renamed = await status(
        post(
          "/api/devices/" + bob.id + "/name",
          { name: "Linux device", fingerprint: bob.fingerprint },
          ownerHeaders,
        ),
        200,
      );
      assert.equal(renamed.name, "Linux device");
      const unwanted = device();
      const rejected = await link(unwanted, "Declined", ownerHeaders);
      await status(
        post(
          "/api/devices/deny",
          { device: unwanted.id, fingerprint: unwanted.fingerprint },
          ownerHeaders,
        ),
        200,
      );
      await poll(unwanted, rejected, "denied");
      const retry = await link(unwanted, "Declined retry", ownerHeaders);
      await poll(unwanted, retry, "denied");
    },
  );

  await t.test(
    "iroh hints are signed, account-scoped and reported on the device page",
    async () => {
      const route = hint(alice, Date.now());
      const path = "/v1/discovery/hints";
      const forged = Buffer.from(route);
      forged[100] ^= 1;
      await status(
        signed(alice, path, "discovery-write", Buffer.concat([bytes(alice.peer), forged])),
        401,
      );
      await status(
        signed(alice, path, "discovery-write", Buffer.concat([bytes(alice.peer), route])),
        204,
      );
      const lookup = await signed(bob, path + "/" + alice.id, "discovery-read", undefined, {
        proofBody: bytes(alice.id),
      });
      assert.equal(lookup.status, 200);
      assert.deepEqual(Buffer.from(await lookup.arrayBuffer()), route);
      await status(
        signed(stranger, path + "/" + alice.id, "discovery-read", undefined, {
          proofBody: bytes(alice.id),
        }),
        401,
      );
      const v2 = "/v2/discovery/hints";
      const routes = routeSet(alice, route, "https://example.test/");
      const forgedSet = Buffer.from(routes);
      forgedSet[forgedSet.length - 1] ^= 1;
      await status(
        signed(alice, v2, "discovery-write", Buffer.concat([bytes(alice.peer), forgedSet])),
        401,
      );
      await status(
        signed(alice, v2, "discovery-write", Buffer.concat([bytes(alice.peer), routes])),
        204,
      );
      const found = await signed(bob, v2 + "/" + alice.id, "discovery-read", undefined, {
        proofBody: bytes(alice.id),
      });
      assert.equal(found.status, 200);
      assert.deepEqual(Buffer.from(await found.arrayBuffer()), routes);
      await status(
        signed(stranger, v2 + "/" + alice.id, "discovery-read", undefined, {
          proofBody: bytes(alice.id),
        }),
        401,
      );
      await status(
        signed(alice, "/v1/discovery/status", "mesh-status", [{ device: bob.id, kind: "direct" }]),
        204,
      );
      const view = await status(http("/api/devices/" + alice.id, { headers: ownerHeaders }), 200);
      assert.equal(view.online, true);
      assert.equal(view.route.port, 41019);
      assert.deepEqual(view.connections, [
        { device: bob.id, kind: "direct", name: "Linux device" },
      ]);
      assert.equal(
        await db.prepare("SELECT COUNT(*) AS n FROM control_mailbox_envelopes").first("n"),
        0,
      );
    },
  );

  await t.test("mailbox requires owner opt-in and acknowledges ciphertext once", async () => {
    const fetchPage = { after: 0, limit: 16 };
    const frame = signedFrame(alice, bob, alice.network);
    const deposit = { recipient: bob.id, ciphertext: frame.ciphertext };
    const endpoint = "/v1/mailbox/settings";
    await status(signed(alice, "/v1/mailbox/deposit", "mailbox-deposit", deposit), 403);
    await status(
      post(
        "/api/mailbox/settings",
        { enabled: true },
        { ...ownerHeaders, Origin: "https://other.test" },
      ),
      403,
    );
    await status(post("/api" + endpoint, { enabled: true }, ownerHeaders), 404);
    assert.deepEqual(
      await status(post("/api/mailbox/settings", { enabled: true }, ownerHeaders), 200),
      { enabled: true },
    );
    await status(signed(alice, "/v1/mailbox/deposit", "mailbox-deposit", deposit), 201);
    await status(signed(alice, "/v1/mailbox/deposit", "mailbox-deposit", deposit), 204);
    const mailbox = await status(signed(bob, "/v1/mailbox/fetch", "mailbox-fetch", fetchPage), 200);
    assert.equal(mailbox.envelopes[0].ciphertext, frame.ciphertext);
    const ack = { message: frame.message, digest: mailbox.envelopes[0].digest };
    await status(signed(alice, "/v1/mailbox/ack", "mailbox-ack", ack), 404);
    await status(signed(bob, "/v1/mailbox/ack", "mailbox-ack", ack), 204);
    assert.deepEqual(
      await status(signed(bob, "/v1/mailbox/fetch", "mailbox-fetch", fetchPage), 200),
      { envelopes: [], next: null },
    );
    assert.deepEqual(
      await status(post("/api/mailbox/settings", { enabled: false }, ownerHeaders), 200),
      { enabled: false },
    );
    await status(signed(bob, "/v1/mailbox/fetch", "mailbox-fetch", fetchPage), 403);
  });

  await t.test("native challenges are single-use and refresh rotates credentials", async () => {
    const credential = alice.credentials;
    const headers = { Authorization: "Bearer " + credential.access_token };
    const { nonce } = await status(
      post("/v1/auth/challenge", { operation: "session" }, headers),
      200,
    );
    await status(signed(alice, "/v1/auth/session", "session", undefined, { nonce }), 200);
    await status(signed(alice, "/v1/auth/session", "session", undefined, { nonce }), 401);
    const refresh = async (token) => {
      const bearer = { Authorization: "Bearer " + token };
      const { nonce } = await status(
        post("/v1/auth/challenge", { operation: "refresh" }, bearer),
        200,
      );
      return post(
        "/v1/auth/refresh",
        {
          nonce,
          signature: proof(alice, credential.session.id, "refresh", nonce, token),
        },
        bearer,
      );
    };
    const fresh = await status(refresh(credential.refresh_token), 200);
    assert.notEqual(fresh.refresh_token, credential.refresh_token);
    await status(refresh(credential.refresh_token), 401);
    await status(
      post(
        "/v1/auth/challenge",
        { operation: "session" },
        { Authorization: "Bearer " + fresh.access_token },
      ),
      401,
    );
  });
});
