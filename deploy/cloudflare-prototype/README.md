# Howl control plane on Workers and D1

Run the integration tests with Node.js 24.

```sh
cd deploy/cloudflare-prototype
npm ci
npm test
```

Miniflare starts Cloudflare's local Workers runtime, applies the D1 migration,
and seeds two owner sessions. The tests generate device keys and exercise
approval, denial, cross-account access, and encrypted delivery over HTTP.

## Device enrollment

A device starts a link with `POST /v1/device-links` and sends its name and
Ed25519 public key as `name` and `public_key`. The response includes a
short-lived link secret, the device ID, and the SHA-256 fingerprint of the key.

The owner sends the link secret to `POST /api/device-links/claim` with their
bearer token. `GET /api/devices` lists the owner's devices, fingerprints,
and approval state. To decide, send `device`, `fingerprint`, and
`decision` set to `approve` or `deny` to `POST /api/devices/decide`.

## Mailbox

| Endpoint | Request body |
| --- | --- |
| `POST /v1/mailbox/deposit` | `recipient`, `message`, `ciphertext`, `expires_at` |
| `POST /v1/mailbox/fetch` | `after`, `limit` |
| `POST /v1/mailbox/ack` | `cursor`, `message`, `digest` |

The client encrypts the message and hex-encodes the resulting bytes before
depositing it. Use a random 32-byte message ID and retry with the same ID and
envelope. Start fetching with `after` set to zero, then advance to the cursor
of the last processed envelope. Acknowledging an envelope removes its ciphertext
and leaves its digest until expiry for deduplication.

Approved devices authenticate each request with the `Howl-Account`,
`Howl-Device`, `Howl-Nonce`, `Howl-Expires`, and `Howl-Signature` headers.
The signature covers the UTF-8 JSON encoding of
`["howl-d1-proof-v1", path, account, device, nonce, expires, bodyDigest]`.
Hash the exact request body with SHA-256. Encode keys, IDs, digests, and
signatures as lowercase hex. Use a fresh 32-byte nonce and set the proof expiry
to a Unix timestamp in seconds up to 60 seconds ahead.
