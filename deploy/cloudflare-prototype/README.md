# Howl control plane on Cloudflare

The Worker hosts the GitHub sign-in, device dashboard, account membership, and signed iroh route hints. Howl encrypts and sends normal messages over iroh.

Run the Worker checks with Node.js 24.

```sh
npm ci
npm run check
```

The check runs Oxlint, Oxfmt, TypeScript, and integration tests using Cloudflare's local Workers runtime and D1. The tests exercise GitHub OAuth state and PKCE, owner-scoped device decisions, signed network enrollment, discovery, dashboard details, and the mailbox.

## Deployment

Use `npm run build` to produce `.build/worker.mjs`. Bind a D1 database as `DB` and apply the SQL migrations in order. Configure the Worker bindings below. Add `/login/github/callback` on the Worker origin to the GitHub OAuth app's callback URLs.

| Binding | Value |
| --- | --- |
| `WEB_ORIGIN` | HTTPS Worker origin without a trailing slash |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth secret |
| `CONTROL_AUDIENCE` | Stable, nonzero 32-byte ID encoded as hex |
| `CONTROL_STATE_KEY` | Stable, random 32-byte key encoded as hex and stored as a Worker secret |
| `GITHUB_OWNER_ID` | Optional numeric GitHub user ID for a restricted deployment |

## Use Howl

Run `howl control login --name NAME STATE_DIR`, open the browser link, and compare the fingerprint before approving the device. The Devices page shows pending and approved devices. Open a device page to rename it or see its iroh endpoint, last known address, online status, and direct or relay connections.

Run `howl mesh run STATE_DIR LISTEN_ADDR` on each device to publish signed route hints and connect over iroh.

## Offline mailbox

The owner can enable **Offline mailbox** in the Devices dashboard. It starts disabled. An approved device can explicitly deposit a retained envelope with `howl mesh mailbox deposit STATE_DIR PEER_DEVICE_ID`. The recipient retrieves it with `howl mesh mailbox fetch STATE_DIR`. D1 stores ciphertext until the recipient acknowledges it or the retention period expires.
