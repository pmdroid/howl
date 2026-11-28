# Howl private beta runbook

Use this runbook to release the control plane, PostgreSQL, iroh relay and encrypted mailbox for the invited cohort. Record the release commit, service hosts, deployment and incident owners, backup schedule, and acceptance results in the internal deployment issue.

## Run the local Docker beta

Build the native device binary and the Linux control plane from the same release checkout. Use a local Docker engine with Compose, Bash, OpenSSL and curl.

```sh
cargo build --locked -p howl --bin howl
beta_build=$(mktemp -d /tmp/howl-beta-build.XXXXXXXX)
docker run --rm -v "$PWD:/repo:ro" -v "$beta_build:/out" \
  -e CARGO_HOME=/out/cargo -e CARGO_TARGET_DIR=/out/target \
  -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_INCREMENTAL=0 \
  -w /repo docker.io/library/rust:1.100.0-bookworm@sha256:75d26c23c24cc6ea1cdabf0714a6bff8fd7bf3248716043fd7ae86dac7f41b94 \
  cargo build --locked -p howl-control-plane --bin howl-control-plane
```

Download and verify the Linux GNU relay archive for the Docker engine's architecture from the [iroh 1.5.0 release](https://github.com/n0-computer/iroh/releases/tag/v1.5.0). Put the extracted executable at `$beta_build/iroh-relay`. The [two-network proof](../spikes/mesh-e2e/README.md) pins the ARM64 archive checksum.

```sh
HOWL_BETA_KEEP=1 bash deploy/private-beta/rehearse-docker.sh \
  "$beta_build/target/debug/howl-control-plane" "$beta_build/iroh-relay" "$PWD/target/debug/howl"
```

The rehearsal starts PostgreSQL, a native Linux control plane, an endpoint-allowlisted relay and a local gateway. The services share PostgreSQL’s Docker network namespace. The gateway publishes the API and relay on loopback, and the backends bind inside the namespace. The script uses generated secrets and synthetic account data. It enrolls two native devices, applies a signed roster, verifies one copy of each message before and after receiver restart, and restarts the API against an independently restored database. Keep the run output with the release record.

With `HOWL_BETA_KEEP=1`, the script prints the API and relay URLs and private device-state paths. Use the printed Compose environment file to manage that instance and retain its binary paths. Stop the device daemons, then stop the services from the same checkout.

```sh
"$PWD/target/debug/howl" mesh stop "$alice_state"
"$PWD/target/debug/howl" mesh stop "$bob_state"
source "$beta_compose_environment"
docker compose -f deploy/private-beta/compose.yaml -f deploy/private-beta/compose.docker.yaml down
```

### Enable GitHub sign-in for the local beta

Choose the HTTPS origin browsers and devices will use to reach the control plane. For a Tailscale beta, publish the local API URL printed by the Docker rehearsal. Set `HOWL_CONTROL_WEB_ORIGIN` to the HTTPS origin printed by Tailscale, including its port.

```sh
tailscale serve --bg --https=8446 "$api_url"
export HOWL_CONTROL_WEB_ORIGIN=https://control.example.ts.net:8446
```

Register a dedicated GitHub OAuth app. Use the control-plane origin as its homepage and append `/login/github/callback` for the authorization callback URL. Store the client ID and secret in separate files named `client-id` and `client-secret` in `~/.local/share/howl/github-oauth`. Give the directory mode `0700` and both files mode `0600`. [GitHub OAuth app setup](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)

Start the API with the GitHub override. Include it whenever you recreate the API.

```sh
source "$beta_compose_environment"
export HOWL_BETA_GITHUB_OAUTH_DIR="$HOME/.local/share/howl/github-oauth"
docker compose -f deploy/private-beta/compose.yaml -f deploy/private-beta/compose.docker.yaml \
  -f deploy/private-beta/compose.github.yaml up -d --no-deps api
```

### Create your network and approve devices

Open `/devices` at the control-plane origin and choose **Sign in with GitHub**. Your first web sign-in creates your account's network. Returning to the dashboard with the same GitHub account opens that network.

On each device, set `HOWL_CONTROL_URL` to the same HTTPS origin. Run the login command with a fresh private state directory. To give the device a name, pass `--name` before the state directory. The command prints a private Howl link and the full certificate fingerprint. Keep the command running while you open the link in your browser.

```sh
howl control login --name "Work laptop" "$device_state"
```

If prompted, sign in with the GitHub account that owns the network. Opening the link while signed in binds the request to that account and adds it to **Pending requests**. Check that the network ID matches your dashboard and compare the full fingerprint on the page with the one printed on the device. Choose **Approve** or **Deny**. The CLI receives the decision from the control plane, even when every previously approved device is offline. Approved devices appear under **Approved devices** on the dashboard after the CLI completes enrollment. On an approved device, run `howl control devices "$device_state"` to see its membership.

Select a device name under **Pending requests** or **Approved devices** to see its membership, full fingerprint and device ID. Choose **Rename** to change its display name. The details page shows request, approval and last address update times when the control plane has recorded them.

Start the mesh on each approved device. Use the network ID shown on the dashboard and the recipient's device ID. The final dash selects the discovered iroh route.

```sh
howl mesh run "$device_state" -
```

From another terminal on the sender, send a message. Read it on the recipient.

```sh
printf '%s\n' 'hello from my first device' | howl send "$sender_state" "$network_id" "$recipient_device_id" -
howl read "$recipient_state" "$network_id"
```

### Transfer an existing founder-managed network

For a network created by an earlier device login, run `howl control transfer "$founder_state"` once on the founding machine using its original state directory and the HTTPS control-plane URL. After the transfer, sign in on the control-plane dashboard to manage that network.

For a founder-managed network awaiting transfer, use `howl control devices "$founder_state"` and `howl control approve "$founder_state" "$device_id"`. The founder's local **Devices** page also accepts approval and denial decisions. Match the full certificate fingerprint with the requesting device before deciding.

### Verify the native API and mailbox

Run without `HOWL_BETA_KEEP` for a clean rehearsal on disposable volumes. The GitHub fixture exercises device login, owner approval and delivery between two iroh nodes using the native CLI.

```sh
cargo build --locked -p howl -p howl-control-plane --bins
HOWL_BETA_TEST_GITHUB_FIXTURE=1 HOWL_TEST_CONTROL_CLI="$PWD/target/debug/howl" \
  bash deploy/private-beta/rehearse.sh "$PWD/target/debug/howl-control-plane"
cargo test --locked -p howl --test enrollment_cli --test mesh --test web
HOWL_TEST_IROH_RELAY=/absolute/path/to/native/iroh-relay \
  cargo test --locked -p howl --test relay stock_relay_allows_only_configured_endpoint_identities -- --ignored
```

Verify enrolled mailbox deposit, fetch, range and acknowledgment in a disposable database named `howl_mailbox_api_test`. Run the fixture and the database in one Docker network namespace with no published ports. Use the Linux Cargo cache from the build above.

```sh
(
set -e
mailbox_postgres=$(docker run --detach --rm --network none \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=howl_mailbox_api_test \
  docker.io/library/postgres:17.12-bookworm@sha256:1eff563f6c868b9b433566e9f3cf6e5c79fbd3b95bf70ec7277d376cdbfc50d7)
trap 'docker stop "$mailbox_postgres" >/dev/null' EXIT
for ((attempt = 0; attempt < 50; attempt++)); do
    if docker exec "$mailbox_postgres" pg_isready -h 127.0.0.1 -U postgres -d howl_mailbox_api_test; then break; fi
    sleep .2
done
docker run --rm --network "container:$mailbox_postgres" \
  -v "$PWD:/repo:ro" -v "$beta_build:/out" -e CARGO_HOME=/out/cargo -e CARGO_TARGET_DIR=/out/target \
  -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_INCREMENTAL=0 \
  -e HOWL_MAILBOX_API_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/howl_mailbox_api_test \
  -w /repo docker.io/library/rust:1.100.0-bookworm@sha256:75d26c23c24cc6ea1cdabf0714a6bff8fd7bf3248716043fd7ae86dac7f41b94 \
  cargo +1.100.0 test --locked --offline -p howl-control-plane --test mailbox_api \
  enrolled_http_mailbox_retains_fetch_and_requires_exact_authorized_ack -- --ignored
)
```

On the device hosting the observer, set up the local Linux Docker engine, Node and the pinned repository image using the [host-agent fixture setup](../crates/howl/tests/fixtures/host-agent/README.md). Verify the repository sandbox before opening a model session. Run the fixture from the release checkout.

```sh
cargo test --locked -p howl --test workflow_mesh \
  signed_two_node_wakes_drive_a_read_only_draft_review_and_final -- --ignored
```

## Install on the service host

Use a Linux host with a local Docker engine, a TLS reverse proxy and resolvable API and relay names. Run the control plane and relay under separate dedicated users. Permit HTTPS ingress to the proxy and keep the PostgreSQL, API and relay backends on loopback. Capture service status and aggregate errors with access logging of bodies, credentials and signed proofs disabled.

Build release artifacts from the approved commit and verify the relay asset checksum from the [iroh 1.5.0 release](https://github.com/n0-computer/iroh/releases/tag/v1.5.0).

```sh
cargo build --release --locked -p howl --bin howl -p howl-control-plane --bin howl-control-plane
```

### PostgreSQL and control plane

Use an absolute, owner-only secret directory outside the checkout. The Compose volume holds the data across ordinary container restarts. PostgreSQL administration and migrations use the owner connection. The long-running API uses the runtime role. [Docker Official Image for PostgreSQL](https://hub.docker.com/_/postgres)

```sh
umask 077
export HOWL_BETA_PRIVATE_DIR=/absolute/path/to/private-credentials
export HOWL_BETA_POSTGRES_PORT=15432
install -d -m 0700 "$HOWL_BETA_PRIVATE_DIR"
for name in postgres-admin postgres-owner postgres-runtime state-key audience; do
    if [ ! -e "$HOWL_BETA_PRIVATE_DIR/$name" ]; then
        (set -C; openssl rand -hex 32 > "$HOWL_BETA_PRIVATE_DIR/$name")
    fi
done
docker compose -f deploy/private-beta/compose.yaml up -d --wait
bash deploy/private-beta/database.sh bootstrap
```

Configure the OAuth app's homepage with the HTTPS control-plane origin and its callback with the same origin followed by `/login/github/callback`. Put the app's client ID and secret in the API service's private environment. [GitHub OAuth app setup](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)

Use shell assignments from a private service environment or secret manager. Run migrations before starting the API and on every release that changes the database schema.

```sh
owner_url="postgresql://howl_control_owner:$(<"$HOWL_BETA_PRIVATE_DIR/postgres-owner")@127.0.0.1:$HOWL_BETA_POSTGRES_PORT/howl"
runtime_url="postgresql://howl_control_runtime:$(<"$HOWL_BETA_PRIVATE_DIR/postgres-runtime")@127.0.0.1:$HOWL_BETA_POSTGRES_PORT/howl"
HOWL_CONTROL_DATABASE_URL="$owner_url" howl-control-plane --migrate
export HOWL_CONTROL_BIND=127.0.0.1:8080
export HOWL_CONTROL_WEB_ORIGIN=https://howl.example.com
export HOWL_CONTROL_AUDIENCE
HOWL_CONTROL_AUDIENCE=$(<"$HOWL_BETA_PRIVATE_DIR/audience")
export HOWL_CONTROL_STATE_KEY
HOWL_CONTROL_STATE_KEY=$(<"$HOWL_BETA_PRIVATE_DIR/state-key")
HOWL_CONTROL_DATABASE_URL="$runtime_url" howl-control-plane
```

Run the API foreground command under the service manager. Pass `HOWL_GITHUB_CLIENT_ID` and `HOWL_GITHUB_CLIENT_SECRET` in that manager's private environment. Keep the audience and state key with service configuration across restarts. Confirm that `GET /healthz` returns HTTP 204 on loopback before switching traffic at the proxy.

### Relay and HTTPS

Build the relay allowlist from the approved devices' public `Endpoint` values. Set the values below to those IDs. Run `iroh-relay --config-path /absolute/path/to/relay.toml` under the relay service user. [iroh relay settings](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/main.rs)

```toml
http_bind_addr = "127.0.0.1:3340"
enable_metrics = false
enable_quic_addr_discovery = false
access.allowlist = ["FIRST_APPROVED_ENDPOINT", "SECOND_APPROVED_ENDPOINT"]

[limits.client.rx]
bytes_per_second = 65536
max_burst_bytes = 8192
```

Terminate TLS at the proxy and forward WebSocket upgrades for the relay. Configure the two service names and their certificates before inviting devices. An example Caddy configuration follows. [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)

```caddyfile
{$HOWL_API_HOST} {
    reverse_proxy 127.0.0.1:8080
}

{$HOWL_RELAY_HOST} {
    reverse_proxy 127.0.0.1:3340
}
```

Use `https://` relay URLs on participant devices. Check `https://$HOWL_API_HOST/healthz` and complete a peer exchange over the HTTPS relay before opening the cohort.

## Enroll two devices and verify delivery

Create the authority once on the operator machine. Put the offline key directory on protected offline storage. For each device, use a fresh exchange directory and a separate invitation directory. Transfer files with private permissions. Verify the fingerprint from the candidate and verify the account, authority head and designation IDs from the operator over a separate trusted channel.

```sh
howl enrollment init "$owner_state" "$offline_keys"
howl enrollment identity "$device_state" "$device_exchange"
howl enrollment authority "$owner_state"
```

Copy the candidate's `device` file into the operator's exchange directory. The owner runs `offer`. Send the public exchange files and the invitation over separate channels.

```sh
howl enrollment offer "$owner_state" "$operator_exchange" "$verified_fingerprint" 1 "$operator_invitation"
howl enrollment respond "$device_state" "$device_exchange" "$verified_account" "$verified_head" "$verified_designation" "$device_invitation"
```

Return the `response` file to the operator. Copy the issued `enrollment-certificate` to the candidate's exchange. After an interrupted transfer, the operator can copy the already issued certificate with `howl enrollment certificate "$owner_state" "$operator_exchange"`.

```sh
howl enrollment certify "$owner_state" "$operator_exchange"
howl enrollment accept "$device_state" "$device_exchange" "$verified_account" "$verified_head" "$verified_designation"
HOWL_CONTROL_DATABASE_URL="$owner_url" howl-control-plane --pin-enrollment \
  "$github_numeric_id" "$verified_account" "$verified_head" "$verified_designation"
```

For a manually enrolled cohort using GitHub device codes, enable Device Flow on the OAuth app and run `howl control login --device-code "$device_state"` before uploading the approved public enrollment. Check that the uploaded enrollment matches the independent pin. Exchange the two candidates' `device` and `enrollment-certificate` files between their private peer-import directories. Run `howl enrollment peer STATE PEER_EXCHANGE` on each recipient. Confirm the relay allowlist contains the two enrolled endpoint IDs.

Enroll the roster issuer as a device using its operator state. Import both participant certificates into that state. The following example grants send and receive permissions on a new channel. Transfer the channel and proof from the issuer to each participant.

```sh
howl roster issue "$owner_state" - active "$alice_device:3" "$bob_device:3"
howl roster apply "$alice_state" "$channel" "$proof"
howl roster apply "$bob_state" "$channel" "$proof"
```

Start both participant daemons with `howl mesh run STATE - "$relay_url"`. Send a test message and confirm the peer sees it with `howl read STATE CHANNEL` and the sender sees acknowledgment with `howl status STATE CHANNEL MESSAGE`. Stop the receiver with `howl mesh stop STATE`, send another message, then start it again and verify one copy of the second message in its history. Run the mailbox integration fixture against disposable PostgreSQL to verify deposit, range recovery and acknowledgment for enrolled clients. Record the message IDs, timestamps and outcomes.

Grant an explicit workflow wake for the recipient's verified agent. On an approved test repository, select the commit and the specific files to include. Confirm the intended provider and file disclosure on the device, run the workflow, and confirm the signed response appears in the peer's history. Record the observer fixture result and the signed turn ID.

## Data and retention

Keep production service logs to aggregate status and operational errors. Device state and recovery files use private, owner-only directories.

| Location | Data and operator handling |
| --- | --- |
| Participant device | Decrypted history, selected repository content, long-lived device keys and local delivery state. Keep state on protected local storage and share only the requested committed files with the authorized model session. |
| Hosted API and PostgreSQL | Public enrollment and discovery records, numeric GitHub account IDs, session digests and device decisions. The control plane encrypts each account’s delegated signing key and the device credentials available for retry during a ten-minute link. Legacy GitHub device codes are also encrypted. Back up the API state key in the service secret store so restored networks can continue to sign memberships. |
| Hosted mailbox | Opaque ciphertext plus routing, sequence, message, time and acknowledgment metadata. Mailbox retention is seven days. Monitor expiry cleanup and quotas, and treat metadata as private operational data. |
| Relay | Connections are admitted by signed endpoint identity. Restrict relay logs and keep the verified allowlist with the deployment configuration. |
| Backup storage | Database archives include the records and metadata present at dump time. Encrypt archives, restrict restore access, and remove copies on the backup schedule recorded for the cohort. |

## Database backup and restore

Schedule backups for the active database and retain the release version and backup timestamp with the encrypted archive. Set the backup directory and age recipient from the deployment record. [PostgreSQL backup](https://www.postgresql.org/docs/17/backup.html) and [age](https://github.com/FiloSottile/age)

```sh
set -o pipefail
umask 077
archive="$HOWL_BACKUP_DIR/howl-$(date -u +%Y%m%dT%H%M%SZ).dump.age"
bash deploy/private-beta/database.sh dump howl |
  age -r "$HOWL_BACKUP_RECIPIENT" -o "$archive.part"
mv "$archive.part" "$archive"
```

Rehearse restoration into a fresh database before redirecting the service. Bootstrap the PostgreSQL roles on a replacement host. Restore by streaming from the encrypted archive. Use an empty name such as `howl_restore`.

```sh
set -o pipefail
age --decrypt -i "$HOWL_BACKUP_IDENTITY_FILE" "$archive" |
  bash deploy/private-beta/database.sh restore howl_restore
```

Start the release against the restored database with the recorded audience and state key, check health and enrollment pins, and compare mailbox counts and representative delivery results. Apply any verified revocations or authority pin updates made after the backup. Revoke sessions affected by the incident before reopening the proxy and take a new backup once the restore is accepted.

## Device and authority recovery

Export a protected recovery package during setup and after authority recovery. Store the encrypted package and the unlock directory separately.

```sh
howl enrollment recover-export "$owner_state" "$offline_keys" "$recovery_package" "$recovery_unlock"
howl enrollment recover "$new_owner_state" "$recovery_package" "$recovery_unlock" "$new_offline_keys" \
  "$verified_account" "$verified_head"
howl enrollment authority "$new_owner_state"
```

Compare the recovered head and designation out of band before updating the hosted enrollment pin. Issue a fresh encrypted recovery export and reenroll the returning devices under the new designation. For a lost participant device, use a newly generated device identity, enroll it, and distribute the updated signed roster and relay allowlist.

## Incident response

1. Open an internal incident record with the deployment and security owners. Capture the release, service status, affected device IDs, authority checkpoint and mailbox cursors without copying credentials or message bodies into the record.
2. For a lost device or suspected device key compromise, remove its relay endpoint, distribute the signed revocation and updated roster, then verify the old device fails to send or fetch.
3. For suspected service credential exposure, restrict proxy ingress, rotate affected OAuth, database or service credentials, and revoke affected sessions. Confirm the replacement service with health, authorized enrollment and delivery checks.
4. For an authority incident, use the offline recovery procedure from a trusted device. Compare the recovered head independently, publish the active pin and reenroll approved participants.
5. Reopen participant access after the two-device delivery and observer checks pass. Record the timeline, updated keys or pins, and the recovery evidence.
