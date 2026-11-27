set -euo pipefail
umask 077

export HOWL_BETA_CONTROL_BINARY=${1:?Usage: bash deploy/private-beta/rehearse-docker.sh LINUX_CONTROL LINUX_RELAY NATIVE_HOWL}
export HOWL_BETA_RELAY_BINARY=${2:?Set the absolute path to the verified Linux iroh-relay}
howl=${3:?Set the absolute path to the native Howl CLI}
for binary in "$HOWL_BETA_CONTROL_BINARY" "$HOWL_BETA_RELAY_BINARY" "$howl"; do
    [[ "$binary" = /* && -x "$binary" ]]
done
host=${DOCKER_HOST:-unix://}
if [[ -n "${DOCKER_CONTEXT:-}" || -z "${DOCKER_HOST:-}" ]]; then
    host=$(docker context inspect "${DOCKER_CONTEXT:-$(docker context show)}" --format '{{.Endpoints.docker.Host}}')
fi
[[ "$host" = unix://* ]]

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d "/tmp/howl-beta-docker.XXXXXXXX")
export HOWL_BETA_PRIVATE_DIR="$scratch"
export HOWL_BETA_RELAY_CONFIG="$scratch/relay.toml"
export HOWL_BETA_POSTGRES_PORT=0 HOWL_BETA_API_PORT=0 HOWL_BETA_RELAY_PORT=0 HOWL_BETA_DB=howl
export HOWL_BETA_UID HOWL_BETA_GID COMPOSE_PROJECT_NAME
HOWL_BETA_UID=$(id -u)
HOWL_BETA_GID=$(id -g)
COMPOSE_PROJECT_NAME=$(printf 'howl-beta-%s' "${scratch##*.}" | tr '[:upper:]' '[:lower:]')
alice_pid=
bob_pid=
keep=${HOWL_BETA_KEEP:-0}

compose() {
    docker compose -f "$directory/compose.yaml" -f "$directory/compose.docker.yaml" "$@"
}

cleanup() {
    result=$?
    trap - EXIT
    if [[ "$result" = 0 && "$keep" = 1 ]]; then
        for name in HOWL_BETA_CONTROL_BINARY HOWL_BETA_RELAY_BINARY HOWL_BETA_PRIVATE_DIR HOWL_BETA_RELAY_CONFIG HOWL_BETA_POSTGRES_PORT HOWL_BETA_API_PORT HOWL_BETA_RELAY_PORT HOWL_BETA_DB HOWL_BETA_UID HOWL_BETA_GID COMPOSE_PROJECT_NAME; do
            printf 'export %s=%q\n' "$name" "${!name}"
        done > "$scratch/compose.env"
        printf 'API %s\nRelay %s\nCompose environment %s\nAlice state %s\nBob state %s\n'             "$api" "$relay" "$scratch/compose.env" "$alice" "$bob"
        return
    fi
    for pid in "$alice_pid" "$bob_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ "$result" != 0 ]]; then
        compose logs --tail=10 api relay gateway >&2 || true
        for log in "$scratch/alice.log" "$scratch/bob.log"; do
            if [[ -f "$log" ]]; then tail -n 10 "$log" >&2; fi
        done
    fi
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf -- "$scratch"
    exit "$result"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

field() {
    awk -v field="$1" '$1 == field {print $2}'
}

wait_for() {
    local attempt
    for ((attempt = 0; attempt < 100; attempt++)); do
        if "$@"; then return; fi
        sleep .2
    done
    printf 'Timed out waiting for %s\n' "$1" >&2
    return 1
}

owner="$scratch/owner"
alice="$scratch/alice"
bob="$scratch/bob"
authority=$("$howl" enrollment init "$owner" "$scratch/offline-keys")
account=$(field Account <<< "$authority")
head=$(field Authority <<< "$authority")
designation=$(field Designation <<< "$authority")

enroll() {
    local state=$1 name=$2 identity fingerprint endpoint
    identity=$("$howl" enrollment identity "$state" "$scratch/$name-exchange")
    fingerprint=$(field Fingerprint <<< "$identity")
    endpoint=$(field Endpoint <<< "$identity")
    [[ "$endpoint" =~ ^[a-f0-9]{64}$ ]]
    "$howl" enrollment offer "$owner" "$scratch/$name-exchange" "$fingerprint" 1 "$scratch/$name-invitation" >/dev/null
    "$howl" enrollment respond "$state" "$scratch/$name-exchange" "$account" "$head" "$designation" "$scratch/$name-invitation" >/dev/null
    "$howl" enrollment certify "$owner" "$scratch/$name-exchange" >/dev/null
    "$howl" enrollment accept "$state" "$scratch/$name-exchange" "$account" "$head" "$designation" >/dev/null
    printf '%s\n' "$endpoint"
}

enroll "$owner" owner >/dev/null
alice_endpoint=$(enroll "$alice" alice)
bob_endpoint=$(enroll "$bob" bob)
"$howl" enrollment peer "$owner" "$scratch/alice-exchange" >/dev/null
"$howl" enrollment peer "$owner" "$scratch/bob-exchange" >/dev/null
"$howl" enrollment peer "$alice" "$scratch/bob-exchange" >/dev/null
"$howl" enrollment peer "$bob" "$scratch/alice-exchange" >/dev/null
alice_device=$("$howl" identity show "$alice" | field Device)
bob_device=$("$howl" identity show "$bob" | field Device)
roster=$("$howl" roster issue "$owner" - active "$alice_device:3" "$bob_device:3")
channel=$(field Channel <<< "$roster")
proof=$(field Proof <<< "$roster")
"$howl" roster apply "$alice" "$channel" "$proof" >/dev/null
"$howl" roster apply "$bob" "$channel" "$proof" >/dev/null

for credential in postgres-admin postgres-owner postgres-runtime state-key audience; do
    openssl rand -hex 32 > "$scratch/$credential"
done
cat > "$HOWL_BETA_RELAY_CONFIG" <<TOML
http_bind_addr = "127.0.0.1:3340"
enable_metrics = false
enable_quic_addr_discovery = false
access.allowlist = ["$alice_endpoint", "$bob_endpoint"]
[limits.client.rx]
bytes_per_second = 65536
max_burst_bytes = 8192
TOML

compose build api
compose up --wait --wait-timeout 90 postgres
bash "$directory/database.sh" bootstrap
compose run --rm operator --migrate
compose run --rm operator --pin-enrollment 900001 "$account" "$head" "$designation"
compose up -d api relay gateway
api="http://$(compose port postgres 18080)"
relay="http://$(compose port postgres 13340)"
status() {
    [[ "$(curl --noproxy '*' --silent --max-time 2 --output /dev/null --write-out '%{http_code}' "$api/$1")" = "$2" ]]
}
wait_for status healthz 204
status v1/auth/session 401
mailbox_status=$(curl --noproxy '*' --silent --max-time 2 --output /dev/null --write-out '%{http_code}'     --header 'Content-Type: application/json' --data '{"after":0,"limit":1}' "$api/v1/mailbox/fetch")
[[ "$mailbox_status" = 401 ]]

"$howl" mesh run "$alice" - "$relay" > "$scratch/alice.log" 2>&1 &
alice_pid=$!
"$howl" mesh run "$bob" - "$relay" > "$scratch/bob.log" 2>&1 &
bob_pid=$!
wait_for grep -q '^Ready ' "$scratch/alice.log"
wait_for grep -q '^Ready ' "$scratch/bob.log"

delivered() {
    "$howl" status "$alice" "$channel" "$1" | grep -q ' delivered '
}

first=$(printf 'Docker private beta online\n' | "$howl" send "$alice" "$channel" "$bob_device" - | field queued)
wait_for delivered "$first"
"$howl" mesh stop "$bob"
wait "$bob_pid"
bob_pid=
second=$(printf 'Docker private beta offline\n' | "$howl" send "$alice" "$channel" "$bob_device" - | field queued)
"$howl" status "$alice" "$channel" "$second" | grep -q ' queued '
"$howl" mesh run "$bob" - "$relay" > "$scratch/bob.log" 2>&1 &
bob_pid=$!
wait_for delivered "$second"
history=$("$howl" read "$bob" "$channel")
[[ "$(grep -c 'Docker private beta online' <<< "$history")" = 1 ]]
[[ "$(grep -c 'Docker private beta offline' <<< "$history")" = 1 ]]

bash "$directory/database.sh" dump howl > "$scratch/howl.dump"
bash "$directory/database.sh" restore howl_restore < "$scratch/howl.dump"
restored=$(compose exec -T postgres psql --no-psqlrc --no-password --username=postgres --dbname=howl_restore --tuples-only --no-align --set=ON_ERROR_STOP=1 --command="SELECT encode(authority_head, 'hex') FROM howl_control.enrollment_pins WHERE github_id = 900001")
[[ "$restored" = "$head" ]]
export HOWL_BETA_DB=howl_restore
compose up -d --force-recreate api
wait_for status healthz 204
printf '%s\n' 'Verified Docker API, PostgreSQL restore, two enrolled devices, a signed roster and relay delivery before and after reconnect.'
