set -euo pipefail
umask 077

control=${1:?Usage: bash deploy/private-beta/rehearse.sh /absolute/path/to/howl-control-plane}
[[ "$control" = /* && -x "$control" ]]
host=${DOCKER_HOST:-unix://}
if [[ -n "${DOCKER_CONTEXT:-}" || -z "${DOCKER_HOST:-}" ]]; then
    host=$(docker context inspect "${DOCKER_CONTEXT:-$(docker context show)}" --format '{{.Endpoints.docker.Host}}')
fi
[[ "$host" = unix://* ]]
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/howl-beta.XXXXXXXX")
export HOWL_BETA_PRIVATE_DIR="$scratch"
export HOWL_BETA_POSTGRES_PORT=0
export COMPOSE_PROJECT_NAME="howl-beta-${scratch##*.}"
COMPOSE_PROJECT_NAME=$(printf '%s' "$COMPOSE_PROJECT_NAME" | tr '[:upper:]' '[:lower:]')
api_port=${HOWL_BETA_API_PORT:-18080}
[[ "$api_port" =~ ^[0-9]+$ ]]
base="http://127.0.0.1:$api_port"
control_pid=

compose() {
    docker compose -f "$directory/compose.yaml" "$@"
}

stop_control() {
    if [[ -n "$control_pid" ]]; then
        kill "$control_pid" 2>/dev/null || true
        wait "$control_pid" 2>/dev/null || true
        control_pid=
    fi
}

cleanup() {
    result=$?
    trap - EXIT
    stop_control
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf -- "$scratch"
    exit "$result"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for credential in postgres-admin postgres-owner postgres-runtime; do
    openssl rand -hex 32 > "$scratch/$credential"
done
compose up --wait --wait-timeout 90
bash "$directory/database.sh" bootstrap
published=$(compose port postgres 5432)
[[ "$published" =~ ^127\.0\.0\.1:([0-9]+)$ ]]
port=${BASH_REMATCH[1]}
owner="postgresql://howl_control_owner:$(<"$scratch/postgres-owner")@127.0.0.1:$port/howl"
runtime="postgresql://howl_control_runtime:$(<"$scratch/postgres-runtime")@127.0.0.1:$port"

export HOWL_CONTROL_BIND="127.0.0.1:$api_port"
export HOWL_CONTROL_AUDIENCE
HOWL_CONTROL_AUDIENCE=$(openssl rand -hex 32)
export HOWL_CONTROL_STATE_KEY
HOWL_CONTROL_STATE_KEY=$(openssl rand -hex 32)
export HOWL_GITHUB_CLIENT_ID=fixture
export HOWL_GITHUB_CLIENT_SECRET=local-fixture
account=$(openssl rand -hex 32)
head=$(openssl rand -hex 32)
designation=$(openssl rand -hex 32)
HOWL_CONTROL_DATABASE_URL="$owner" "$control" --migrate
HOWL_CONTROL_DATABASE_URL="$owner" "$control" --migrate
HOWL_CONTROL_DATABASE_URL="$owner" "$control" --pin-enrollment 900001 "$account" "$head" "$designation"

http() {
    curl --noproxy '*' --silent --show-error --max-time 2 "$@"
}

check_api() {
    HOWL_CONTROL_DATABASE_URL="$runtime/$1" "$control" > "$scratch/control.log" 2>&1 &
    control_pid=$!
    local status privileges ready=false
    for ((attempt = 0; attempt < 80; attempt++)); do
        if ! kill -0 "$control_pid" 2>/dev/null; then
            cat "$scratch/control.log" >&2
            return 1
        fi
        status=$(http --output /dev/null --write-out '%{http_code}' "$base/healthz" 2>/dev/null) || true
        if [[ "$status" = 204 ]]; then
            ready=true
            break
        fi
        sleep .1
    done
    [[ "$ready" = true ]]
    status=$(http --dump-header "$scratch/headers" --output /dev/null --write-out '%{http_code}' "$base/v1/auth/session")
    [[ "$status" = 401 ]]
    grep -qi '^cache-control: no-store' "$scratch/headers"
    privileges=$(compose exec -T postgres psql --no-psqlrc --no-password --username=postgres --dbname="$1" --tuples-only --no-align --set=ON_ERROR_STOP=1 --command="SELECT has_table_privilege('howl_control_runtime', 'howl_control.enrollment_pins', 'SELECT') AND NOT has_table_privilege('howl_control_runtime', 'howl_control.enrollment_pins', 'INSERT') AND NOT has_schema_privilege('howl_control_runtime', 'howl_control', 'CREATE')")
    [[ "$privileges" = t ]]
}

check_api howl
bash "$directory/database.sh" dump howl > "$scratch/howl.dump"
stop_control
bash "$directory/database.sh" restore howl_restore < "$scratch/howl.dump"
restored=$(compose exec -T postgres psql --no-psqlrc --no-password --username=postgres --dbname=howl_restore --tuples-only --no-align --set=ON_ERROR_STOP=1 --command="SELECT encode(account_id, 'hex') || ':' || encode(authority_head, 'hex') || ':' || encode(designation_digest, 'hex') FROM howl_control.enrollment_pins WHERE github_id = 900001")
[[ "$restored" = "$account:$head:$designation" ]]
check_api howl_restore
if [[ "${HOWL_BETA_TEST_GITHUB_FIXTURE:-0}" = 1 ]]; then
    HOWL_TEST_CONTROL_DATABASE_OWNER="$owner" HOWL_TEST_CONTROL_DATABASE_RUNTIME="$runtime/howl"         cargo test --manifest-path "$directory/../../Cargo.toml" --locked -p howl-control-plane --lib         device_login_rejects_replays_and_rotates_or_revokes_device_bound_credentials -- --ignored
fi
printf '%s\n' 'Verified loopback API, private PostgreSQL roles, authenticated route rejection and recovery from a database backup.'
