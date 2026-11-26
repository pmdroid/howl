set -euo pipefail

linux=${1:?Usage: bash proof.sh /absolute/linux/howl [/absolute/macos/howl] [/absolute/tamper]}
mac=${2:-}
tamper=${3:-}
archive=${HOWL_RELAY_ARCHIVE:?Set HOWL_RELAY_ARCHIVE to the iroh-relay 1.5.0 ARM64 Linux GNU archive}
image=${HOWL_TEST_IMAGE:-rust:1.100}
scratch=$(mktemp -d /private/tmp/hwl-2506.XXXXXX)
prefix=howl-2506-$$
left=$prefix-left
right=$prefix-right
alice_container=$prefix-a
bob_container=$prefix-b
relay_container=$prefix-r
alice_pid=
bob_pid=
mode=relay

cleanup() {
    result=$?
    trap - EXIT
    if [ "$mode" = direct ] && [ -n "$alice_pid" ]; then
        "$mac" mesh stop "$alice_state" >/dev/null 2>&1 || true
        kill "$alice_pid" 2>/dev/null || true
        wait "$alice_pid" 2>/dev/null || true
    fi
    if [ "$result" -ne 0 ]; then
        for log in "$scratch"/alice.* "$scratch"/bob.*; do
            if [ -f "$log" ]; then
                printf '\n%s\n' "$(basename "$log")" >&2
                tail -n 16 "$log" >&2
            fi
        done
    fi
    docker rm -f "$alice_container" "$bob_container" "$relay_container" >/dev/null 2>&1 || true
    docker network rm "$left" "$right" >/dev/null 2>&1 || true
    rm -r "$scratch"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ -f "$linux" ]
[ -z "$mac" ] || [ -x "$mac" ]
[ -z "$tamper" ] || [ -x "$tamper" ]

alice() {
    if [ "$mode" = direct ]; then
        "$mac" "$@"
    else
        docker exec -i "$alice_container" /howl "$@"
    fi
}

bob() {
    docker exec -i "$bob_container" /howl "$@"
}

field() {
    awk -v key="$1" '$1 == key { print $2; exit }'
}

pair() {
    local a b record manifest damaged suffix joined
    a=$(alice mesh init "$alice_state")
    b=$(bob mesh init "$bob_state")
    alice_device=$(field Device <<< "$a")
    bob_device=$(field Device <<< "$b")
    [ "${#alice_device}" -eq 64 ]
    [ "${#bob_device}" -eq 64 ]
    alice peer add "$alice_state" "$(field Certificate <<< "$b")" "$(field Fingerprint <<< "$b")" >/dev/null
    bob peer add "$bob_state" "$(field Certificate <<< "$a")" "$(field Fingerprint <<< "$a")" >/dev/null
    record=$(alice channel create "$alice_state" "$bob_device")
    channel=$(field Channel <<< "$record")
    manifest=$(field Manifest <<< "$record")
    [ "${#channel}" -eq 64 ]
    [ -n "$manifest" ]
    suffix=${manifest#"${manifest%?}"}
    if [ "$suffix" = 0 ]; then
        damaged=${manifest%?}1
    else
        damaged=${manifest%?}0
    fi
    if joined=$(bob channel join "$bob_state" "$damaged" 2>&1); then
        printf 'Tampered channel manifest was accepted\n' >&2
        return 1
    fi
    printf '%s tampered manifest rejected: %s\n' "$mode" "$joined"
    joined=$(bob channel join "$bob_state" "$manifest")
    [ "$(field Channel <<< "$joined")" = "$channel" ]
    printf '%s channel=%s\n' "$mode" "$channel"
}

wait_log() {
    local log=$1 pattern=$2 duration=$3 minimum=${4:-1}
    local until=$((SECONDS + duration)) count
    while [ "$SECONDS" -lt "$until" ]; do
        count=$(grep -Ec "$pattern" "$log" || true)
        if [ "${count:-0}" -ge "$minimum" ]; then
            return 0
        fi
        sleep 0.2
    done
    printf 'Timed out waiting for %s in %s\n' "$pattern" "$log" >&2
    return 1
}

start_nodes() {
    local who=$1
    if [ "$who" = alice ]; then
        alice_log=$(mktemp "$scratch/alice.XXXXXX")
        if [ "$mode" = direct ]; then
            "$mac" mesh run "$alice_state" 0.0.0.0:0 > "$alice_log" 2>&1 &
        else
            docker exec "$alice_container" /howl mesh run "$alice_state" - "$relay_url" > "$alice_log" 2>&1 &
        fi
        alice_pid=$!
        wait_log "$alice_log" "^Ready $alice_device$" 18
    else
        bob_log=$(mktemp "$scratch/bob.XXXXXX")
        if [ "$mode" = direct ]; then
            docker exec "$bob_container" /howl mesh run "$bob_state" 0.0.0.0:0 > "$bob_log" 2>&1 &
        else
            docker exec "$bob_container" /howl mesh run "$bob_state" - "$relay_url" > "$bob_log" 2>&1 &
        fi
        bob_pid=$!
        wait_log "$bob_log" "^Ready $bob_device$" 18
    fi
}

stop_alice() {
    alice mesh stop "$alice_state"
    wait "$alice_pid"
    alice_pid=
}

stop_bob() {
    bob mesh stop "$bob_state"
    wait "$bob_pid"
    bob_pid=
}

wait_status() {
    local caller=$1 state=$2 id=$3 expected=$4 budget=$5 current
    local until=$((SECONDS + budget))
    while [ "$SECONDS" -lt "$until" ]; do
        current=$("$caller" status "$state" "$channel" "$id")
        case "$current" in
            *" $expected attempts="*) printf '%s\n' "$current"; return 0 ;;
        esac
        sleep 0.3
    done
    printf 'Expected %s for %s, got %s\n' "$expected" "$id" "${current:-no status}" >&2
    return 1
}

queue() {
    local caller=$1 state=$2 peer=$3 target=$4 text=$5 reply id
    reply=$(printf '%s' "$text" | "$caller" send "$state" "$channel" "$peer" "$target") || return
    id=$(field queued <<< "$reply")
    [ "${#id}" -eq 64 ] || return 1
    printf '%s\n' "$id"
}

verify_history() {
    local caller=$1 state=$2 message=$3 history count
    history=$("$caller" read "$state" "$channel")
    count=$(grep -Fc -- "$message" <<< "$history" || true)
    [ "$count" -eq 1 ]
    printf '%s inbox contains exactly one copy of "%s"\n' "$mode" "$message"
}

proof_port() {
    awk '$1 == "Listening" && $2 ~ /^[0-9.]+:[0-9]+$/ {sub(/.*:/, "", $2); print $2; exit}' "$1"
}

[ "$(shasum -a 256 "$archive" | awk '{print $1}')" = 6d2c968389af35a2d6cef8f1eb62b960b13ba0538d2eb628169f0c8cdff94262 ]
tar -xzf "$archive" -C "$scratch"
printf 'http_bind_addr = "0.0.0.0:3340"\nenable_metrics = false\nenable_quic_addr_discovery = false\n' > "$scratch/relay.toml"
relay_url=http://relay-node:3340
docker network create --internal "$left" >/dev/null
docker network create --internal "$right" >/dev/null
docker network inspect "$left" "$right" --format 'isolated={{.Internal}} {{range .IPAM.Config}}{{.Subnet}} {{end}}'
docker run -d --name "$relay_container" --network "$left" --network-alias relay-node -v "$scratch":/relay:ro "$image" /relay/iroh-relay --dev --config-path /relay/relay.toml >/dev/null
docker network connect --alias relay-node "$right" "$relay_container"
docker run -d --name "$alice_container" --network "$left" -v "$linux":/howl:ro "$image" sleep 600 >/dev/null
docker run -d --name "$bob_container" --network "$right" -v "$linux":/howl:ro "$image" sleep 600 >/dev/null
alice_state=/tmp/alice
bob_state=/tmp/bob
pair
start_nodes alice
start_nodes bob
first_text='relay chat across isolated networks'
first_id=$(queue alice "$alice_state" "$bob_device" - "$first_text")
report=$(wait_status alice "$alice_state" "$first_id" delivered 50)
printf 'relay delivery %s %s\n' "$first_id" "$report"
verify_history bob "$bob_state" "$first_text"

stop_bob
prior_failures=$(grep -Ec 'Delivery (will|queued for) retry' "$alice_log" || true)
offline_text='queued while the destination was offline'
offline_id=$(queue alice "$alice_state" "$bob_device" - "$offline_text")
wait_log "$alice_log" 'Delivery (will|queued for) retry' 40 "$((prior_failures+1))"
report=$(wait_status alice "$alice_state" "$offline_id" queued 5)
printf 'relay offline status %s %s\n' "$offline_id" "$report"
grep -E 'Delivery (will|queued for) retry' "$alice_log" | tail -n 1

stop_alice
report=$(wait_status alice "$alice_state" "$offline_id" queued 5)
printf 'persisted outbox after shutdown %s\n' "$report"
start_nodes alice
start_nodes bob
report=$(wait_status alice "$alice_state" "$offline_id" delivered 90)
printf 'relay retry %s %s\n' "$offline_id" "$report"
verify_history bob "$bob_state" "$first_text"
verify_history bob "$bob_state" "$offline_text"
stop_alice
stop_bob
printf 'persisted inbox after shutdown\n'
verify_history bob "$bob_state" "$offline_text"

if [ -n "$mac" ]; then
    docker rm -f "$alice_container" "$bob_container" "$relay_container" >/dev/null
    mode=direct
    alice_state=$scratch/mac
    bob_state=/tmp/bob
    docker run -d --name "$bob_container" -v "$linux":/howl:ro "$image" sleep 600 >/dev/null
    linux_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$bob_container")
    mac_ip=$(docker exec "$bob_container" getent ahostsv4 host.docker.internal | awk 'NR==1 {print $1}')
    [ -n "$linux_ip" ]
    [ -n "$mac_ip" ]
    printf 'direct macOS host gateway=%s Linux bridge=%s\n' "$mac_ip" "$linux_ip"
    pair
    start_nodes alice
    start_nodes bob
    port=$(proof_port "$alice_log")
    [ -n "$port" ]
    direct_text='direct chat from Linux to macOS'
    direct_id=$(queue bob "$bob_state" "$alice_device" "$mac_ip:$port" "$direct_text")
    report=$(wait_status bob "$bob_state" "$direct_id" delivered 45)
    printf 'direct delivery %s %s\n' "$direct_id" "$report"
    verify_history alice "$alice_state" "$direct_text"

    if [ -n "$tamper" ]; then
        stop_alice
        start_nodes alice
        tampered_text='this signed envelope must be rejected'
        tampered_id=$(queue alice "$alice_state" "$bob_device" 127.0.0.1:9 "$tampered_text")
        stop_alice
        bob_port=$(proof_port "$bob_log")
        [ -n "$bob_port" ]
        "$tamper" "$alice_state" "$channel" "$linux_ip:$bob_port"
        wait_log "$bob_log" 'Rejected mesh frame' 10
        grep 'Rejected mesh frame' "$bob_log" | tail -n 1
        report=$(wait_status alice "$alice_state" "$tampered_id" queued 5)
        history=$(bob read "$bob_state" "$channel")
        if grep -Fq "$tampered_text" <<< "$history"; then
            printf 'Tampered envelope appeared in chat history\n' >&2
            exit 1
        fi
        printf 'direct tampered envelope left no ACK or inbox entry: %s\n' "$report"
    else
        stop_alice
    fi
    stop_bob
fi
