set -euo pipefail

probe=${1:?Pass the absolute path to howl-iroh-spike}
relay=${2:-}
mode=direct
selection='direct=true relay=false selected=direct'
set -- 127.0.0.1:0
if [ -n "$relay" ]; then
    mode=relay=$relay
    selection='direct=false relay=true selected=relay'
    set --
fi
scratch=$(mktemp -d)
listener=
cleanup() {
    if [ -n "$listener" ]; then
        kill "$listener" 2>/dev/null || true
        wait "$listener" 2>/dev/null || true
    fi
    rm -r "$scratch"
}
trap cleanup EXIT

server=$("$probe" keygen "$scratch/server.key")
client=$("$probe" keygen "$scratch/client.key")
if "$probe" keygen "$scratch/server.key" > /dev/null 2>&1; then
    exit 1
fi

for run in 1 2; do
    [ "$("$probe" id "$scratch/server.key")" = "$server" ]
    [ "$("$probe" id "$scratch/client.key")" = "$client" ]
    log=$scratch/server-$run.log
    "$probe" listen "$scratch/server.key" "$mode" "$client" "$@" > "$log" &
    listener=$!
    for _ in $(seq 1 100); do
        grep -qE '^(udp|relay)=' "$log" && break
        sleep 0.1
    done
    grep -qE '^(udp|relay)=' "$log"
    if [ -n "$relay" ]; then
        echo_log=$("$probe" dial "$scratch/client.key" "$mode" "$server")
    else
        addr=$(sed -n 's/^udp=//p' "$log")
        echo_log=$("$probe" dial "$scratch/client.key" "$mode" "$server" "$addr")
    fi
    wait "$listener"
    listener=
    cat "$log"
    printf '%s\n' "$echo_log"
    [[ "$echo_log" == "echo-confirmed peer=$server alpn=howl/transport-spike/1 $selection" ]]
done
