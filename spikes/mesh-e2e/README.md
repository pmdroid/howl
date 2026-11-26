# Two-network mesh verification

Run from an Apple Silicon Mac with a local Docker engine. Build the native and Linux binaries from the same checkout using Rust 1.100.

```sh
proof=$(mktemp -d /private/tmp/howl-mesh-build.XXXXXX)
mkdir "$proof/linux"
docker run --rm \
  -v "$PWD:/repo:ro" -v "$proof/linux:/out" \
  -e CARGO_HOME=/out/cargo -e CARGO_TARGET_DIR=/out/target \
  -w /repo rust:1.100 cargo build --locked -p howl --bin howl
CARGO_TARGET_DIR="$proof/mac" cargo build --locked -p howl --bin howl --example proof_tamper
curl -fL https://github.com/n0-computer/iroh/releases/download/v1.5.0/iroh-relay-v1.5.0-aarch64-unknown-linux-gnu.tar.gz \
  -o "$proof/relay.tar.gz"
HOWL_RELAY_ARCHIVE="$proof/relay.tar.gz" bash spikes/mesh-e2e/proof.sh \
  "$proof/linux/target/debug/howl" "$proof/mac/debug/howl" "$proof/mac/debug/examples/proof_tamper"
```

The runner verifies the relay archive checksum, then starts two isolated Linux network bridges joined by a local relay. It checks delivery, a visible retry while the receiver is down, queued state across both daemon restarts, and one inbox record per message. A second run exchanges chat directly between Linux and macOS. Both check signed manifest rejection. The direct run also checks rejection of a corrupted envelope without an acknowledgment or inbox record.
