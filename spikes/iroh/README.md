# Native iroh transport probe

Build the probe with the repository toolchain. The crate locks iroh 1.5.0 and uses its `tls-ring` feature.

```sh
cargo build --locked --manifest-path spikes/iroh/Cargo.toml
cargo test --locked --manifest-path spikes/iroh/Cargo.toml
PROBE="$PWD/spikes/iroh/target/debug/howl-iroh-spike"
```

## Loopback

Run the restart check over direct QUIC. It starts each endpoint twice, verifies that the key files still yield the same endpoint IDs, and checks the echoed payload and selected path.

```sh
bash spikes/iroh/test-transport.sh "$PROBE"
```

Start [iroh-relay 1.5.0](https://github.com/n0-computer/iroh/releases/tag/v1.5.0) in one terminal for the TCP relay check.

```sh
iroh-relay --dev --config-path spikes/iroh/relay-loopback.toml
```

Run the same restart check through the relay in a second terminal. Both endpoints use relay-only transport and disable QUIC address discovery.

```sh
bash spikes/iroh/test-transport.sh "$PROBE" http://127.0.0.1:3340
```

## Two networks

On each host, create a key file in a private directory. Exchange the printed endpoint IDs and set `PEER` to the other host's ID. Keep the file for repeat runs. The key creation command refuses to overwrite an existing file.

```sh
KEY_DIR=$(mktemp -d)
KEY="$KEY_DIR/endpoint.key"
"$PROBE" keygen "$KEY"
```

Choose a relay URL reachable from both networks. Start the listener and wait for it to print `relay=`. Then run the dial command on the other network. The listing and confirmation report the negotiated ALPN and the selected path after the exchange.

```sh
RELAY=https://use1-1.relay.n0.iroh.link
"$PROBE" listen "$KEY" "relay=$RELAY" "$PEER"
```

```sh
RELAY=https://use1-1.relay.n0.iroh.link
"$PROBE" dial "$KEY" "relay=$RELAY" "$PEER"
```

Repeat with `auto=$RELAY` to enable direct UDP and relay fallback. For a reachable peer UDP socket, pass its IP and port as the last argument to `dial`. To test a direct-only path, use `direct` on both sides. Pass the listener socket as the last argument to `listen` and its reachable IP and port as the last argument to `dial`.

Restart the listener and redial with the same `KEY` values. Use `"$PROBE" id "$KEY"` to compare IDs across restarts. Save each endpoint's output, the network topology, and any UDP filtering rules used for the run.

## Relay ports

For a TLS relay, configure an HTTPS listener and a certificate for the relay's DNS name. Permit TCP 443 and WebSocket upgrades through any reverse proxy. If the deployment enables iroh's QUIC address discovery, also expose UDP 7842 and set `enable_quic_addr_discovery = true` in the relay config. Assign the HTTPS URL to `RELAY` on both networks. The relay config and port defaults are maintained upstream. [iroh-relay 1.5.0 config](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/main.rs)
