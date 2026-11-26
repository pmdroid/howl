# Observer isolation spike

Run the OpenCode fixture with Python 3 and a trusted local Docker engine running Linux with built-in seccomp. Set `HOWL_OBSERVER_DOCKER_SOCKET` to its absolute Unix socket path.

```sh
howl_observer_image_id=$(mktemp)
docker --host "unix://$HOWL_OBSERVER_DOCKER_SOCKET" build --iidfile "$howl_observer_image_id" spikes/observer
python3 spikes/observer/probe.py --socket "$HOWL_OBSERVER_DOCKER_SOCKET" --image "$(cat "$howl_observer_image_id")"
rm "$howl_observer_image_id"
```

The expected output ends with `HOWL_OBSERVER_BOUNDARY_OK`. The probe drives OpenCode over ACP stdio with a loopback model fixture. The harness runs a tool that checks the read-only snapshot, ephemeral scratch, absence of the host credential fixture and Docker socket, process restrictions, and denial of outbound network access.

# SQLCipher packaging spike

Install a C compiler, Make, and Perl for the vendored SQLCipher and OpenSSL build.

```sh
cargo run --manifest-path spikes/observer/Cargo.toml --target-dir target/observer --release --locked
```

The probe prints the linked SQLCipher and OpenSSL versions after reopening an encrypted fixture with the correct key and rejecting missing and incorrect keys. Inspect dynamic dependencies with `ldd` on Linux or `otool -L` on macOS.
