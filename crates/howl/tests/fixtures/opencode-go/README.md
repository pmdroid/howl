# Verify OpenCode Go in the Docker observer

Build the pinned fixture and pass its immutable image ID to Howl.

```sh
docker build -t howl-test-opencode-go crates/howl/tests/fixtures/opencode-go
export HOWL_OPENCODE_GO_IMAGE=$(docker image inspect --format '{{.Id}}' howl-test-opencode-go)
export HOWL_OBSERVER_DOCKER_SOCKET=/absolute/path/to/docker.sock
cargo test --locked -p howl --lib opencode_go_streams_from_the_host_broker -- --ignored
```

For the live test, configure an OpenCode Go subscription key in the host environment as `HOWL_OPENCODE_GO_API_KEY`. The test uses `kimi-k3` unless you set `HOWL_OPENCODE_GO_MODEL` to another model on your plan. It sends a short prompt from a disposable repository.

```sh
cargo test --locked -p howl --test managed_acp live_opencode_go -- --ignored
```
