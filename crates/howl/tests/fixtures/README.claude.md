# Native Claude Code Docker smoke test

Build the pinned Claude Code and ACP overlay image, then use its immutable ID. Set `HOWL_OBSERVER_DOCKER_SOCKET` to the absolute path of your local Linux Docker engine socket.

```sh
export DOCKER_HOST="unix://$HOWL_OBSERVER_DOCKER_SOCKET"
docker build -t howl-test-claude crates/howl/tests/fixtures/claude-acp
export HOWL_CLAUDE_IMAGE=$(docker image inspect --format '{{.Id}}' howl-test-claude)
export HOWL_CLAUDE_PROFILE=subscription-smoke
```

For a new profile, create a dedicated Docker volume and sign in directly with native Claude Code. Run these commands in a terminal so Claude Code can prompt you to finish sign-in.

```sh
volume="howl-claude-$HOWL_CLAUDE_PROFILE"
docker volume create --label "com.howl.native-claude=$HOWL_CLAUDE_PROFILE" "$volume"
docker run --rm -it --name "$volume" --pull=never --read-only --log-driver=none \
  --cap-drop=ALL --security-opt=no-new-privileges --user=65532:65532 \
  --tmpfs=/scratch:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700 \
  --env=HOME=/scratch --env=TMPDIR=/scratch --env=CLAUDE_CONFIG_DIR=/claude-profile \
  --mount="type=volume,src=$volume,dst=/claude-profile" \
  --entrypoint=/fixture/claude "$HOWL_CLAUDE_IMAGE" auth login --claudeai
```

Run the smoke test from the host. The managed container uses the dedicated Claude profile and reads a selected file from a disposable repository snapshot.

```sh
cargo test --locked -p howl --test claude_native live_native_claude -- --ignored
```
