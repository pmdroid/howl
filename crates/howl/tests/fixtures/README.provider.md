# Sandboxed provider smoke tests

Build the pinned harness images on a Linux Docker engine and pass their immutable image IDs to the host test runner.

```sh
docker build -t howl-test-codex crates/howl/tests/fixtures/codex-acp
docker build -t howl-test-grok crates/howl/tests/fixtures/grok-acp
export HOWL_CODEX_IMAGE=$(docker image inspect --format '{{.Id}}' howl-test-codex)
export HOWL_GROK_IMAGE=$(docker image inspect --format '{{.Id}}' howl-test-grok)
```

Set `HOWL_OBSERVER_DOCKER_SOCKET` to the absolute path of the local Linux engine socket. Run the synthetic provider test from the host.

```sh
cargo test --locked -p howl --lib both_brokered_harnesses_stream_from_a_host_fixture -- --ignored
```

For a live test, supply the provider keys through the host environment using `HOWL_OPENAI_API_KEY` and `HOWL_XAI_API_KEY`. Set `HOWL_CODEX_MODEL` to the approved OpenAI model ID and set `HOWL_GROK_MODEL` to the approved xAI model ID if it differs from `grok-4.7`. The test sends a one-word prompt from a disposable snapshot.

```sh
cargo test --locked -p howl --test managed_acp live_brokered_ -- --ignored --test-threads=1
```

## Codex with a ChatGPT plan

Use Node.js 24 or newer on the host. Sign in with ChatGPT once to authorize Howl. Choose an absolute directory outside the repository for the credential store.

```sh
export HOWL_CHATGPT_NODE=$(command -v node)
export HOWL_CHATGPT_STORE="$HOME/.local/share/howl/chatgpt-auth"
"$HOWL_CHATGPT_NODE" tools/chatgpt-auth/chatgpt-auth.mjs sign-in "$HOWL_CHATGPT_STORE"
"$HOWL_CHATGPT_NODE" tools/chatgpt-auth/chatgpt-auth.mjs models "$HOWL_CHATGPT_STORE"
```

Set `HOWL_CODEX_MODEL` to a model from the returned list. Use the pinned Codex image and Docker socket from the previous steps, then run the subscription-backed smoke test.

```sh
cargo test --locked -p howl --test managed_acp live_chatgpt_plan_codex -- --ignored
```
