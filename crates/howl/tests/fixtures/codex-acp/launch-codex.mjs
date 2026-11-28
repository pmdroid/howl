import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function runCodex(mode) {
  const [model] = process.argv.slice(2);
  if (process.argv.length !== 3 || !/^[a-zA-Z0-9._-]{1,128}$/.test(model ?? "")) {
    throw new Error("usage: /usr/local/bin/node /fixture/codex-wrapper.mjs MODEL");
  }
  if (process.env.HOME !== "/scratch" || process.cwd() !== "/workspace") {
    throw new Error("Codex ACP requires its isolated observer workspace");
  }

  const provider = "howl_broker";
  const profile = `
  model = "${model}"
  model_provider = "${provider}"
  web_search = "disabled"

  [analytics]
  enabled = false

  [feedback]
  enabled = false

  [otel]
  exporter = "none"
  metrics_exporter = "none"
  trace_exporter = "none"

  [model_providers.${provider}]
  name = "Howl observer model broker"
  base_url = "http://127.0.0.1:17861/v1"
  wire_api = "responses"
  env_key = "HOWL_CODEX_BROKER_KEY"
  requires_openai_auth = false
  supports_websockets = false
  request_max_retries = 0
  stream_max_retries = 0
  `;
  mkdirSync("/scratch/.codex", { recursive: true, mode: 0o700 });
  writeFileSync("/scratch/.codex/config.toml", profile, { flag: "wx", mode: 0o600 });

  const env = {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    LANG: "C.UTF-8",
    NO_BROWSER: "1",
    INITIAL_AGENT_MODE: mode,
    MODEL_PROVIDER: provider,
    HOWL_CODEX_BROKER_KEY: "howl-local",
  };
  for (const name of ["HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]) {
    if (process.env[name]) env[name] = process.env[name];
  }
  const executable = fileURLToPath(new URL("node_modules/@agentclientprotocol/codex-acp/dist/index.js", import.meta.url));
  process.execve(process.execPath, [process.execPath, executable], env);
}
