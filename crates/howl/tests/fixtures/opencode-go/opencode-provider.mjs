import { spawn } from "node:child_process";

const [model = "kimi-k3"] = process.argv.slice(2);
if (!/^[a-zA-Z0-9._-]{1,128}$/.test(model)) {
  throw new Error("Invalid OpenCode Go model identifier");
}

const config = {
  model: `howl-go/${model}`,
  small_model: `howl-go/${model}`,
  enabled_providers: ["howl-go"],
  autoupdate: false,
  share: "disabled",
  permission: {
    "*": "deny",
    read: "allow",
    list: "allow",
    glob: "allow",
    grep: "allow",
  },
  provider: {
    "howl-go": {
      name: "Howl OpenCode Go",
      npm: "@ai-sdk/openai-compatible",
      options: {
        baseURL: "http://127.0.0.1:17861/v1",
        apiKey: "howl-guest-opencode-go",
      },
      models: {
        [model]: { name: model, limit: { context: 128000, output: 8192 } },
      },
    },
  },
};

const agent = spawn("/opt/howl-opencode/node_modules/.bin/opencode", ["acp"], {
  stdio: "inherit",
  env: {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: "/scratch",
    TMPDIR: "/scratch",
    OPENCODE_CONFIG_CONTENT: JSON.stringify(config),
    OPENCODE_DISABLE_PROJECT_CONFIG: "true",
    OPENCODE_DISABLE_MODELS_FETCH: "true",
    OPENCODE_DISABLE_LSP_DOWNLOAD: "true",
    OPENCODE_DISABLE_DEFAULT_PLUGINS: "true",
  },
});
agent.on("exit", (code) => { process.exitCode = code ?? 1; });
