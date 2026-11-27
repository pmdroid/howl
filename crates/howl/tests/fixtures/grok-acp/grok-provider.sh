set -eu
umask 077

model=${1:-grok-4.7}
case "$model" in
  *[!a-zA-Z0-9._-]*)
    echo "Invalid Grok model identifier" >&2
    exit 1
    ;;
esac

export GROK_HOME=/scratch/howl-grok
export GROK_MODELS_BASE_URL=http://127.0.0.1:17861/v1
unset HOWL_XAI_API_KEY
export XAI_API_KEY=howl-local-grok
export GROK_FEEDBACK_ENABLED=0
mkdir -p "$GROK_HOME"

cat > "$GROK_HOME/config.toml" <<CONFIG
[models]
default = "howl-grok"

[model.howl-grok]
model = "$model"
name = "Howl Grok"
api_backend = "chat_completions"
base_url = "http://127.0.0.1:17861/v1"
env_key = "XAI_API_KEY"

[cli]
auto_update = false
CONFIG

/usr/local/bin/node -e '
const net = require("node:net");
const deadline = Date.now() + 5000;
function waitForBroker() {
  const socket = net.connect(17861, "127.0.0.1");
  socket.once("connect", () => socket.end());
  socket.once("error", () => {
    if (Date.now() >= deadline) {
      console.error("Grok provider broker is unavailable");
      process.exitCode = 1;
    } else {
      setTimeout(waitForBroker, 50);
    }
  });
}
waitForBroker();
'

exec /usr/local/bin/grok --no-auto-update --model howl-grok agent stdio --leader-socket /scratch/grok.sock
