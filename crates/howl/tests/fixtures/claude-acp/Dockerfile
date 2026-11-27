FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
WORKDIR /fixture
ARG TARGETARCH
RUN set -eu; case "$TARGETARCH" in amd64) arch=x64; digest=5ba71f9005177f11b231bf15d464d2444d3cb8bc0f9bb7094d88dc051da7a8c5 ;; arm64) arch=arm64; digest=44b251fe102f2ba5c50fd458be4a8f980afe34dafac393368f51d129e0ae2a65 ;; *) exit 1 ;; esac; \
    node -e 'const { pipeline } = require("node:stream/promises"); const { Readable } = require("node:stream"); const { createWriteStream } = require("node:fs"); fetch(process.argv[1]).then(r => { if (!r.ok || !r.body) throw new Error("Claude ACP release download failed"); return pipeline(Readable.fromWeb(r.body), createWriteStream("/tmp/claude-acp.tar.gz")); }).catch(() => { process.exitCode = 1; });' "https://github.com/agentclientprotocol/claude-agent-acp/releases/download/v0.112.0/claude-agent-acp-linux-$arch.tar.gz"; \
    echo "$digest  /tmp/claude-acp.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/claude-acp.tar.gz -C /fixture; \
    test -x /fixture/claude && test -x /fixture/claude-agent-acp; \
    rm /tmp/claude-acp.tar.gz; \
    install -d -m 700 -o 65532 -g 65532 /claude-profile; \
    install -m 600 -o 65532 -g 65532 /dev/null /claude-profile/.howl-profile
COPY --chmod=555 claude-agent.sh claude-restricted.sh claude-restricted.mjs /fixture/
COPY managed-settings.json /etc/claude-code/managed-settings.json
WORKDIR /workspace
