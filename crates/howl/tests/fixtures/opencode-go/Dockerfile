FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
WORKDIR /opt/howl-opencode
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
RUN --network=none node node_modules/opencode-ai/postinstall.mjs && npm cache clean --force
COPY opencode-provider.mjs /usr/local/share/howl/opencode-provider.mjs
WORKDIR /workspace
