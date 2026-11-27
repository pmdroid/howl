FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
WORKDIR /opt/howl-mcp-interop
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY client.mjs verify.mjs ./
ENTRYPOINT ["node", "/opt/howl-mcp-interop/verify.mjs"]
