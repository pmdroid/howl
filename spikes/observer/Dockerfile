FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
RUN npm install --global opencode-ai@1.18.33 && npm cache clean --force
COPY probe.mjs /observer/probe.mjs
