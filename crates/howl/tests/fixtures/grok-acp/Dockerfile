FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
RUN npm install --global @xai-official/grok@1.0.92
COPY grok-provider.sh /usr/local/share/howl/grok-provider.sh
WORKDIR /workspace
