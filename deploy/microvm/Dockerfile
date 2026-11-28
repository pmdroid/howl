ARG CODEX_ROOTFS=base
FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d AS base
RUN apt-get update && apt-get install -y --no-install-recommends git iproute2 kmod && rm -rf /var/lib/apt/lists/*
WORKDIR /fixture
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force

FROM debian:bookworm-slim AS vsock
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY vsock.c /vsock.c
RUN gcc -static -Os -Wall -Wextra -Werror -o /howl-vsock /vsock.c

FROM ${CODEX_ROOTFS} AS guest
COPY --chmod=755 init /init
COPY howl-model /etc/howl-model
COPY worker.cjs codex-guest.mjs launch-codex.mjs provider-bridge.cjs /fixture/
COPY --from=vsock /howl-vsock /fixture/howl-vsock

FROM debian:bookworm-slim AS packer
RUN apt-get update && apt-get install -y --no-install-recommends cpio gzip && rm -rf /var/lib/apt/lists/*
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
COPY modules.cpio.gz /modules.cpio.gz
RUN --mount=type=bind,from=guest,target=/guest cd /guest && find . -xdev -print0 | cpio --null -o -H newc | gzip -1 > /initramfs.cpio.gz
RUN if test -s /modules.cpio.gz; then mkdir /modules && cd /modules && gzip -dc /modules.cpio.gz | cpio -id --no-absolute-filenames 'usr/lib/modules/*' './usr/lib/modules/*' 'lib/modules/*' './lib/modules/*' && test -n "$(find . -type f -print -quit)" && find . -print0 | cpio --null -o -H newc | gzip -1 >> /initramfs.cpio.gz; fi

FROM scratch
COPY --from=packer /initramfs.cpio.gz /
