#!/bin/sh
set -eu
exec /usr/local/bin/node /fixture/claude-restricted.mjs "$@"
