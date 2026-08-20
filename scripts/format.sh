#!/usr/bin/env sh
set -e

if ! command -v stylua >/dev/null 2>&1; then
    echo "error: stylua is not installed." >&2
    echo "Install it with one of:" >&2
    echo "  brew install stylua" >&2
    echo "  cargo install stylua" >&2
    exit 1
fi

if [ "$1" = "--check" ]; then
    stylua --check --config-path .stylua.toml zab.lua
else
    stylua --config-path .stylua.toml zab.lua
fi