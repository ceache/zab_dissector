#!/usr/bin/env sh
set -e

if ! command -v luacheck >/dev/null 2>&1; then
    echo "error: luacheck is not installed." >&2
    echo "Install it with one of:" >&2
    echo "  luarocks install luacheck" >&2
    echo "  brew install luacheck" >&2
    exit 1
fi

luacheck zab.lua --config .luacheckrc