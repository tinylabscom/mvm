#!/bin/sh
# Wrapper for aarch64-unknown-linux-gnu cross-links on macOS.
# Rust's default target spec passes -Wl,--fix-cortex-a53-843419, which
# zig cc does not support, so strip it and delegate to zig cc.
set -e
filtered=""
for arg in "$@"; do
    case "$arg" in
        --fix-cortex-a53-843419 | -Wl,--fix-cortex-a53-843419) ;;
        *) filtered="$filtered $arg" ;;
    esac
done
exec zig cc -target aarch64-linux-gnu $filtered
