#!/usr/bin/env bash
# Source this to enter the dev env for a worktree.
# Sets MVM_DATA_DIR to a worktree-local directory so mvmctl's
# registry/cache writes don't stomp on the main checkout.
export MVM_DATA_DIR="${MVM_DATA_DIR:-$PWD/.mvm-test}"
export MVM_NO_LEGACY_BANNER=1
