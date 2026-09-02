#!/usr/bin/env bash
# Reclaim a CARGO_TARGET_DIR inherited from a different source tree.
#
# The compile-time version of the stale-helper bug: cargo decides a cached
# artifact is fresh by comparing source mtimes, and fingerprints embed
# absolute paths. A CARGO_TARGET_DIR exported in a shell that belonged to
# another worktree — or to non-repo work like an issuer build — is silently
# inherited by every cargo invocation in this tree. The failure it produces
# is an E0063 naming a field that exists in none of the sources being
# compiled: rustc type-checked this tree against metadata from an rlib built
# from a different revision, where the field still existed. Nothing about
# the message says the cache lied.
#
# Sourced by the cargo wrapper scripts (cargo-fast.sh, cargo-stable.sh)
# before they resolve the target dir. The reclaim mirrors scripts/dev-env.sh:
# a value already inside this worktree is a real override and is honored; a
# value pointing anywhere else — another worktree, a sibling shared dir, a
# relative path that resolves per-cwd — is reclaimed, loudly.
# MVM_DEV_ENV_KEEP_INHERITED=1 keeps the inherited value anyway.
#
# Only CARGO_TARGET_DIR is claimed here. A shared CARGO_HOME costs lock
# contention, not wrong artifacts; a shared MVM_HOME is a runtime-state
# concern the runtime already guards.

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    _cargo_target_guard_root=$(
        CDPATH="" cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd
    )
    case "${CARGO_TARGET_DIR}" in
        "${_cargo_target_guard_root}"/*) ;;
        *)
            if [ -n "${MVM_DEV_ENV_KEEP_INHERITED:-}" ]; then
                printf 'cargo-target-dir-guard: keeping inherited CARGO_TARGET_DIR=%s (outside %s)\n' \
                    "${CARGO_TARGET_DIR}" "${_cargo_target_guard_root}" >&2
            else
                printf 'cargo-target-dir-guard: CARGO_TARGET_DIR=%s points outside this source tree — reclaiming to %s/target (MVM_DEV_ENV_KEEP_INHERITED=1 keeps it)\n' \
                    "${CARGO_TARGET_DIR}" "${_cargo_target_guard_root}" >&2
                export CARGO_TARGET_DIR="${_cargo_target_guard_root}/target"
            fi
            ;;
    esac
    unset _cargo_target_guard_root
fi
