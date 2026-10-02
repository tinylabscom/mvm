# mvm — Firecracker MicroVM Development Tool
# https://github.com/casey/just
#
# The top level is the short set that mirrors CI one-to-one.
# Everything else lives in a module under just/ — one theme per
# module, invoked as `just <module>::<recipe>`. `just --list` shows
# the whole surface: modules collapse to a single line each.

set dotenv-load := false

mod check 'just/check/mod.just'
mod sdk 'just/sdk/mod.just'
mod tests 'just/tests/mod.just'
mod bdd 'just/bdd/mod.just'
mod e2e 'just/e2e/mod.just'
mod payload 'just/payload/mod.just'
mod kernel 'just/kernel/mod.just'
mod lints 'just/lints/mod.just'
mod release 'just/release/mod.just'
mod site 'just/site/mod.just'
mod maint 'just/maint/mod.just'
mod audit 'just/audit/mod.just'
mod mem 'just/mem/mod.just'
mod lab 'just/lab/mod.just'

# Default recipe - show help
default:
    @just --list


# Build all crates (debug), including the per-VM host helpers `mvmctl` spawns.
#
# The native per-VM helpers are separate bin targets. The optional libkrun
# integration has its own explicit recipe `libkrun-supervisor`.
#
# Build all crates (debug).
build:
    ./scripts/cargo-fast.sh build --workspace


# ── Testing (nextest) ────────────────────────────────────────────────────
# Run all tests, keeping the full output at target/nextest/last-run.log.
#
# An intermittent failure in a suite this size is only diagnosable from the
# panic and captured streams nextest prints beside it, and those survive
# nowhere by default — a dev who hits one has terminal scrollback at best,
# and anyone piping this through `grep` has already discarded the part that
# mattered. `tee` costs nothing and leaves the evidence under target/, which
# is gitignored and never uploaded, so this says nothing about the CI-artifact
# question that .config/nextest.toml settles deliberately.
#
# `pipefail` is load-bearing: without it the recipe reports `tee`'s status and
# a failing suite exits 0, which is the exact silent-green this whole change
# ── Testing (nextest) ────────────────────────────────────────────────────
# Run all tests, keeping the full output at target/nextest/last-run.log.
# An intermittent failure in a suite this size is only diagnosable from the
# panic and captured streams nextest prints beside it, and those survive
# nowhere by default — a dev who hits one has terminal scrollback at best,
# and anyone piping this through `grep` has already discarded the part that
# mattered. `tee` costs nothing and leaves the evidence under target/, which
# is gitignored and never uploaded, so this says nothing about the CI-artifact
# question that .config/nextest.toml settles deliberately.
# `pipefail` is load-bearing: without it the recipe reports `tee`'s status and
# a failing suite exits 0, which is the exact silent-green this whole change
# is trying to remove.

# Usage: just test [FILTER]
#   FILTER: optional test filter expression (e.g., "my_test" or "test(my_*)")

# Run all tests with nextest
test FILTER="":
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/require-nextest.sh
    mkdir -p target/nextest
    if [ -n "{{ FILTER }}" ]; then
    ./scripts/cargo-fast.sh nextest run --workspace -E 'test({{ FILTER }})' 2>&1 | tee target/nextest/last-run.log
    else
    ./scripts/cargo-fast.sh nextest run --workspace 2>&1 | tee target/nextest/last-run.log
    fi


# Build an mvmctl that carries the Linux host binaries the builder VM needs,
# plus the native per-VM helpers it spawns beside the resulting executable.
#
# Not required to boot a VM: `cargo build --release` embeds the host binaries by
# default, and an mvmctl built without them builds them itself the first time
# it needs a builder VM. This recipe does both halves in one go and embeds in a
# debug build too. Note that it and a plain `cargo build` write the same
# `target/<profile>/mvmctl` under different feature sets, so alternating the two

# relinks mvmctl; that is why this is a deliberate step and not part of `build`.
# Bare, this writes `target/debug/mvmctl` — pass `--release` if the mvmctl you
# invoke is the release one, or the release binary is left untouched.
#

# Build an mvmctl carrying the embedded Linux host binaries (--release for a release one)
embed *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    # Make rust-objcopy able to load libLLVM, or the strip step aborts and every
    # binary this recipe links is emitted unstripped.
    source "{{justfile_directory()}}/scripts/macos-objcopy-env.sh" "{{justfile_directory()}}"
    # `mvmctl` and these `[[bin]]` targets live in different packages, so
    # building one does not cause Cargo to build the others. Forward the same
    # profile arguments (`--release`, `--profile ...`) so runtime's adjacent-
    # executable lookup always finds the helper matching the selected mvmctl.
    ./scripts/cargo-fast.sh build -p mvm-hostd --bins {{ARGS}}
    ./scripts/cargo-fast.sh build -p mvm-gpu --bin mvm-gpu-endpoint {{ARGS}}
    # The default embeds the host binaries alone. bin/dev overrides this to
    # "embed-host-bins,dev" so the binary it runs carries the contributor
    # surface (manifest-verify included) and can verify published image-set
    # signatures during bootstrap. Any surface carrying manifest-verify must
    # build with plain cargo: the fast-codegen config wrapper leaves the
    # verifier's native aws-lc symbols unresolved on macOS.
    FEATURES="${MVM_EMBED_FEATURES:-embed-host-bins}"
    case ",$FEATURES," in
      *,dev,*|*,user,*) CARGO=(cargo) ;;
      *) CARGO=(./scripts/cargo-fast.sh) ;;
    esac
    "${CARGO[@]}" build --features "$FEATURES" {{ARGS}}


# Lint all: fmt-check + clippy + clippy-bdd + model gates
# Usage: just lint [subset]
#   subset: subset of checks (fmt, clippy, clippy-bdd, model)
lint SUBSET="all":
    case "{{ SUBSET }}" in
    fmt) just lints::fmt-check ;;
    clippy) just lint::clippy ;;
    clippy-bdd) just lints::clippy-bdd ;;
    model) just lint::model ;;
    all)
    just lints::fmt-check
    just lints::clippy
    just lints::clippy-bdd
    just lints::model
    just check::fast-cargo
    ;;
    *)
    echo "Unknown lint subset: {{ SUBSET }}" >&2
    echo "Valid subsets: fmt, clippy, clippy-bdd, model, all" >&2
    exit 1
    ;;
    esac


# ── CI Gate ──────────────────────────────────────────────────────────────

# Full CI gate: lint + test + doctests + hermetic BDD + model gates.
ci: lint test (tests::doc) (bdd::run)


# Build optimized release binary. `embed-host-bins` matches the release
# workflow's `MVMCTL_RELEASE_FEATURES`; without it this produces the one build
# that looks finished and cannot bootstrap a builder VM. `release-channel` is
# deliberately absent — it would resolve artifacts from the published channel
# rather than this checkout.
release-build:
    cargo build --release --features host,user,template-registry-s3,release-artifact-bootstrap,embed-host-bins

# Build the documentation site (stages the /demo wasm assets first if missing)
docs:
    @just site::build
