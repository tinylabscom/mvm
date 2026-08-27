# mvm — Firecracker MicroVM Development Tool
# https://github.com/casey/just

set dotenv-load := false

# Extract workspace version from Cargo.toml

version := `grep -A 5 '^\[workspace\.package\]' Cargo.toml | grep '^version' | head -1 | cut -d '"' -f 2`

# Default recipe - show help
default:
    @just --list

# ── Development ──────────────────────────────────────────────────────────

# Wire core.hooksPath at .githooks/ (one-time per clone)
install-hooks:
    # Without this, git falls back to .git/hooks/pre-commit, which may
    # be a stale local copy or the legacy heavy hook. .githooks/pre-commit
    # is intentionally light (cargo fmt + nix fmt --check).
    git config core.hooksPath .githooks
    @echo "core.hooksPath -> .githooks/"

# Provision the pinned cross-compile toolchain the embed step (mvm-cli/build.rs)
# needs: the exact zig from the `ziglang` PyPI package + the musl rust targets.
# Homebrew's `zig` drifts to newer, incompatible releases (fails downstream with
# `CacheCheckFailed`); build.rs auto-detects the `ziglang`-installed zig instead.

# Run once per machine (or after a toolchain pin bump).
toolchain-embed:
    #!/usr/bin/env bash
    set -euo pipefail
    RUST=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['rust'])")
    ZIG=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['zig'])")
    echo "installing pinned Rust ${RUST} + zig ${ZIG} (ziglang) + musl targets"
    python3 -m pip install --quiet "ziglang==${ZIG}"
    rustup toolchain install "${RUST}" --profile minimal
    rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl --toolchain "${RUST}"
    echo "embed toolchain ready: Rust ${RUST} + zig ${ZIG} + aarch64/x86_64 musl targets"

# Build all crates (debug)
build:
    ./scripts/cargo-fast.sh build --workspace

# `--all-targets` is narrower than it sounds: it skips any target behind
# `required-features`, and on macOS it cannot compile `cfg(target_os = "linux")`
# files at all. `check-gated` covers both.
# Type-check without codegen
check:
    ./scripts/cargo-fast.sh check --workspace --all-targets

# Cross-compile every crate's lib for Linux (glibc) via zig — no Docker — so
# cfg(target_os="linux") code a macOS host never compiles is caught locally.
# --all-features reaches feature-gated modules (e.g. libkrun_builder). Lib-only:
# linking the libkrun-sys bins needs target libkrun, which CI provides. Needs
# `cargo install cargo-zigbuild`, a `zig` on PATH, and
# `rustup target add x86_64-unknown-linux-gnu`. musl is intentionally not the
# default — libc's ioctl request arg is c_int there vs c_ulong on glibc, so the
# COW FICLONE path (mvm-runtime) only type-checks against glibc.
# Cross-compile every crate's lib for Linux via zig
check-linux TARGET="x86_64-unknown-linux-gnu":
    ./scripts/cargo-stable.sh zigbuild --target {{ TARGET }} --workspace --lib --all-features

# Type-check the targets `just check` cannot see. Two blind spots, both of which
# have shipped a red CI run that named neither:
#
#   1. `cfg(target_os = "linux")` *test* files. `check-linux` above is --lib
#      only, so a Linux-gated test target is checked by nothing local. This
#      surfaces in CI as `check-nextest-groups` failing with "cargo nextest list
#      failed" — a message that never names the file or the field.
#   2. Targets behind `required-features` (mvm-conformance's cucumber runner).
#      `--all-targets` skips them silently: without `--features bdd` the same
#      broken tree reports zero errors.
#
# `check` rather than a build, so nothing links — that is the constraint that
# forces `check-linux` to stay lib-only. Same prerequisites as `check-linux`
# (cargo-zigbuild, zig on PATH, the rustup target). Note the binary is invoked
# as `cargo-zigbuild check`: `cargo zigbuild check` is a different subcommand
# and errors on the argument.
#
# Not folded into `ci`: it needs a zig toolchain that not every contributor has
# (the same reason `check-linux` is opt-in), and a cold run costs ~8 min because
# it type-checks the whole workspace for a second target. Run it before pushing
# anything that changes a shared type's shape; a warm run is far cheaper.
# Type-check the linux-gated and feature-gated targets `just check` cannot see
check-gated TARGET="x86_64-unknown-linux-gnu":
    ./scripts/cargo-stable.sh --direct cargo-zigbuild check --target {{ TARGET }} --workspace --all-targets
    ./scripts/cargo-stable.sh check -p mvm-conformance --all-targets --features bdd

# Bare-metal no_std proof for the embeddable foundation crate (mvm-contract).
# A `-none-elf` target exposes only core + alloc with no std to leak into, so
# this is a stricter no_std check than the wasm32 gate. riscv32imac is the
# mainline stand-in for the RISC-V microcontrollers the on-device verifier
# targets; lib-only means an rlib with no final link, so no cross-linker is
# needed. Note: riscv32imc parts (no atomics) and Xtensa parts need extra

# shims/toolchains — see specs/notes for the embedding track.
check-embedded TARGET="riscv32imac-unknown-none-elf":
    rustup target add {{ TARGET }}
    cargo build -p mvm-contract --lib --target {{ TARGET }}

# Run mvmctl with arguments
run *ARGS:
    ./scripts/cargo-fast.sh run -- {{ ARGS }}

# Run mvmctl with the dev env set (worktree-local MVM_HOME).
dev *ARGS:
    sh ./scripts/dev {{ ARGS }}

# Run cargo with the dev env set (worktree-local MVM_HOME /

# CARGO_TARGET_DIR / CARGO_HOME).
dev-cargo *ARGS:
    bash -c 'source scripts/dev-env.sh && ./scripts/cargo-fast.sh {{ ARGS }}'

# Run cargo test --workspace with the dev env.
dev-test:
    just dev-cargo test --workspace

# Run clippy with the dev env.
dev-clippy:
    bash -c 'source scripts/dev-env.sh && ./scripts/cargo-stable.sh clippy --workspace -- -D warnings'

# Build the host-side eBPF object for vsock egress telemetry.

# Requires nightly Rust and `cargo install bpf-linker`.
build-ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    cd crates/mvm-hostd/ebpf
    PATH="${HOME}/.cargo/bin:${PATH}" cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

# Run cargo check with the dev env.
dev-check:
    just dev-cargo check --workspace

# Verify that the nightly fast path stays pinned and does not leak into the
# stable-compatible Cargo configuration used by release and MSRV lanes.
check-fast-cargo:
    ./scripts/check-fast-cargo.sh

# Prebuild or refresh the version-matched read-only runtime overlay once so
# later required-overlay boots can reuse it without rebuilding guest binaries

# on the hot path. Pass through extra args like `--force` or `--source download`.
runtime-overlay *ARGS:
    just dev build runtime-overlay build {{ ARGS }}

# Prebuild or refresh the version-matched read-only runtime overlay once so
# later required-overlay boots can reuse it without rebuilding guest binaries

# on the hot path. Kept as a compatibility alias for `just runtime-overlay`.
runtime-overlay-build *ARGS:
    just runtime-overlay {{ ARGS }}

# Build the publishable SDK artifacts without building the full Rust workspace.
sdk-build: sdk-build-python sdk-build-typescript

# Build the Python SDK wheel + sdist into crates/mvm-sdk/sdks/python/dist/.
sdk-build-python:
    uv build crates/mvm-sdk/sdks/python --out-dir crates/mvm-sdk/sdks/python/dist

# Install TypeScript SDK dependencies locally. Run once after a fresh clone or

# whenever package-lock.json changes.
sdk-install-typescript:
    npm --prefix crates/mvm-sdk/sdks/typescript ci

# Build the TypeScript SDK into crates/mvm-sdk/sdks/typescript/dist/.
sdk-build-typescript:
    npm --prefix crates/mvm-sdk/sdks/typescript run build

# Run the language SDKs' own unit suites. Neither is a cargo target, so
# `cargo nextest run --workspace` does not touch them and a Rust-only gate
# leaves the hand-written half of each SDK — the subprocess wrappers, the
# argv builders, the refusal paths — unproven.
sdk-test: sdk-test-python sdk-test-typescript

# `--extra schema` installs pydantic; without it the eight
# `derive_schema` tests fail on an ImportError rather than being skipped.
sdk-test-python:
    uv run --directory crates/mvm-sdk/sdks/python --group dev --extra schema pytest -q

sdk-test-typescript: sdk-install-typescript
    npm --prefix crates/mvm-sdk/sdks/typescript run test

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

# is trying to remove.
test:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/require-nextest.sh
    mkdir -p target/nextest
    ./scripts/cargo-fast.sh nextest run --workspace 2>&1 | tee target/nextest/last-run.log

# Doctests. nextest does NOT run doctests, so `just test` skips them;

# this is the companion that keeps doc-fence coverage gated.
test-doc:
    ./scripts/cargo-fast.sh test --workspace --doc

# Run tests with sccache also caching the workspace crates.
#
# The wrapper itself is not what this recipe adds. `RUSTC_WRAPPER = "sccache"`
# belongs in a contributor's own `~/.cargo/config.toml` (a fact about a host
# that runs many worktrees, not about the project), and there it already caches
# every third-party dependency, because cargo compiles dependencies
# non-incrementally regardless of this setting.
#
# What `CARGO_INCREMENTAL=0` adds is the *workspace* crates, which are the ones
# incremental compilation otherwise keeps out of the cache. That is a good
# trade for a full-suite run — incremental buys nothing when everything is
# being compiled anyway — and a bad one for the inner loop, which is why it is
# scoped to this recipe instead of being set globally.
#
# A content cache, not a build lock, so parallel sessions don't serialize on it.
# Needs `cargo install sccache`.
#
# Do not expect this to dedupe across worktrees. `basedirs` in the host config
# is necessary for that but is NOT sufficient: sccache's key covers the
# rustc command line, which carries the target directory's full path, and every
# worktree has its own. Measured on this host with `basedirs` correctly set,
# building one crate three ways:
#
#   cold, target dir A                       2 hits / 100 misses
#   target dir A wiped and rebuilt          70 hits /  79 misses
#   identical source, target dir B           0 hits / 152 misses
#
# So it pays for re-populating one checkout after `cargo clean`, and pays
# nothing for the second checkout — which is why the machine-wide Rust hit rate
# sits near 2.5% across ~35k compiles rather than the 84% a same-path
# experiment suggests. Cargo already caches deps within a target dir, so the
# remaining value here is narrow.
test-cached:
    @command -v sccache >/dev/null || { echo "sccache not found — install with: cargo install sccache"; exit 1; }
    RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 cargo nextest run --workspace
    @sccache --show-stats

# Test a single crate
test-crate CRATE:
    ./scripts/require-nextest.sh
    ./scripts/cargo-fast.sh nextest run -p {{ CRATE }}

# Run tests matching a filter expression
test-filter FILTER:
    ./scripts/require-nextest.sh
    ./scripts/cargo-fast.sh nextest run --workspace -E 'test({{ FILTER }})'

# Run tests under the `ci` profile: no retries, slow-test warnings, and a
# JUnit report at target/nextest/ci/junit.xml carrying pass/fail structure

# only (no captured test output — see .config/nextest.toml).
test-ci:
    ./scripts/require-nextest.sh
    ./scripts/cargo-fast.sh nextest run --workspace --profile ci

# Run tests with cargo test (fallback if nextest not installed)
test-cargo:
    ./scripts/cargo-fast.sh test --workspace

# BDD conformance suite (cucumber-rs): builds mvmctl and the TypeScript SDK,
# checks generated SDK artifacts, then runs every Gherkin scenario under
# features/suites/ against it. Scenarios tagged `@wip` describe

# not-yet-implemented coverage and are filtered out by the runner.
bdd:
    ./scripts/cargo-fast.sh build --bin mvmctl
    ./scripts/cargo-fast.sh build -p xtask
    just sdk-install-typescript
    just sdk-build-typescript
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" ./scripts/cargo-fast.sh test -p mvm-conformance --test conformance --features bdd

# End-to-end launch gate: boot a real guest through every README-documented
# entry point (CLI verbs, runtime SDK, decorator SDK, Rust library facade) on
# whatever backend this host has. Unlike `bdd-live-ci` this is deliberately NOT
# narrowed to the merge-queue subset and NOT `@firecracker`-gated — that
# narrowing is what left the macOS default backend with no lane that boots a
# guest at all.
#
# Sibling of `e2e-docs`: this one proves the ways in, that one proves the whole
# documented command surface. They overlap in the suite they drive; the split is
# that this lane also exercises the in-process Rust library seam.
#
# Boot a real guest through every documented entry point
e2e-launch:
    ./scripts/e2e-launch-modes.sh

# The hermetic `bdd` lane proves a documented command parses; this one boots
# real microVMs and runs them. Needs an artifact-warm home: it defaults to the
# real `~/.mvm`, override with MVM_E2E_HOME. Expect minutes on a cold home.
#
# Follows each guest's console as it boots; MVM_E2E_FOLLOW=0 silences that.
# Sweeps its own machines on entry and exit — see `e2e-docs-clean`.
#
# Every documented example, executed against a real host
e2e-docs:
    ./scripts/e2e-documented-surface.sh

# Reap machines a killed e2e run left behind. Scoped to the `bdd-` prefix the
# suite creates, so it never touches a machine you made.
#
# Clean up after an interrupted e2e run
e2e-docs-clean:
    ./scripts/e2e-documented-surface.sh --clean-only

# KVM-backed merge-queue witness for the cheap documented machine lifecycle.
# The tag selector keeps registry/build-heavy live scenarios in their dedicated
# witness lanes while proving that the public commands operate a real guest.
bdd-live-ci:
    cargo build --bin mvmctl --features user
    CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl" MVM_BDD_LIVE=1 MVM_BDD_CI_LIVE_ONLY=1 cargo test -p mvm-conformance --test conformance --features bdd

# Build the per-VM host helper bins explicitly. mvmctl's build script already
# compiles them during `cargo build`/`cargo run`; this is the manual route for

# a targeted rebuild or CI.
build-supervisors:
    ./scripts/cargo-fast.sh build -p mvm-hostd --bin mvm-network-endpoint --bin mvm-hvf-supervisor
    ./scripts/cargo-fast.sh build -p mvm-hostd --bin mvm-libkrun-supervisor --features libkrun-sys

# Drop the cached cross-compiled host binaries so the next build rebuilds them.
# Dev builds reuse these instead of re-running cargo-zigbuild, which is ~93% of
# mvm-cli's build-script wall time. Run this after editing anything they link
# (mvm-build, mvm-core, ...) when you are about to boot a real VM; ordinary
# check/test/clippy runs never need it. Release builds always rebuild.
embed-refresh:
    rm -rf target/*/build/mvm-cli-nested-target/host-vm-target

# Build the dm-verity-capable workload kernel into the local mvm cache.
# Set MVM_KERNEL_SOURCE=download to use the hash-verified release artifact, or

# MVM_KERNEL_SOURCE=auto to prefer it and compile when no asset is available.
kernel-workload:
    cargo run -- kernel build --which workload

# Live macOS Apple-Silicon HVF proof for OCI --allow-host:
#  1. exact `machine run --image ... --allow-host ... -- ps aux` path

# 2. admit/deny relay proof over the host-vsock egress endpoint
hvf-oci-allow-host-smoke:
    bash scripts/check-hvf-oci-allow-host-smoke.sh

# Live Apple-Silicon HVF warm-restore matrix. Requires the HVF warm capability
# to have passed its live continuity gate; it never enables that capability.
hvf-warm-restore:
    bash scripts/check-hvf-warm-restore.sh

# ── Model / Conformance gates ────────────────────────────────────────────
# R1: the model is the single source. Verify model/*.toml, the generated

# CONFORMANCE.md, and the honesty/deferral meta-gates.
model:
    cargo run -p xtask -- check-conformance
    cargo run -p xtask -- check-honesty
    cargo run -p xtask -- check-deferrals

# Regenerate everything the model owns: CONFORMANCE.md.
model-write:
    cargo run -p xtask -- check-conformance --write

# R2: verify no open/some-true claim is asserted as established in docs.
honesty:
    cargo run -p xtask -- check-honesty

# R4: verify no TODO/FIXME/unimplemented!/placeholder markers are deferred.
deferrals:
    cargo run -p xtask -- check-deferrals

# ── Lint & Format ────────────────────────────────────────────────────────

# Format all code
fmt:
    cargo fmt --all

# Check formatting (no changes)
fmt-check:
    cargo fmt --all -- --check

# Run clippy with warnings as errors
clippy:
    ./scripts/cargo-stable.sh clippy --workspace --all-targets -- -D warnings

# Compile the cucumber conformance target. It sits behind the `bdd` feature to
# stay out of `cargo nextest run --workspace` (nextest lists tests via `--list`,
# which a `harness = false` target cannot answer), and `--all-targets` above
# honors `required-features`, so nothing else builds it — a struct change

# elsewhere in the workspace can break it unnoticed.
clippy-bdd:
    ./scripts/cargo-stable.sh clippy -p mvm-conformance --tests --features bdd -- -D warnings

# Format check + clippy + model gates (workspace + the feature-gated BDD target)
lint: fmt-check clippy clippy-bdd model check-fast-cargo

# ── Claim mutation testing ───────────────────────────────────────────────
# Verify the committed mutation surface still matches the claims ledger.

# Milliseconds, needs no cargo-mutants — this is the part CI runs per PR.
mutation-surface:
    cargo run -p xtask -- check-mutation-witnesses

# Mutate the claim surface and ratchet survivors against the baseline.
# HOURS: this is the nightly lane's command, not an inner-loop check.
# Needs `cargo install cargo-mutants cargo-nextest`.
#
# No isolation wrapper here on purpose. `--run` executes security code with
# its check removed, so it must not reach a real mvm state root — and that
# confinement lives where cargo-mutants is actually spawned, so every
# caller gets it rather than each one carrying its own copy. This recipe

# had no wrapper at all until that landed, which is the failure mode.
mutation-witnesses:
    cargo run -p xtask -- check-mutation-witnesses --run

# Re-pin the surface after a witness legitimately moved. Cheap, and keeps
# the stated reasons on existing accepted misses. Add --run to also

# re-record the misses themselves (hours, and it discards those reasons).
mutation-repin:
    cargo run -p xtask -- check-mutation-witnesses --write-baseline

# ── CI Gate ──────────────────────────────────────────────────────────────

# Full CI gate: lint + test + doctests + hermetic BDD + model gates.
ci: lint test test-doc bdd

# Alias for ci
preflight: ci

# ── Release ──────────────────────────────────────────────────────────────
# Cut a release with automatic version bump (based on conventional commits)
# Cut the next release (auto-detected version) via a PR. `main` is protected
# (enforce_admins + merge queue), so the version bump lands through a PR — a
# direct `git push` to main is rejected. After the PR merges, run

# `just release-tag <version>` to publish.
release-auto:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Preparing automatic release (PR-based)"
    # Quality gates — auto-fix fmt and clippy, then test.
    cargo fmt --all
    ./scripts/cargo-stable.sh clippy --fix --allow-dirty --workspace --all-targets -- -D warnings
    ./scripts/cargo-stable.sh clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    NEXT_VERSION=$(git cliff --bumped-version | sed 's/^v//')
    echo "==> Auto-detected next version: $NEXT_VERSION"
    just _release-prep "$NEXT_VERSION"

# Cut a specific version via a PR: just release 0.17.0
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Preparing release v{{ VERSION }}"
    cargo fmt --all
    ./scripts/cargo-stable.sh clippy --fix --allow-dirty --workspace --all-targets -- -D warnings
    ./scripts/cargo-stable.sh clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    just _release-prep "{{ VERSION }}"

# Shared release prep: on a `release/v<version>` branch, bump every version pin,
# prepend the changelog, commit, push, and open the release PR. Bumps the
# workspace version AND every internal path-dep pin — the old `mvm-[a-z]*` regex
# missed `mvm`, `mvm-ext4`, `libkrun-sys`, `mvm-egress-proxy`, which then

# version-mismatched on `cargo update`.
_release-prep VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{ VERSION }}"
    BRANCH="release/v$V"
    git switch -c "$BRANCH"
    sed -i.bak -E \
        -e "s/^version = \"[^\"]*\"/version = \"$V\"/" \
        -e "s/(path = \"[^\"]*\", version = )\"[^\"]*\"/\1\"$V\"/" Cargo.toml
    rm Cargo.toml.bak
    cargo update -w
    # The runtime-overlay flake pins its version to the workspace version
    # (check-runtime-overlay-version fails closed on a mismatch, ADR-018); the
    # nix package versions should track too. Bump them alongside Cargo.toml.
    sed -i.bak -E "s/(overlayVersion[[:space:]]*=[[:space:]]*\")[^\"]*(\")/\1$V\2/" nix/images/runtime-overlay/flake.nix
    rm nix/images/runtime-overlay/flake.nix.bak
    sed -i.bak -E "s/(^[[:space:]]*version = \")[0-9][^\"]*(\")/\1$V\2/" nix/packages/mvmctl.nix nix/packages/mvm-sdk-cdylib.nix
    rm nix/packages/*.bak
    git add nix/images/runtime-overlay/flake.nix nix/packages/mvmctl.nix nix/packages/mvm-sdk-cdylib.nix
    git-cliff --tag "v$V" --unreleased --prepend CHANGELOG.md
    # Fail closed if git-cliff did not add the new section (silently shipped
    # v0.15.2/v0.16.0/v0.16.1 with no changelog entry — never again).
    if ! grep -qE "^## \[$V\]" CHANGELOG.md; then
        echo "ERROR: git-cliff did not add a '## [$V]' section to CHANGELOG.md — aborting (no changelog for the release)." >&2
        exit 1
    fi
    git add Cargo.toml Cargo.lock CHANGELOG.md
    git commit -m "release: v$V"
    git push -u origin "$BRANCH"
    gh pr create --base main --head "$BRANCH" --title "release: v$V" \
        --body "Version bump + git-cliff changelog for v$V. Merge via the queue, then \`just release-tag $V\`."
    echo "==> Opened release PR for v$V. Merge it via the queue, then run: just release-tag $V"

# After the release PR merges: tag the merged main commit and push the tag,

# which triggers the build + publish pipeline. Tags are not branch-protected.
release-tag VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{ VERSION }}"
    git fetch origin main
    # The bump commit must be on main (the release PR merged) before tagging.
    if ! git show "origin/main:Cargo.toml" | grep -qE "^version = \"$V\""; then
        echo "ERROR: origin/main is not at version $V — merge the release PR first." >&2
        exit 1
    fi
    git tag "v$V" origin/main
    git push origin "v$V"
    echo "==> Pushed tag v$V — the release pipeline will build + publish."

# Build optimized release binary
release-build:
    cargo build --release --features host,user,template-registry-s3,release-artifact-bootstrap

# Cross-compile release binary for a target
release-build-target TARGET:
    cargo build --release --target {{ TARGET }} --features host,user,template-registry-s3,release-artifact-bootstrap

# Dry-run crates.io publish (all crates in dependency order)
publish-dry-run:
    ./scripts/release-dry-run.sh

# Pre-publish verification (version, tag, clippy)
deploy-guard:
    ./scripts/deploy-guard.sh

# Print workspace version
@version:
    echo {{ version }}

# Create a git tag for the current workspace version
tag:
    git tag v{{ version }}
    @echo "Tagged v{{ version }}"

# ── Documentation ────────────────────────────────────────────────────────

# Install docs site dependencies
docs-install:
    cd public && pnpm install

# Start docs dev server (stages the /demo wasm assets first if missing)
docs-dev: demo-assets
    cd public && pnpm dev

# Build docs site (stages the /demo wasm assets first if missing)
docs-build: demo-assets
    cd public && pnpm build

# Publish the docs site to Cloudflare Pages (dispatches pages.yml on main)
docs-publish:
    # `pages.yml` runs automatically when a release is published or a `v*`
    # tag is pushed; this recipe exists for operator-triggered docs publishes.
    # The old `push: branches:[main] paths:[public/**]` trigger was dropped in
    # the CI cost reduction — so a docs-only change reaches the site only when
    # someone asks for it or a release/tag fires.
    #
    # `--ref main`, never the current branch: Pages serves what is on main, and
    # dispatching from a branch would publish something nobody has merged.
    gh workflow run pages.yml --ref main
    @echo "Dispatched pages.yml on main. Watch it with: gh run watch \$(gh run list --workflow=pages.yml --limit 1 --json databaseId --jq '.[0].databaseId')"

# Alias for `docs-publish` using the Cloudflare Pages deployment name.
pages-deploy: docs-publish

# Check the live site sends the cross-origin isolation headers the demo needs
docs-check-live-headers url="":
    # No argument checks the domain in public/astro.config.mjs; pass a URL to
    # check a preview deployment instead. `pnpm check:headers` gates the
    # `_headers` config — this one gates what the host actually sends, which is
    # a different question and the one that has been answered wrong.
    ./scripts/check-site-isolation-headers.sh {{ url }}

# Build the browser-tier microVM demo assets (wasm core + guest + fixtures)
demo-build:
    ./web/mvm-demo/build.sh

# Build the weblinux demo assets (requires Linux builder)
weblinux-demo-build:
    ./web/weblinux-demo/build.sh

# Stage the browser WASM demo unless every generated asset class is present.
# WebLinux is staged separately from its verified release pack by pages.yml.
demo-assets:
    test -s public/public/demo/demo.js \
      && test -s public/public/demo/worker.js \
      && test -s public/public/demo/pkg/mvm_demo_web.js \
      && test -s public/public/demo/pkg/mvm_demo_web_bg.wasm \
      && test -s public/public/demo/guest/mvm-demo-guest.wasm \
      && test -s public/public/demo/fixtures/allowed.opt.wasm \
      && test -s public/public/demo/fixtures/denied.opt.wasm \
      && test -s public/public/demo/fixtures/unbound.opt.wasm \
      || just demo-build

# Build all demo assets (wasm + weblinux); requires Linux for weblinux
demo-build-all: demo-build weblinux-demo-build

# ── VMM setup ────────────────────────────────────────────────────────────

# Install libkrun (the macOS VMM mvm targets)
setup: setup-libkrun
    @echo
    @echo "libkrun installed. Validate with:"
    @echo "  cargo run --example libkrun-bootcheck --features libkrun-sys   (macOS)"

# Install libkrun (macOS via slp/krun tap; Linux via apt/dnf/pacman)
setup-libkrun:
    #!/usr/bin/env bash
    # macOS:   brew install slp/krun/libkrun  (libkrun is not in core; the
    #                                          qualified form auto-taps)
    # Linux:   apt install libkrun-dev        (Debian/Ubuntu, drags libkrun1)
    #          dnf install libkrun-devel      (Fedora/RHEL)
    #          pacman -S libkrun              (Arch / community)
    # Other:   build from source at https://github.com/containers/libkrun
    set -euo pipefail
    EXISTING=""
    for p in \
        /opt/homebrew/lib/libkrun.dylib \
        /usr/local/lib/libkrun.dylib \
        /usr/lib/x86_64-linux-gnu/libkrun.so \
        /usr/lib/aarch64-linux-gnu/libkrun.so \
        /usr/lib64/libkrun.so \
        /usr/local/lib/libkrun.so
    do
        if [ -f "$p" ]; then
            EXISTING="$p"
            break
        fi
    done
    if [ -n "$EXISTING" ]; then
        echo "libkrun already installed at $EXISTING — skipping."
        exit 0
    fi
    case "$(uname -s)" in
        Darwin)
            if ! command -v brew >/dev/null; then
                echo "error: Homebrew not found. Install: https://brew.sh" >&2
                exit 1
            fi
            echo "→ brew install slp/krun/libkrun"
            brew install slp/krun/libkrun
            ;;
        Linux)
            if command -v apt-get >/dev/null; then
                echo "→ apt install libkrun-dev"
                sudo apt-get update
                sudo apt-get install -y libkrun-dev
            elif command -v dnf >/dev/null; then
                echo "→ dnf install libkrun-devel"
                sudo dnf install -y libkrun-devel
            elif command -v pacman >/dev/null; then
                echo "→ pacman -S libkrun"
                sudo pacman -S --needed libkrun
            else
                echo "error: no recognized package manager (apt / dnf / pacman)." >&2
                echo "       Build from source: https://github.com/containers/libkrun" >&2
                exit 1
            fi
            ;;
        *)
            echo "error: libkrun is not supported on $(uname -s)." >&2
            exit 1
            ;;
    esac
    echo "Verifying install…"
    for p in \
        /opt/homebrew/lib/libkrun.dylib \
        /usr/local/lib/libkrun.dylib \
        /usr/lib/x86_64-linux-gnu/libkrun.so \
        /usr/lib/aarch64-linux-gnu/libkrun.so \
        /usr/lib64/libkrun.so \
        /usr/local/lib/libkrun.so
    do
        if [ -f "$p" ]; then
            echo "  ✓ $p"
            exit 0
        fi
    done
    echo "  ! libkrun shared library not found at the standard locations." >&2
    exit 1

# ── Utilities ────────────────────────────────────────────────────────────

# Clean build artifacts, the regenerable mvm cache, and the dev state root
clean: clean-dev-state
    cargo clean
    cargo run --quiet -- env cleanup --cache --yes

# Remove this worktree's dev state root `.mvm-test` (DRY_RUN=1 to preview)
clean-dev-state:
    #!/usr/bin/env bash
    # `scripts/dev-env.sh` points MVM_HOME, CARGO_TARGET_DIR *and* CARGO_HOME at
    # `<repo>/.mvm-test`, so every `just dev-*` run accumulates VM images, a full
    # build tree and a per-worktree cargo registry in one gitignored directory.
    # It is the largest thing a checkout owns and nothing used to sweep it:
    # `cargo clean` cleans `./target`, and `mvmctl env cleanup` only ever sees
    # whatever MVM_HOME points at in the shell that invokes it — which, outside
    # `just dev-*`, is not this directory. Measured 2026-08-09: 65 GB in one
    # worktree and 282 GB across a machine's worktrees, none of it reported by
    # any clean command.
    #
    # Safe whenever no dev VM is live out of this worktree; the contents are
    # rebuilt or re-fetched on demand.
    set -euo pipefail
    root="$(git rev-parse --show-toplevel)/.mvm-test"
    if [ ! -d "$root" ]; then
        echo "clean-dev-state: nothing at $root"
        exit 0
    fi
    size=$(du -sh "$root" 2>/dev/null | cut -f1)
    if [ -n "${DRY_RUN:-}" ]; then
        echo "clean-dev-state: would remove $root ($size)"
        exit 0
    fi
    rm -rf "$root"
    echo "clean-dev-state: removed $root ($size)"

# Classify worktrees: finished, needs-a-human, or in use (--safe-only for paths)
worktrees *ARGS:
    ./scripts/worktree-status.sh {{ ARGS }}

# Remove worktrees the classifier calls finished — preview by default, APPLY=1 to do it
worktrees-prune:
    #!/usr/bin/env bash
    # Separate from `just worktrees`, which is read-only and says so in its own
    # header. Classifying and deleting are different risks, so they stay
    # different commands. This one only ever acts on paths that classifier
    # already called SAFE: the PR merged, and this tip is exactly the merged head.
    #
    # Previews by default. `clean-dev-state` is the other way round (DRY_RUN=1)
    # because its blast radius is one regenerable directory; here it is whole
    # checkouts, so the cautious mode is the one you get without asking.
    #
    # Never passes --force, so git independently refuses any worktree with
    # uncommitted or untracked files — a second veto behind the classifier.
    # Branches are kept: removing a worktree does not touch its commits, so
    # anything that never landed stays reachable by branch name.
    set -euo pipefail
    paths=$(./scripts/worktree-status.sh --safe-only)
    if [ -z "$paths" ]; then
        echo "worktrees-prune: nothing finished to remove"
        exit 0
    fi
    # Snapshot the process list ONCE. Grepping ps per path inside the loop looks
    # equivalent and is not: the grep's own argv holds the path it searches for,
    # so every worktree matches itself and the whole set reads as busy.
    ps_snapshot=$(ps -eo command 2>/dev/null || true)
    removed=0
    while IFS= read -r p; do
        [ -d "$p" ] || continue
        # Re-checked at the moment of action: the classification is seconds old,
        # and a session may have started work in one since.
        case "$ps_snapshot" in
            *"$p"*) echo "  skip (in use)     $(basename "$p")"; continue ;;
        esac
        if [ -n "$(git -C "$p" status --porcelain 2>/dev/null)" ]; then
            echo "  skip (now dirty)  $(basename "$p")"; continue
        fi
        size=$(du -sh "$p" 2>/dev/null | cut -f1 | tr -d ' ')
        if [ -z "${APPLY:-}" ]; then
            echo "  would remove      $(basename "$p")  (${size})"
            continue
        fi
        if git worktree remove "$p" 2>/tmp/wtprune-err.$$; then
            echo "  removed           $(basename "$p")  (${size})"
            removed=$((removed + 1))
        else
            echo "  refused           $(basename "$p"): $(head -1 /tmp/wtprune-err.$$)"
        fi
        rm -f /tmp/wtprune-err.$$
    done <<< "$paths"
    if [ -z "${APPLY:-}" ]; then
        echo "worktrees-prune: preview only — re-run with APPLY=1 to remove"
    else
        echo "worktrees-prune: removed ${removed}; branches kept"
    fi

# Reap leaked host-side helper subprocesses (broker/host-agent/signer/etc.)
# older than N minutes (default 30). Backstop for the in-binary parent-death
# watchdog; clears orphans from past test runs across worktrees. DRY_RUN=1 to

# preview, e.g. `DRY_RUN=1 just reap-helpers` or `just reap-helpers 5`.
reap-helpers MINUTES="30":
    ./scripts/reap-helper-orphans.sh {{ MINUTES }}

# Security audit (cargo-audit — RUSTSEC advisories against Cargo.lock)
audit:
    cargo audit

# Supply chain check (cargo-deny — advisories + licenses + bans + sources)
deny:
    cargo deny check

# Combined supply-chain gate (ADR-001 §W5.2)
supply-chain: audit deny

# Verify production guest agent has no dev-only Exec symbols (ADR-001 §W4.3)
security-gate-prod-agent:
    ./scripts/check-prod-agent-no-exec.sh

# Run the GuestRequest deserializer fuzzer (ADR-001 §W4.2). Default 5min.

# Override with: just fuzz-guest-request 3600
fuzz-guest-request SECONDS="300":
    cd crates/mvm-agentd && cargo +nightly fuzz run fuzz_guest_request -- -max_total_time={{ SECONDS }}

# Run the AuthenticatedFrame envelope fuzzer (ADR-001 §W4.2). Default 5min.
fuzz-authenticated-frame SECONDS="300":
    cd crates/mvm-agentd && cargo +nightly fuzz run fuzz_authenticated_frame -- -max_total_time={{ SECONDS }}

# Check for outdated dependencies
outdated:
    cargo outdated -R

# Watch open PRs for a GitHub repo
watch-prs repo="tinylabscom/mvm" interval="10":
    watch -n {{ interval }} "gh pr list --repo {{ repo }} --state open --json number,title,mergeStateStatus,reviewDecision,isDraft --jq '.[] | \"#\(.number)  \(.mergeStateStatus // \"UNKNOWN\")  review=\(.reviewDecision // \"NONE\")  draft=\(.isDraft)  \(.title)\"'"

# List all available recipes
@_default:
    just --list
