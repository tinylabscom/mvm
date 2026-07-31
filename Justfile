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
    ZIG=$(python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['metadata']['mvm']['toolchain']['zig'])")
    echo "installing pinned zig ${ZIG} (ziglang) + musl rust targets"
    python3 -m pip install --quiet "ziglang==${ZIG}"
    rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
    echo "embed toolchain ready: zig ${ZIG} + aarch64/x86_64 musl targets"

# Build all crates (debug)
build:
    cargo build --workspace

# Type-check without codegen
check:
    cargo check --workspace --all-targets

# Cross-compile every crate's lib for Linux (glibc) via zig — no Docker — so
# cfg(target_os="linux") code a macOS host never compiles is caught locally.
# --all-features reaches feature-gated modules (e.g. libkrun_builder). Lib-only:
# linking the libkrun-sys bins needs target libkrun, which CI provides. Needs
# `cargo install cargo-zigbuild`, a `zig` on PATH, and
# `rustup target add x86_64-unknown-linux-gnu`. musl is intentionally not the
# default — libc's ioctl request arg is c_int there vs c_ulong on glibc, so the
# COW FICLONE path (mvm-runtime) only type-checks against glibc.
check-linux TARGET="x86_64-unknown-linux-gnu":
    cargo zigbuild --target {{TARGET}} --workspace --lib --all-features

# Bare-metal no_std proof for the embeddable foundation crate (mvm-protocol).
# A `-none-elf` target exposes only core + alloc with no std to leak into, so
# this is a stricter no_std check than the wasm32 gate. riscv32imac is the
# mainline stand-in for the RISC-V microcontrollers the on-device verifier
# targets; lib-only means an rlib with no final link, so no cross-linker is
# needed. Note: riscv32imc parts (no atomics) and Xtensa parts need extra
# shims/toolchains — see specs/notes for the embedding track.
check-embedded TARGET="riscv32imac-unknown-none-elf":
    rustup target add {{TARGET}}
    cargo build -p mvm-protocol --lib --target {{TARGET}}

# Run mvmctl with arguments
run *ARGS:
    cargo run -- {{ARGS}}

# Run mvmctl with the dev env set (worktree-local MVM_HOME).
dev *ARGS:
    sh ./bin/dev {{ARGS}}

# Run cargo with the dev env set (worktree-local MVM_HOME /
# CARGO_TARGET_DIR / CARGO_HOME).
dev-cargo *ARGS:
    bash -c 'source scripts/dev-env.sh && cargo {{ARGS}}'

# Run cargo test --workspace with the dev env.
dev-test:
    just dev-cargo test --workspace

# Run clippy with the dev env.
dev-clippy:
    just dev-cargo clippy --workspace -- -D warnings

# Run cargo check with the dev env.
dev-check:
    just dev-cargo check --workspace

# Prebuild or refresh the version-matched read-only runtime overlay once so
# later required-overlay boots can reuse it without rebuilding guest binaries
# on the hot path. Pass through extra args like `--force` or `--source download`.
runtime-overlay *ARGS:
    just dev build runtime-overlay build {{ARGS}}

# Prebuild or refresh the version-matched read-only runtime overlay once so
# later required-overlay boots can reuse it without rebuilding guest binaries
# on the hot path. Kept as a compatibility alias for `just runtime-overlay`.
runtime-overlay-build *ARGS:
    just runtime-overlay {{ARGS}}

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
    mkdir -p target/nextest
    cargo nextest run --workspace 2>&1 | tee target/nextest/last-run.log

# Non-release builds now skip the embedded host-vm binary cross-compile by
# default. Keep this explicit recipe as the "always stub" path when a caller
# wants to force the fast mode even after opting into real embeds elsewhere.
test-fast:
    MVM_SKIP_EMBED_BINARIES=1 cargo nextest run --workspace

# Doctests. nextest does NOT run doctests, so `just test` skips them;
# this is the companion that keeps doc-fence coverage gated.
test-doc:
    cargo test --workspace --doc

# Run tests with sccache wrapping rustc — caches compilation across
# worktrees/branches (a content cache, not a build lock, so parallel
# sessions don't serialize on it). Incremental is OFF because sccache and
# incremental compilation are mutually exclusive: this trades inner-loop
# incremental for cross-worktree cache hits. Needs `cargo install sccache`.
test-cached:
    @command -v sccache >/dev/null || { echo "sccache not found — install with: cargo install sccache"; exit 1; }
    RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 cargo nextest run --workspace
    @sccache --show-stats

# Test a single crate
test-crate CRATE:
    cargo nextest run -p {{CRATE}}

# Run tests matching a filter expression
test-filter FILTER:
    cargo nextest run --workspace -E 'test({{FILTER}})'

# Run tests under the `ci` profile: no retries, slow-test warnings, and a
# JUnit report at target/nextest/ci/junit.xml carrying pass/fail structure
# only (no captured test output — see .config/nextest.toml).
test-ci:
    cargo nextest run --workspace --profile ci

# Run tests with cargo test (fallback if nextest not installed)
test-cargo:
    cargo test --workspace

# BDD conformance suite (cucumber-rs): builds mvmctl, then runs every
# Gherkin scenario under features/suites/ against it. Scenarios tagged
# `@wip` describe not-yet-implemented coverage and are filtered out by the
# runner, so this stays green as later suites land their steps.
bdd:
    cargo build --bin mvmctl
    cargo test -p mvm-conformance --test conformance --features bdd

# Build the per-VM host helper bins explicitly. mvmctl's build script already
# compiles them during `cargo build`/`cargo run`; this is the manual route for
# a targeted rebuild or CI.
build-supervisors:
    cargo build -p mvm-hostd --bin mvm-substitution-endpoint
    cargo build -p mvm-vm-host --bin mvm-hvf-supervisor
    cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys

# Build the dm-verity-capable workload kernel into the local mvm cache.
kernel-workload:
    cargo run -- kernel build --which workload

# Live macOS Apple-Silicon HVF proof for OCI --allow-host:
#  1. exact `machine run --image ... --allow-host ... -- ps aux` path
#  2. admit/deny relay proof over the host-vsock egress endpoint
hvf-oci-allow-host-smoke:
    bash scripts/check-hvf-oci-allow-host-smoke.sh

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
    cargo clippy --workspace --all-targets -- -D warnings

# Compile the cucumber conformance target. It sits behind the `bdd` feature to
# stay out of `cargo nextest run --workspace` (nextest lists tests via `--list`,
# which a `harness = false` target cannot answer), and `--all-targets` above
# honors `required-features`, so nothing else builds it — a struct change
# elsewhere in the workspace can break it unnoticed.
clippy-bdd:
    cargo clippy -p mvm-conformance --tests --features bdd -- -D warnings

# Format check + clippy + model gates (workspace + the feature-gated BDD target)
lint: fmt-check clippy clippy-bdd model

# ── Claim mutation testing ───────────────────────────────────────────────

# Verify the committed mutation surface still matches the claims ledger.
# Milliseconds, needs no cargo-mutants — this is the part CI runs per PR.
mutation-surface:
    cargo run -p xtask -- check-mutation-witnesses

# Mutate the claim surface and ratchet survivors against the baseline.
# HOURS: this is the nightly lane's command, not an inner-loop check.
# Needs `cargo install cargo-mutants cargo-nextest`.
#
# Runs under a redirected HOME and MVM_HOME, matching security.yml.
# `--run` executes security code with its check removed — plan
# verification that no longer verifies, the host signer, seccomp
# construction — so it must not reach a real mvm state root. The mutation
# may be *in* the path or mode logic, so it could mint a key at the wrong
# path or leave firewall rules behind. MVM_HOME alone is not enough,
# because `default_mvm_cache_dir` deliberately reads the home directory to
# seed from the shared cache.
#
# CARGO_HOME/RUSTUP_HOME resolve from the real home *first*: `~` follows
# HOME, so without this cargo and rustup follow the redirect into an empty
# temp dir and the toolchain disappears mid-run.
mutation-witnesses:
    #!/usr/bin/env bash
    set -euo pipefail
    export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
    MUTANTS_HOME="$(mktemp -d "${TMPDIR:-/tmp}/mvm-mutants-home.XXXXXX")"
    export MVM_HOME="$MUTANTS_HOME"
    export HOME="$MUTANTS_HOME"
    if [ -e "$HOME/.mvm/keys" ]; then
        echo "refusing to mutate against a reachable keystore at $HOME/.mvm/keys" >&2
        exit 1
    fi
    echo "mutating under an isolated HOME/MVM_HOME at $MUTANTS_HOME"
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
    cargo clippy --fix --allow-dirty --workspace --all-targets -- -D warnings
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    NEXT_VERSION=$(git cliff --bumped-version | sed 's/^v//')
    echo "==> Auto-detected next version: $NEXT_VERSION"
    just _release-prep "$NEXT_VERSION"

# Cut a specific version via a PR: just release 0.17.0
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Preparing release v{{VERSION}}"
    cargo fmt --all
    cargo clippy --fix --allow-dirty --workspace --all-targets -- -D warnings
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    just _release-prep "{{VERSION}}"

# Shared release prep: on a `release/v<version>` branch, bump every version pin,
# prepend the changelog, commit, push, and open the release PR. Bumps the
# workspace version AND every internal path-dep pin — the old `mvm-[a-z]*` regex
# missed `mvm`, `mvm-ext4`, `libkrun-sys`, `mvm-egress-proxy`, which then
# version-mismatched on `cargo update`.
_release-prep VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    V="{{VERSION}}"
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
    sed -i.bak -E "s/(^[[:space:]]*version = \")[0-9][^\"]*(\")/\1$V\2/" nix/packages/mvmctl.nix nix/packages/mvm-host-services-ffi.nix
    rm nix/packages/*.bak
    git add nix/images/runtime-overlay/flake.nix nix/packages/mvmctl.nix nix/packages/mvm-host-services-ffi.nix
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
    V="{{VERSION}}"
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
    cargo build --release --target {{TARGET}} --features host,user,template-registry-s3,release-artifact-bootstrap

# Dry-run crates.io publish (all crates in dependency order)
publish-dry-run:
    ./scripts/release-dry-run.sh

# Pre-publish verification (version, tag, clippy)
deploy-guard:
    ./scripts/deploy-guard.sh

# Print workspace version
@version:
    echo {{version}}

# Create a git tag for the current workspace version
tag:
    git tag v{{version}}
    @echo "Tagged v{{version}}"

# ── Documentation ────────────────────────────────────────────────────────

# Install docs site dependencies
docs-install:
    cd public && pnpm install

# Start docs dev server
docs-dev:
    cd public && pnpm dev

# Build docs site
docs-build:
    cd public && pnpm build

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

# Clean build artifacts
clean:
    cargo clean

# Reap leaked host-side helper subprocesses (broker/host-agent/signer/etc.)
# older than N minutes (default 30). Backstop for the in-binary parent-death
# watchdog; clears orphans from past test runs across worktrees. DRY_RUN=1 to
# preview, e.g. `DRY_RUN=1 just reap-helpers` or `just reap-helpers 5`.
reap-helpers MINUTES="30":
    ./scripts/reap-helper-orphans.sh {{MINUTES}}

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
    cd crates/mvm-agentd && cargo +nightly fuzz run fuzz_guest_request -- -max_total_time={{SECONDS}}

# Run the AuthenticatedFrame envelope fuzzer (ADR-001 §W4.2). Default 5min.
fuzz-authenticated-frame SECONDS="300":
    cd crates/mvm-agentd && cargo +nightly fuzz run fuzz_authenticated_frame -- -max_total_time={{SECONDS}}

# Check for outdated dependencies
outdated:
    cargo outdated -R

# Watch open PRs for a GitHub repo
watch-prs repo="tinylabscom/mvm" interval="10":
    watch -n {{interval}} "gh pr list --repo {{repo}} --state open --json number,title,mergeStateStatus,reviewDecision,isDraft --jq '.[] | \"#\(.number)  \(.mergeStateStatus // \"UNKNOWN\")  review=\(.reviewDecision // \"NONE\")  draft=\(.isDraft)  \(.title)\"'"

# List all available recipes
@_default:
    just --list
