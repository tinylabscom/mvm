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
# COW FICLONE path (mvm-backend) only type-checks against glibc.
check-linux TARGET="x86_64-unknown-linux-gnu":
    cargo zigbuild --target {{TARGET}} --workspace --lib --all-features

# Run mvmctl with arguments
run *ARGS:
    cargo run -- {{ARGS}}

# Run mvmctl with the dev env set (worktree-local MVM_DATA_DIR).
dev *ARGS:
    bin/dev {{ARGS}}

# Run cargo test --workspace with the dev env.
dev-test:
    bash -c 'source scripts/dev-env.sh && cargo test --workspace'

# Run clippy with the dev env.
dev-clippy:
    bash -c 'source scripts/dev-env.sh && cargo clippy --workspace -- -D warnings'

# Run cargo check with the dev env.
dev-check:
    bash -c 'source scripts/dev-env.sh && cargo check --workspace'

# ── Testing (nextest) ────────────────────────────────────────────────────

# Run all tests
test:
    cargo nextest run --workspace

# Fast inner-loop / fresh-worktree run: skips the embedded host-vm binary
# cross-compile (cargo zigbuild --release) in mvm-cli/build.rs. Safe for
# everything except builder-VM boot — the env-gated E2E tests need the
# real binaries and the `e2e-core-demo` recipe never sets this var.
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

# Run tests with CI profile (retries, JUnit output)
test-ci:
    cargo nextest run --workspace --profile ci

# Run tests with cargo test (fallback if nextest not installed)
test-cargo:
    cargo test --workspace

# Run the core-demo end-to-end smoke (libkrun builder + workload VM, minutes).
# Builds two binaries first that `cargo test -p mvm-cli` does NOT rebuild:
#   1. `mvmctl` — the root-package binary the test execs via
#      `Command::cargo_bin`. `-p mvm-cli` only rebuilds the mvm-cli *lib*;
#      without this, the test silently runs a STALE mvmctl and changes to
#      `crates/mvm-cli/src/commands/**` (e.g. the `up` agent-wait) never take
#      effect — a false green.
#   2. `mvm-libkrun-supervisor` — a standalone bin gated behind
#      `required-features = ["libkrun-sys"]`; a stale one reintroduces the
#      gvproxy-orphan hang.
e2e-core-demo:
    cargo build --bin mvmctl
    # Plan 121 D2 folded the supervisor bin into mvm-vm-host; build the
    # cfg-gated [[bin]] by crate + bin name (it is no longer its own crate).
    cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys
    MVM_E2E_SMOKE=1 MVM_BUILDER_BACKEND=libkrun cargo test -p mvm-cli --test core_demo_e2e -- --nocapture

# Build the per-VM host helper bins `mvmctl` spawns. `cargo run` builds only
# `mvmctl`; the backend resolves these alongside the exe / in `target/` and also
# self-builds them on the first `machine run`, so this is just the explicit route.
build-supervisors:
    cargo build -p mvm-hostd --bin mvm-substitution-endpoint
    cargo build -p mvm-vm-host --bin mvm-hvf-supervisor
    cargo build -p mvm-vm-host --bin mvm-vz-supervisor
    cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys

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

# Format check + clippy
lint: fmt-check clippy

# ── CI Gate ──────────────────────────────────────────────────────────────

# Full CI gate: lint + test + doctests (nextest skips doctests).
ci: lint test test-doc

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
    cargo build --release --features host,user,template-registry-s3

# Cross-compile release binary for a target
release-build-target TARGET:
    cargo build --release --target {{TARGET}} --features host,user,template-registry-s3

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

# Combined supply-chain gate (ADR-002 §W5.2)
supply-chain: audit deny

# Verify production guest agent has no dev-only Exec symbols (ADR-002 §W4.3)
security-gate-prod-agent:
    ./scripts/check-prod-agent-no-exec.sh

# Run the GuestRequest deserializer fuzzer (ADR-002 §W4.2). Default 5min.
# Override with: just fuzz-guest-request 3600
fuzz-guest-request SECONDS="300":
    cd crates/mvm-guest && cargo +nightly fuzz run fuzz_guest_request -- -max_total_time={{SECONDS}}

# Run the AuthenticatedFrame envelope fuzzer (ADR-002 §W4.2). Default 5min.
fuzz-authenticated-frame SECONDS="300":
    cd crates/mvm-guest && cargo +nightly fuzz run fuzz_authenticated_frame -- -max_total_time={{SECONDS}}

# Check for outdated dependencies
outdated:
    cargo outdated -R

# Watch open PRs for a GitHub repo
watch-prs repo="tinylabscom/mvm" interval="10":
    watch -n {{interval}} "gh pr list --repo {{repo}} --state open --json number,title,mergeStateStatus,reviewDecision,isDraft --jq '.[] | \"#\(.number)  \(.mergeStateStatus // \"UNKNOWN\")  review=\(.reviewDecision // \"NONE\")  draft=\(.isDraft)  \(.title)\"'"

# List all available recipes
@_default:
    just --list
