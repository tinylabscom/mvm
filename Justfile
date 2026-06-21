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

# Build all crates (debug)
build:
    cargo build --workspace

# Type-check without codegen
check:
    cargo check --workspace --all-targets

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
release-auto:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Preparing automatic release"
    # 1. Quality gates — auto-fix fmt and clippy, then test
    cargo fmt --all
    cargo clippy --fix --allow-dirty --workspace --all-targets -- -D warnings
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    # 2. Determine next version from conventional commits
    NEXT_VERSION=$(git cliff --bumped-version | sed 's/^v//')
    echo "==> Auto-detected next version: $NEXT_VERSION"
    # 3. Update version in Cargo.toml (workspace.package.version and internal crate versions)
    sed -i.bak -e "s/^version = \".*\"/version = \"$NEXT_VERSION\"/" \
               -e "s/\(mvm-[a-z]* = .*version = \)\"[^\"]*\"/\1\"$NEXT_VERSION\"/" Cargo.toml
    rm Cargo.toml.bak
    cargo update -w
    git add Cargo.toml Cargo.lock
    # 4. Generate changelog and create tag
    git-cliff --tag "v$NEXT_VERSION" --unreleased --prepend CHANGELOG.md
    git add CHANGELOG.md
    git commit -m "chore(release): prepare v$NEXT_VERSION"
    git tag "v$NEXT_VERSION"
    # 5. Push commits and tags
    git push --follow-tags
    echo "==> Release v$NEXT_VERSION complete. CI workflow will build and publish."

# Cut a release with specific version: just release 0.4.1
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Preparing release v{{VERSION}}"
    # 1. Quality gates — auto-fix fmt and clippy, then test
    cargo fmt --all
    cargo clippy --fix --allow-dirty --workspace --all-targets -- -D warnings
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    # 2. Update version in Cargo.toml (workspace.package.version and internal crate versions)
    sed -i.bak -e 's/^version = ".*"/version = "{{VERSION}}"/' \
               -e 's/\(mvm-[a-z]* = .*version = \)"[^"]*"/\1"{{VERSION}}"/' Cargo.toml
    rm Cargo.toml.bak
    cargo update -w
    git add Cargo.toml Cargo.lock
    # 3. Use git-cliff to generate changelog and create tag
    # --tag: use specified version instead of auto-bump
    # --prepend: add new changelog entry to CHANGELOG.md
    git-cliff --tag "v{{VERSION}}" --unreleased --prepend CHANGELOG.md
    git add CHANGELOG.md
    git commit -m "chore(release): prepare v{{VERSION}}"
    git tag "v{{VERSION}}"
    # 4. Push commits and tags
    git push --follow-tags
    echo "==> Release v{{VERSION}} complete. CI workflow will build and publish."

# Build optimized release binary
release-build:
    cargo build --release --features backends-libkrun,template-registry-s3,dev-watch,custom-dns,manifest-verify

# Cross-compile release binary for a target
release-build-target TARGET:
    cargo build --release --target {{TARGET}} --features backends-libkrun,template-registry-s3,dev-watch,custom-dns,manifest-verify

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


# List all available recipes
@_default:
    just --list
