# mvm — Firecracker MicroVM Development Tool
# https://github.com/casey/just

set dotenv-load := false

# Extract workspace version from Cargo.toml
version := `grep -A 5 '^\[workspace\.package\]' Cargo.toml | grep '^version' | head -1 | cut -d '"' -f 2`

# Default recipe - show help
default:
    @just --list

# ── Development ──────────────────────────────────────────────────────────

# One-time setup: point git at the committed .githooks/ dir so the
# lightweight pre-commit hook (cargo fmt + nix fmt --check) actually runs.
# Without this, git falls back to .git/hooks/pre-commit, which may be a
# stale local copy or the legacy heavy hook.
install-hooks:
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

# Full CI gate: lint + test
ci: lint test

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
    cargo build --release

# Cross-compile release binary for a target
release-build-target TARGET:
    cargo build --release --target {{TARGET}}

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

# ── Utilities ────────────────────────────────────────────────────────────

# Clean build artifacts
clean:
    cargo clean

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
