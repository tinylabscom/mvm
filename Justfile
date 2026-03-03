# mvm — Firecracker MicroVM Development Tool
# https://github.com/casey/just

set dotenv-load := false

# Extract workspace version from Cargo.toml
version := `grep -A 5 '^\[workspace\.package\]' Cargo.toml | grep '^version' | head -1 | cut -d '"' -f 2`

# Default recipe - show help
default:
    @just --list

# ── Development ──────────────────────────────────────────────────────────

# Build all crates (debug)
build:
    cargo build --workspace

# Type-check without codegen
check:
    cargo check --workspace --all-targets

# Run mvmctl with arguments
run *ARGS:
    cargo run -- {{ARGS}}

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

# Cut a release: just release 0.3.0
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Releasing v{{VERSION}}"
    # 1. Bump workspace version in root Cargo.toml
    sed -i '' 's/^version = ".*"/version = "{{VERSION}}"/' Cargo.toml
    cargo check --workspace --quiet
    echo "    Cargo.toml [workspace.package] version set to {{VERSION}}"
    # 2. Auto-generate changelog entry if missing
    scripts/update-changelog.sh --version "{{VERSION}}"
    # 3. Commit the version bump and changelog (if anything changed)
    if ! git diff --quiet Cargo.toml Cargo.lock CHANGELOG.md; then
        git add Cargo.toml Cargo.lock CHANGELOG.md
        git commit -m "chore: bump version to {{VERSION}} and update changelog"
    fi
    # 4. Quality gates
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run --workspace
    # 5. Verify changelog & crate versions match
    scripts/verify-release-version.sh --version "{{VERSION}}"
    # 6. Tag and push (triggers .github/workflows/release.yml)
    git tag "v{{VERSION}}"
    git push origin "v{{VERSION}}"
    echo "==> Tag v{{VERSION}} pushed. Release workflow will build and publish."

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

# Security audit
audit:
    cargo audit

# Check for outdated dependencies
outdated:
    cargo outdated -R


# List all available recipes
@_default:
    just --list
