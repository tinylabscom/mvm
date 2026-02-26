# Development Guide

Getting started as a contributor to mvm.

## Prerequisites

- **Rust 1.85+** (Edition 2024) — install via [rustup](https://rustup.rs)
- **macOS or Linux** — macOS for development via Lima, Linux for native `/dev/kvm`
- **Nix** (optional) — only needed for building microVM images

Run the bootstrap script on a fresh machine:

```bash
./scripts/dev-setup.sh
```

This installs build essentials, OpenSSL dev headers, `lld`, Rust toolchain, and `cargo-watch`.

## Project Structure

```
mvm/
├── src/
│   ├── lib.rs          # Facade: re-exports all workspace crates
│   └── main.rs         # Binary entry: calls mvm_cli::run()
├── crates/
│   ├── mvm-core/       # Pure types, IDs, config, protocol, signing (no runtime deps)
│   ├── mvm-guest/      # Vsock protocol, integration manifest
│   ├── mvm-build/      # Nix builder pipeline
│   ├── mvm-runtime/    # Shell execution, security, VM lifecycle, bridge, pool/tenant/instance
│   ├── mvm-agent/      # Reconcile engine, coordinator client, sleep policy
│   ├── mvm-coordinator/# Gateway load-balancer, TCP proxy, wake manager
│   └── mvm-cli/        # Clap CLI, UI, bootstrap, upgrade
├── tests/
│   └── cli.rs          # Root-level integration tests (assert_cmd)
├── resources/          # Lima template, systemd units, scripts
├── deploy/
│   └── systemd/        # Service files (mvm-agent, mvm-agentd, mvm-hostd)
├── scripts/            # Dev setup, deploy guard, release tooling
├── docs/               # Architecture, security, networking, CLI reference
└── specs/              # Sprint specs and implementation plans
```

### Crate Dependency Graph

```
mvm-core (foundation, no mvm deps)
├── mvm-guest (core)
├── mvm-build (core, guest)
├── mvm-runtime (core, guest, build)
├── mvm-agent (core, runtime, build, guest)
├── mvm-coordinator (core, runtime)
└── mvm-cli (core, agent, runtime, coordinator, build)
```

Changes to `mvm-core` affect all crates. Changes to `mvm-cli` affect nothing else. Keep this in mind when deciding where to put new types and functions.

## Building and Running

```bash
# Build
cargo build

# Run CLI
cargo run -- --help

# Dev mode (auto-bootstraps Lima + Firecracker, then SSH into microVM)
cargo run -- dev

# Check status
cargo run -- status

# Build in release mode (stripped, LTO)
cargo build --release
```

## Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for a single crate
cargo test -p mvm-core
cargo test -p mvm-runtime

# Run a specific test
cargo test -p mvm-build test_cache_hit

# Run integration tests only (in the root package)
cargo test --test cli

# Run with output visible
cargo test -- --nocapture
```

### Test Organization

| Location | Type | What it tests |
|----------|------|---------------|
| `crates/*/src/**/*.rs` (`#[cfg(test)]`) | Unit tests | Internal functions within the crate |
| `crates/*/tests/*.rs` | Integration tests | Public API of each crate |
| `tests/cli.rs` | Binary tests | CLI arg parsing, help output, subcommand structure |

Key test infrastructure:

- **Shell mocks** (`mvm-runtime/src/shell_mock.rs`): simulate Lima/shell execution without a real VM
- **TestBuildEnv** (`mvm-build/tests/pipeline.rs`): queue-based `BuildEnvironment` implementation for build pipeline tests
- **MemStateStore** (`mvm-coordinator/src/state.rs`): in-memory async state store for coordinator tests
- **assert_cmd** (`tests/cli.rs`): binary testing with `Command::cargo_bin("mvmctl")`

### Testing Conventions

- Unit tests go in `#[cfg(test)] mod tests {}` at the bottom of the source file
- Integration tests go in `crates/<crate>/tests/`
- CLI binary tests go in root `tests/cli.rs` (the `mvmctl` binary is defined in the root package)
- Use `#[serde(default)]` when adding fields to structs used in test fixtures

## Linting and Formatting

```bash
# Format code
cargo fmt

# Lint (zero warnings required)
cargo clippy --workspace -- -D warnings

# Fix clippy warnings automatically
cargo clippy --workspace --fix --allow-dirty
```

### Pre-commit Hooks

Git hooks are configured automatically via `.githooks/`. Every commit runs:

1. `cargo fmt` — auto-formats and re-stages
2. `cargo clippy --all-targets -- -D warnings` — must pass with zero warnings
3. `cargo test` — all tests must pass

If a commit fails, fix the issue and commit again. The hooks cannot be bypassed without `--no-verify` (which you should avoid).

### Style Rules

- **Edition 2024**: `use` statements don't need `extern crate`; let chains supported
- **No `clippy::too_many_arguments`**: never suppress this lint — refactor into a params struct instead
- **No `format!()` in `format!()` named args**: extract to a variable first
- **Cross-crate imports**: always use `mvm_core::`, `mvm_runtime::`, etc. (not `crate::` across boundaries)
- **No unnecessary comments**: don't add docstrings or type annotations to code you didn't change

## Architecture Principles

### Host vs. VM Execution

All Linux operations (networking, Firecracker, cgroups) run inside the Lima VM on macOS:

```rust
// This runs a bash script inside the Lima VM
mvm_runtime::shell::run_in_vm("ip link add br-tenant-1 type bridge")?;

// Returns Result<Output> — use .map(|_| ()) when you need Result<()>
```

On native Linux, `run_in_vm` executes directly without Lima.

### Key Patterns

- **Single lifecycle API**: all instance operations go through `instance/lifecycle.rs`
- **Coordinator owns network**: tenant subnets come from the coordinator, never derived locally
- **Config drive for metadata**: instance metadata delivered via read-only ext4 disk, not SSH
- **Vsock over SSH**: guest communication uses Firecracker vsock (port 52), not sshd
- **Idempotent operations**: every setup step checks if already done before acting
- **`BuildEnvironment` trait**: abstraction for shell execution used by `mvm-build`, implemented by `RuntimeBuildEnv` in `mvm-runtime`

### Adding New Types

When adding fields to structs that appear in serialized state (JSON files, API payloads):

1. Add `#[serde(default)]` to the new field for backward compatibility
2. Update ALL test constructions across ALL crates that use the struct
3. If the struct is in `mvm-core`, expect ripple effects across the workspace

### Instance State Machine

```
Created → Ready → Running → Warm → Sleeping → (wake) → Running
                   Running/Warm/Sleeping → Stopped → Running
                   Any → Destroyed
```

All transitions enforced in `instance/state.rs`. Invalid transitions fail loudly.

## CI/CD

### GitHub Actions Workflows

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | Push to main/feat/*, PRs | check, fmt, clippy, test (macOS + Linux), audit |
| `release.yml` | Tags matching `v*` | Builds 4 platform binaries, creates GitHub Release |
| `publish-crates.yml` | Release published / manual | Publishes to crates.io in dependency order |
| `pages.yml` | Push to main | Deploys docs to GitHub Pages |

CI uses nightly Rust and enforces `-D warnings` globally.

### Release Process

```bash
# 1. Bump version in root Cargo.toml [workspace.package]
#    Inter-crate dependency versions update automatically

# 2. Update CHANGELOG.md

# 3. Commit and tag
git add -A && git commit -m "release: v0.3.0"
git tag v0.3.0

# 4. Push (triggers release.yml)
git push && git push --tags

# 5. Optionally publish crates (manual dispatch or automatic on release)
```

The deploy guard (`scripts/deploy-guard.sh`) validates that the tag matches the workspace version before publishing.

## Common Tasks

### Adding a New CLI Command

1. Add the subcommand enum variant in `crates/mvm-cli/src/commands.rs`
2. Implement the handler function
3. Wire it into the match block in `run()`
4. Add a help test in `tests/cli.rs`

### Adding a New Crate Field

1. Add the field to the struct in `mvm-core` (with `#[serde(default)]`)
2. `cargo test --workspace` to find all broken test constructions
3. Fix each one
4. Add a unit test for the new behavior

### Debugging

```bash
# Verbose logging
RUST_LOG=debug cargo run -- <command>

# Trace a specific module
RUST_LOG=mvm_runtime=trace cargo run -- instance start <path>

# JSON log output
cargo run -- --log-format json <command> 2>&1 | jq .
```

### Watch Mode

```bash
# Rebuild on file changes
cargo watch -x check

# Run tests on changes
cargo watch -x 'test --workspace'
```

## Documentation

| Document | Content |
|----------|---------|
| [architecture.md](architecture.md) | Module map, data model, filesystem layout |
| [networking.md](networking.md) | Cluster CIDR, bridges, isolation model |
| [security.md](security.md) | Threat model, hardening, privilege separation |
| [cli.md](cli.md) | Complete command reference |
| [agent.md](agent.md) | Desired state schema, reconcile loop, QUIC API |
| [coordinator.md](coordinator.md) | Gateway proxy, wake coalescing, idle tracking |
| [deployment.md](deployment.md) | Single/multi-node deployment, systemd, env vars |
| [runbook.md](runbook.md) | Operational procedures for production incidents |
| [user-guide.md](user-guide.md) | Writing Nix flakes for mvm pools |
| [SMOKE_TEST.md](SMOKE_TEST.md) | End-to-end manual validation |
