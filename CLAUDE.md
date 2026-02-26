# mvm -- Firecracker MicroVM Development Tool

## Project Overview

Rust CLI for building and running Firecracker microVMs on macOS (via Lima) and Linux. Handles the full dev lifecycle: bootstrapping, Nix-based image builds, single-VM management, and reusable template creation.

Multi-tenant fleet orchestration (tenants, pools, instances, agents, coordinators) lives in the separate [mvmd](https://github.com/auser/mvmd) repository.

```
macOS / Linux Host (this CLI) -> Lima VM (Ubuntu) -> Firecracker microVM (/dev/kvm)
```

## Architecture

### Workspace Structure

5-crate Cargo workspace with root facade:

- `mvm-core` -- pure types, IDs, config, protocol, signing, routing (NO runtime deps)
- `mvm-guest` -- vsock protocol, integration manifest/state (OpenClaw)
- `mvm-build` -- Nix builder pipeline (dev_build uses `ShellEnvironment` trait, pool_build uses `BuildEnvironment`)
- `mvm-runtime` -- shell execution, Lima/Firecracker VM lifecycle, UI, template management
- `mvm-cli` -- Clap CLI, bootstrap, upgrade, doctor, template commands

Root package: `src/lib.rs` (facade re-exports `mvmctl::core`, `mvmctl::runtime`, `mvmctl::build`, `mvmctl::guest`) + `src/main.rs` (thin CLI entry -> `mvm_cli::run()`)

Binary: `mvmctl` (from root, delegates to mvm-cli)

**Dependency graph:**
```
mvm-core (foundation, no mvm deps)
├── mvm-guest (core)
├── mvm-build (core, guest)
├── mvm-runtime (core, guest, build)
└── mvm-cli (core, runtime, build)
```

**Key module locations:**

mvm-core: `build_env.rs` (ShellEnvironment + BuildEnvironment traits), `pool.rs`, `instance.rs`, `tenant.rs`, `template.rs`, `naming.rs`, `signing.rs`, `routing.rs`, `protocol.rs`, `agent.rs`

mvm-runtime: `shell.rs`, `config.rs`, `ui.rs`, `build_env.rs` (DevShellEnv impl), `vm/lima.rs`, `vm/firecracker.rs`, `vm/microvm.rs`, `vm/network.rs`, `vm/image.rs`, `vm/template/`

mvm-build: `dev_build.rs` (local Nix builds via ShellEnvironment), `build.rs` (orchestrated builds via BuildEnvironment), `nix_manifest.rs`, `scripts.rs`

mvm-guest: `vsock.rs`, `integrations.rs`, `builder_agent.rs`

mvm-cli: `commands.rs`, `bootstrap.rs`, `template_cmd.rs`, `doctor.rs`, `upgrade.rs`, `http.rs`, `logging.rs`, `ui.rs`

### Trait Architecture

`BuildEnvironment` is split into two traits in `mvm-core/src/build_env.rs`:

```
ShellEnvironment (base)
  shell_exec(), shell_exec_stdout(), shell_exec_visible()
  log_info(), log_success(), log_warn()

BuildEnvironment : ShellEnvironment (extends)
  load_pool_spec(), load_tenant_config()
  ensure_bridge(), setup_tap(), teardown_tap()
  record_revision()
```

- **Dev mode** (`mvmctl build`, `mvmctl template build`): uses `dev_build()` with `&dyn ShellEnvironment`
- **Fleet mode** (in mvmd): uses `pool_build()` with `&dyn BuildEnvironment`

The `RuntimeBuildEnv` in mvm-runtime implements only `ShellEnvironment`. The full `BuildEnvironment` impl lives in mvmd-runtime.

### Key Design Decisions

- **Firecracker-only**: no Docker/containers. Builds run Nix inside the Lima VM.
- **No SSH in microVMs, ever**: microVMs are headless workloads. No sshd, no SSH keys, no SSH users in any rootfs. Guest communication uses Firecracker vsock only. The dev environment is the Lima VM (`mvmctl dev` / `mvmctl shell`), not the microVM.
- **Dev mode = Lima shell**: `mvmctl dev` auto-bootstraps then drops into the Lima VM shell. It does NOT start or SSH into a Firecracker microVM.
- **Headless microVMs**: `mvmctl start` and `mvmctl run` boot Firecracker as a daemon. No interactive access to the microVM.
- **Dev mode isolation**: `mvmctl start/stop/dev` use a completely separate code path from orchestration.
- **Shell scripts inside run_in_vm**: complex ops are bash scripts passed to `limactl shell`. Deliberate -- they run inside the Linux VM.
- **Idempotent setup**: every step checks if already done before acting.
- **Templates use dev_build path**: `mvmctl template build` runs `nix build` locally in the Lima VM (no ephemeral FC builder VMs).
- **mvm-core stays whole**: orchestration types (tenant, pool, instance, agent, protocol) remain in mvm-core even though they're only used by mvmd. This avoids a third shared-types crate and keeps the facade dependency simple.
- **No `clippy::too_many_arguments`**: never suppress this lint. Refactor into smaller functions or a config/params struct.

## Testing

No task is done without tests. Before marking any feature complete:

```bash
cargo test --workspace              # all tests must pass
cargo clippy --workspace -- -D warnings  # zero warnings
```

Every new module, type, or function needs test coverage:
- Types: serde roundtrip, default values
- Protocol/wire code: mock I/O roundtrip, tampered data rejection, error paths
- CLI: integration tests in `tests/cli.rs` for help text and argument parsing
- Security: positive path, negative path (wrong key, tampered, replay), edge cases

## Build and Run

```bash
cargo build
cargo run -- --help

# Dev mode
cargo run -- dev         # auto-bootstrap + drop into Lima shell
cargo run -- status      # check what's running

# Build from Nix flake
cargo run -- build --flake . --profile minimal --role worker
cargo run -- run --flake . --profile minimal --cpus 2 --memory 1024

# Templates
cargo run -- template create base --flake . --profile minimal --role worker --cpus 2 --mem 1024
cargo run -- template build base
cargo run -- template list
```

## Dev Network Layout

```
MicroVM (172.16.0.2, eth0)
    | TAP interface
Lima VM (172.16.0.1, tap0) -- iptables NAT -- internet
    | Lima virtualization
macOS / Linux Host
```

## Documentation

- `docs/development.md` -- contributor guide, testing, CI/CD
- `docs/user-guide.md` -- writing Nix flakes for microVM images
- `docs/SMOKE_TEST.md` -- smoke testing the dev workflow
- `docs/troubleshooting.md` -- common issues and fixes
- `docs/adr/001-firecracker-only.md` -- ADR: Firecracker-only execution
- `specs/plans/` -- implementation specs and plans

## Sprint Management

- Active sprint spec: `specs/SPRINT.md`
- Completed sprints archived to: `specs/sprints/` (e.g. `specs/sprints/01-foundation.md`)
- When a sprint is completed, rename `specs/SPRINT.md` to `specs/sprints/<NN>-<name>.md` and create a new `specs/SPRINT.md` for the next sprint
