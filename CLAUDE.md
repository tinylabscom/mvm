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
- `mvm-cli` -- Clap CLI, bootstrap, update, doctor, template commands

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

mvm-core: `build_env.rs` (ShellEnvironment + BuildEnvironment traits), `pool.rs`, `instance.rs`, `tenant.rs`, `template.rs`, `naming.rs`, `signing.rs`, `routing.rs`, `protocol.rs`, `agent.rs`, `catalog.rs` (image catalog), `dev_network.rs` (named networks), `config.rs` (XDG directory functions)

mvm-runtime: `shell.rs`, `config.rs`, `ui.rs`, `build_env.rs` (DevShellEnv impl), `vm/lima.rs`, `vm/firecracker.rs`, `vm/microvm.rs`, `vm/network.rs`, `vm/image.rs`, `vm/template/`

mvm-build: `dev_build.rs` (local Nix builds via ShellEnvironment), `build.rs` (orchestrated builds via BuildEnvironment), `nix_manifest.rs`, `scripts.rs`

mvm-guest: `vsock.rs`, `console.rs` (PTY-over-vsock), `integrations.rs`, `builder_agent.rs`

mvm-cli: `commands.rs` (network, image, console, cache, init, security commands), `bootstrap.rs`, `template_cmd.rs`, `doctor.rs`, `update.rs`, `http.rs`, `logging.rs`, `ui.rs`

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
- **No SSH in microVMs, ever**: microVMs are headless workloads. No sshd, no SSH keys, no SSH users in any rootfs. Guest communication uses Firecracker vsock only. The dev environment is the Lima VM (`mvmctl dev` / `mvmctl dev shell`), not the microVM. See **Security model** below for the full posture.
- **Dev mode**: `mvmctl dev` (or `mvmctl dev up`) auto-bootstraps then drops into a dev shell. On macOS 26+ Apple Silicon: boots an Apple Container with Nix + build tools via PTY-over-vsock console. On macOS <26 or Linux without KVM: uses Lima VM. Use `--lima` to force Lima fallback. `mvmctl dev down` stops it. `mvmctl dev shell` opens a shell. `mvmctl dev status` shows environment info. It does NOT start or SSH into a Firecracker microVM.
- **Headless microVMs**: `mvmctl start` and `mvmctl run` boot Firecracker as a daemon. Interactive access via `mvmctl console` (PTY-over-vsock, dev-mode only).
- **Dev mode isolation**: `mvmctl start/stop/dev` use a completely separate code path from orchestration.
- **Shell scripts inside run_in_vm**: complex ops are bash scripts passed to `limactl shell`. Deliberate -- they run inside the Linux VM.
- **Idempotent setup**: every step checks if already done before acting.
- **Templates use dev_build path**: `mvmctl template build` runs `nix build` locally in the Lima VM (no ephemeral FC builder VMs).
- **mvm-core stays whole**: orchestration types (tenant, pool, instance, agent, protocol) remain in mvm-core even though they're only used by mvmd. This avoids a third shared-types crate and keeps the facade dependency simple.
- **No `clippy::too_many_arguments`**: never suppress this lint. Refactor into smaller functions or a config/params struct.

## Security model

mvm makes seven CI-enforced security claims. Each one is backed by a
test or a workflow gate; ADR-002 (`specs/adrs/002-microvm-security-posture.md`)
describes the threat model and `specs/plans/25-microvm-hardening.md`
sequences the implementation.

1. **No host-fs access from a guest beyond explicit shares.** Per-service
   uid (W2.1), seccomp `standard` default (W1.1, W2.4), and `setpriv
   --bounding-set=-all --no-new-privs` (W2.3) confine each service.
2. **No guest binary can elevate to uid 0.** `setpriv --no-new-privs`
   in the launch path; `/etc/{passwd,group,nsswitch.conf}` are
   read-only bind-mounts so a compromised service can't mint a uid 0
   entry (W2.2).
3. **A tampered rootfs ext4 fails to boot.** dm-verity sidecar +
   kernel-cmdline roothash (W3 — separate sprint).
4. **The guest agent does not contain `do_exec` in production
   builds.** `prod-agent-no-exec` job in `.github/workflows/ci.yml`
   builds the agent without `dev-shell` and asserts the
   `mvm_guest_agent::do_exec` symbol is absent (W4.3).
5. **Vsock framing is fuzzed.** `cargo-fuzz` targets at
   `crates/mvm-guest/fuzz/` cover `GuestRequest` and
   `AuthenticatedFrame` (W4.2). `#[serde(deny_unknown_fields)]` on
   every host↔guest type ensures unexpected fields fail-closed (W4.1).
6. **Pre-built dev image is hash-verified.** `download_dev_image`
   fetches the per-arch `*-checksums-sha256.txt` manifest, streams
   the artifact through SHA-256, and rejects + deletes on mismatch
   (W5.1). `MVM_SKIP_HASH_VERIFY=1` is the documented emergency
   escape; never set it in CI.
7. **Cargo deps are audited on every PR.** `deny.toml` + the `deny`
   and `audit` jobs in CI (W5.2). Reproducibility double-build
   (W5.3) catches non-determinism that could mask injection.

The guest agent itself runs as uid 901 under setpriv (W4.5); the
host-side vsock proxy socket is mode 0700 (W1.2), the proxy port
allowlist drops anything outside the agent and forward ranges
(W1.3), and `~/.mvm` / `~/.cache/mvm` are mode 0700 (W1.5).

Out of scope (named in ADR-002):

- A malicious *host*. mvmctl trusts the host with the hypervisor and
  private build keys.
- Multi-tenant guests. One guest = one workload.
- Hardware-backed key attestation.

`mvmctl security status` reports the live posture on the running
host. Architecture detail in
`specs/adrs/002-microvm-security-posture.md`. Implementation
sequence in `specs/plans/25-microvm-hardening.md`.

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
cargo run -- dev         # auto-bootstrap + drop into Lima shell (alias for dev up)
cargo run -- dev up      # same as above, explicit
cargo run -- dev down    # stop the Lima dev VM
cargo run -- dev shell   # open shell in running Lima VM
cargo run -- dev status  # show dev environment status

# Build from Nix flake
cargo run -- build --flake . --profile minimal --role worker
cargo run -- run --flake . --profile minimal --cpus 2 --memory 1024

# Templates
cargo run -- template create base --flake . --profile minimal --role worker --cpus 2 --mem 1024
cargo run -- template build base
cargo run -- template list

# Image catalog
cargo run -- image list              # browse bundled catalog
cargo run -- image search http       # search by name/tag
cargo run -- image fetch minimal     # build from catalog entry

# Networks
cargo run -- network create isolated # create named network
cargo run -- network list            # list all networks
cargo run -- network remove isolated # remove a network

# Console (interactive PTY, dev-mode only)
cargo run -- console myvm            # interactive shell
cargo run -- console myvm --command "uname -a"  # one-shot exec

# Setup & diagnostics
cargo run -- init                    # first-time setup wizard
cargo run -- security status         # security posture evaluation
cargo run -- cache info              # cache directory info
cargo run -- cache prune             # clean stale temp files
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

- `public/src/content/docs/contributing/development.md` -- contributor guide, testing, CI/CD
- `public/src/content/docs/guides/nix-flakes.md` -- writing Nix flakes for microVM images (mkGuest API)
- `public/src/content/docs/guides/troubleshooting.md` -- common issues and fixes
- `public/src/content/docs/contributing/adr/001-firecracker-only.md` -- ADR: Firecracker-only execution
- `public/src/content/docs/reference/cli-commands.md` -- complete CLI command reference
- `specs/plans/` -- implementation specs and plans

## Sprint Management

- Active sprint spec: `specs/SPRINT.md`
- Completed sprints archived to: `specs/backlog/` (e.g. `specs/backlog/01-foundation.md`)
- When a sprint is completed, rename `specs/SPRINT.md` to `specs/backlog/<NN>-<name>.md` and create a new `specs/SPRINT.md` for the next sprint
