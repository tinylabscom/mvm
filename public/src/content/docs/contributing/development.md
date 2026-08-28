---
title: Development Guide
description: Getting started as a contributor to mvm.
---

## Prerequisites

- **Rust 1.85+** (Edition 2024) — install via [rustup](https://rustup.rs)
- **macOS Apple Silicon or Linux** — macOS for development via HVF (26+) or libkrun (pre-26); Linux for native `/dev/kvm`. Intel Macs are not a supported local microVM host.
- **`zig` + `cargo-zigbuild`** — source-checkout contributors only; needed when a source build has to produce Linux helper binaries on demand, or when building a release artifact with `release-artifact-bootstrap`. End-users running a downloaded `mvmctl` don't need them.
- **Nix** — not needed on the host. Nix evaluation and `nix build` run inside the builder VM.

### Do I need to install libkrun?

It depends on your machine. The builder VM (the headless Linux guest that runs
`nix build` inside `mvmctl machine build` / `mvmctl machine run`) auto-selects
its host VMM:

| Host | libkrun (`slp/krun/*`) needed? |
|---|---|
| macOS 26+ Apple Silicon | **No** — auto-detect picks the **HVF** builder (Hypervisor.framework, ships with the OS, no Homebrew deps); mvm transparently retries with libkrun if HVF fails to create its VM (the ADR-007 builder auto-fallback). |
| macOS 13–25 Apple Silicon | **Yes** — `brew install slp/krun/libkrun slp/krun/libkrunfw`. |
| Linux + `/dev/kvm` | **No** — auto-detect picks the **QEMU** builder, so libkrun is not part of the default builder path on native Linux hosts. |

`mvmctl doctor` reports the resolved choice on the `builder backend`
line (`<backend> — <source> — <availability>`) and emits install hints
for anything missing — run it first and follow what it says.

### Getting started

```bash
git clone https://github.com/tinylabscom/mvm.git
cd mvm

# Source-checkout contributors exercising Linux helper/release builds:
# install the *pinned* zig + the Linux cross-targets for the active
# toolchain. Do NOT `brew install zig` — Homebrew's zig drifts off the
# pinned cargo-zigbuild and fails with a cryptic CacheCheckFailed.
just toolchain-embed

cargo build
cargo run -- doctor     # reports the builder backend + anything missing
cargo run -- bootstrap  # pre-fetch the builder VM image (optional — builds auto-bootstrap it)
```

> **Note — after a toolchain-version change.** `rust-toolchain.toml` pins an
> exact Rust version, and rustup keys installed cross-targets per toolchain
> *name*. When that pin changes (a version bump), rustup resolves a fresh
> toolchain that carries none of the Linux cross-targets, so `just check-linux`
> or an `mvmctl` build fails with `error[E0463]: can't find crate for core …
> target may not be installed`. Re-run `just toolchain-embed` to reinstall the
> targets for the new toolchain.

Or run the bootstrap script on a fresh machine:

```bash
./nix/ops/bootstrap/dev-setup.sh
```

## Building and Running

```bash
# Build
just build

# Prebuild the guest runtime overlay once so later required-overlay boots
# can reuse the cached artifact instead of rebuilding guest binaries.
just runtime-overlay-build

# Run CLI
just run -- --help

# Boot a throwaway workload — the (headless) builder VM auto-bootstraps
# on first use, then the workload boots on the platform's default backend.
just run -- machine run --image alpine -- uname -a

# Release build (stripped, LTO)
just release-build
```

The runtime-overlay command only builds the **guest-executed** runtime payload
and stores the sealed shared artifact under
`~/.mvm/cache/runtime-overlay/<version>/<arch>/`. Host-side binaries used for
bootstrap or supervision stay outside that overlay.

### Kernel builds

The builder-VM and workload microVM kernels are slim custom Linux
builds: one shared config in `nix/images/kernel/base.nix` plus a
per-variant delta (`workload.nix` adds dm-verity; `builder.nix` adds
the nix-build sandbox + egress-lockdown bits). Because the config is
custom, `cache.nixos.org` has no substitute, so the first build on a
fresh machine compiles the kernel from source. It can take several minutes
depending on the host and is memory-heavy; later builds reuse the persistent
Nix store.

`mvmctl build kernel build` makes that compile explicit and one-time. Image
backed runs from a source checkout also bootstrap this kernel automatically;
prebuilding it is useful when you want the first interactive run to be warm:

```bash
# Compile the builder kernel once into the cache + persistent nix store.
# The next build reuses it (substituted, not rebuilt).
just run -- build kernel build --which builder

# Or both kernels:
just run -- build kernel build --all

# The same policy applies to the direct kernel recipe:
MVM_KERNEL_SOURCE=download just kernel-workload
```

To skip the kernel compile entirely on a fresh machine, boot the builder
VM on a published kernel (once a release has shipped one):

```bash
# Build only the rootfs locally; fetch + hash-verify the kernel.
just run -- --kernel-source download bootstrap
# `auto` downloads if available, else compiles in-image (the default).
```

Notes:

- **Host-arch only for `--source compile`.** Stage 0 boots a host-arch
  VM under libkrun, so it builds your host's arch (aarch64 *or* x86_64).
  The other arch is published by the `kernel-build` GitHub workflow,
  which builds both on native runners — fetch it with `--source
  download` once a release ships it.
- On macOS the compile arm needs the libkrun trio (`slp/krun/*`), since
  Stage 0 is libkrun-backed even on HVF-default hosts.
- Editing `base.nix` or a variant delta? Just re-run the command — a
  custom config always compiles locally; downloads only ever return the
  kernel that shipped with that exact `mvmctl` release.

#### Iterating on the kernel config (slimming, adding a driver)

Changing `base.nix` / `workload.nix` / `builder.nix` and want to see the
effect? The loop is build → boot-smoke → measure:

```bash
# 1. Build the variant you touched (compiles your edited config in Stage 0).
just run -- build kernel build --which workload

# 2. Boot-smoke it — a kernel that builds isn't proof it boots. Boot a
#    throwaway VM and confirm the in-guest agent answers over vsock.
just run -- machine run --flake examples/sleeper --hypervisor libkrun --name smoke -d
just run -- machine boot-report smoke   # "control plane  ready" == good
just run -- machine stop smoke
```

Two sharp edges worth knowing:

- **A build that passes the config guard still has to boot.** After
  `make olddefconfig`, the build asserts every requested `enable` is
  still `=y` and fails loudly if one got dropped by a missing
  dependency — but that guard can't tell you a *disable* removed
  something the boot path needed. Only the boot-smoke proves that, so
  never skip step 2.
- **`enable` and `disable` are scoped.** A disable in the shared
  `base.nix` hits *both* kernels; if only the workload should drop a
  symbol (or only the builder needs one), put it in that variant's
  delta. (The builder kernel, for example, keeps netfilter for its
  egress lockdown while the workload drops it.)
- **You can't read the resolved `.config` locally** — Stage 0 hands the
  host a `vmlinux`, not the config. The `=y` symbol count + byte size
  come from the `kernel-build` CI lane, which uploads
  `workload-config-<arch>` and `kernel-metrics-<arch>.json`. Trigger it
  without a release via `gh workflow run kernel-build.yml`. The
  `check-kernel-config-budget` xtask gate fails CI if the `=y` count
  regresses past `KERNEL_Y_BUDGET`.

## Testing

```bash
# Run all tests with nextest
just test

# Test a single crate
just test-crate mvm-core

# Run tests matching a filter
just test-filter "test_snapshot"

# Full CI gate (lint + test)
just ci
```

### Test Organization

| Location | Type | What it tests |
|----------|------|---------------|
| `crates/*/src/**/*.rs` (`#[cfg(test)]`) | Unit tests | Internal functions within the crate |
| `crates/*/tests/*.rs` | Integration tests | Public API of each crate |
| `tests/cli.rs` | Binary tests | CLI arg parsing, help output, subcommand structure |

### Testing Conventions

- Unit tests go in `#[cfg(test)] mod tests {}` at the bottom of the source file
- CLI binary tests go in root `tests/cli.rs`
- Use `#[serde(default)]` when adding fields to structs used in test fixtures

### Gated E2E: the core-demo regression guard

`crates/mvm-cli/tests/core_demo_e2e.rs` exercises the whole `bootstrap → compile → machine run → vsock ping` spine end-to-end. It boots the persistent builder VM, lowers `examples/python/hello-app/app.py` to a flake, builds + boots the workload microVM, and waits for the guest agent to answer over vsock. Default-skips so it doesn't fire on routine `cargo test` runs; gate is `MVM_E2E_SMOKE=1`:

```bash
# Local run — requires libkrun + libkrunfw on pre-26 macOS, or
# native /dev/kvm on Linux. Threads `--hypervisor` per host.
MVM_E2E_SMOKE=1 cargo test -p mvm-cli --test core_demo_e2e -- --nocapture
```

The lane mirrored at `.github/workflows/ci.yml::core-demo-e2e` runs the same command on a self-hosted runner labelled `[self-hosted, macOS, ARM64, libkrun]`, gated on the `MACOS_LIBKRUN_AVAILABLE` repo variable. GitHub-hosted macOS runners cannot serve this lane (no nested HVF, no libkrun) — it stays opt-in until a self-hosted runner is wired.

The same gated convention covers `crates/mvm-sdk/sdks/python/tests/test_sandbox_exec.py`, which exercises `Sandbox.exec(*argv) -> ExecResult` against a real microVM. Default-skips on `pytest`; opt-in with `MVM_E2E_SMOKE=1 python -m pytest crates/mvm-sdk/sdks/python/tests/test_sandbox_exec.py`.

## Profiling

Functions carrying `#[instrument]` are timed when `MVM_SPAN_TIMINGS` is set.
Profiling is off otherwise — the timing layer is not installed at all.

```bash
MVM_SPAN_TIMINGS=1 mvmctl <command>              # table to stderr
MVM_SPAN_TIMINGS=json mvmctl <command>           # JSON to stderr
MVM_SPAN_TIMINGS=json MVM_SPAN_TIMINGS_OUT=/tmp/p.json mvmctl <command>
MVM_SPAN_TIMINGS=1 MVM_SPAN_TIMINGS_FILTER=mvm_fs=trace mvmctl <command>
```

The report is sorted by **self time** — time inside the function excluding
nested instrumented calls — which is the column that identifies what to
optimize. A row with high `total` but low `self` is an orchestrator whose cost
lives in a callee. `wall` above `total` means the span was open but not
entered; on async code that gap is time spent awaiting something else.

Percentiles come from a fixed-memory log-scale histogram and carry ~12% bucket
error. They are a profiling signal, not an SLO measurement.

Span timing is independent of `-v`: spans are measured even at the default
quiet log filter. To add a new measurement point, put `#[instrument(skip_all)]`
on the function. Prefer coarse entry points — recording takes a process-wide
lock on span close, so instrumenting a per-item inner loop distorts the
measurement it is meant to produce. Measured cost, debug build: 12 ns/span with
profiling off, ~4 us/span with it on, and aggregate throughput rises rather
than falls under contention (`cargo test -p mvm-core --test
span_timing_overhead -- --nocapture`).

When profiling is enabled, the served metrics endpoint also carries
`mvm_span_calls_total`, `mvm_span_self_seconds_total`,
`mvm_span_total_seconds_total`, and `mvm_span_max_seconds`, each labelled with
`target` and `span`. Nothing is exported when profiling is off. This is the
scrape endpoint only, not `mvmctl ops metrics`: a profile accumulates in the
process that ran the instrumented code, and a short-lived CLI invocation
renders its output before doing any work, so those series would always be
empty there.

To diff two runs rather than read two tables, `bench::span_profile` captures a
profile from a child `mvmctl` and compares them. It gates on **per-call** self
time, so a run with more iterations does not read as a regression, and reports
call-count changes separately — a function called twice as often is a different
defect from one that got slower.

## Linting and Formatting

```bash
just fmt          # Format all code
just clippy       # Lint (zero warnings required)
just lint         # Both format check + clippy
```

### Style Rules

- **Edition 2024**: `use` statements don't need `extern crate`; let chains supported
- **No `clippy::too_many_arguments`**: never suppress this lint — refactor into a params struct
- **No `format!()` in `format!()` named args**: extract to a variable first
- **Cross-crate imports**: always use `mvm_core::`, `mvm_runtime::`, etc.

## Architecture Principles

### Multi-Backend

mvmctl's supported local microVM hosts are native Linux with `/dev/kvm` and macOS Apple Silicon. Firecracker is the Linux baseline; HVF and libkrun-backed components cover Apple Silicon macOS. WSL2 nested KVM and a Hyper-V managed Linux builder are future backend work.

### Host vs. VM

All Linux build operations run inside the builder VM on macOS:

```rust
// On Linux this runs directly on the host; on supported macOS hosts it
// routes into the libkrun-backed builder VM.
mvm_runtime::shell::run_in_vm("ip link add br-tenant-1 type bridge")?;
```

On native Linux, `run_in_vm` executes directly on the host. On supported macOS Apple Silicon hosts, it delegates into the builder VM.

### Key Patterns

- **Idempotent operations**: every setup step checks if already done before acting
- **Config drive for metadata**: instance metadata delivered via read-only ext4 disk
- **Vsock, not SSH**: guest communication uses vsock directly on all supported backends
- **Same rootfs everywhere**: Nix-built ext4 images work on all backends

### Adding New Types

When adding fields to structs in serialized state:

1. Add `#[serde(default)]` to the new field for backward compatibility
2. `cargo test --workspace` to find all broken test constructions
3. Fix each one
4. Add a unit test for the new behavior

## Developer Workflow Commands

Beyond the standard build/test/lint cycle, mvmctl provides commands for managing the dev environment:

```bash
# First-time host setup (installs deps, stages the builder VM image)
just run -- bootstrap
# `init` is a different verb: it scaffolds mvm.toml + flake.nix in a project dir
just run -- init ./my-app

# Bundled image catalog — browse the entries `init --catalog` can scaffold from
just run -- catalog list            # browse bundled catalog
just run -- catalog search http     # search by name/tag
just run -- catalog info minimal    # show one entry
# (`mvmctl image` is a different namespace: pull/ls/inspect/rm of cached OCI images.)

# Named dev networks
just run -- network create isolated # create a named network
just run -- network list            # list all networks
just run -- machine run --flake .  # attach VM to a network

# Interactive console (PTY-over-vsock, no SSH) — `console` lives under `machine`
just run -- machine console myvm            # interactive shell
just run -- machine console myvm --command "uname -a"  # one-shot exec

# Cache and diagnostics
just run -- cache info              # show cache dir and disk usage
just run -- cache prune             # clean stale temp files
just run -- doctor                  # dependency checks + security posture
# There is no `security` verb — plan 40 folded it into `doctor`.
```

### Console Access

microVMs have no SSH. Interactive access is via `mvmctl machine console` which uses PTY-over-vsock:
- Authenticated via the existing Ed25519 vsock protocol
- Dev-mode only (`access.console` must be `true` in the guest security policy)
- Single session per VM, 15-minute idle timeout
- Supports Firecracker, libkrun, and HVF backends

### Directory Layout

All dev tool state lives under one root, `~/.mvm` (relocate the whole tree
with `MVM_HOME`; `rm -rf ~/.mvm` removes every trace):

| Path | Purpose |
|------|---------|
| `~/.mvm/` | Data: keys, audit chains, volumes, bundles, machine specs |
| `~/.mvm/vms/` | Per-VM state: sockets, pid files, console logs, FC workspace |
| `~/.mvm/cache/` | Build artifacts, images, VM runtime state |
| `~/.mvm/config/` | User config (`config.toml`) |
| `~/.mvm/run/` | Ephemeral per-session state |
| `~/.mvm/state/` | Logs, audit trail |
| `~/.mvm/share/` | Templates, network definitions, VM name registry |

## CI/CD

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| `ci.yml` | Push to main/feat/*, PRs | check, fmt, clippy, test (macOS + Linux), audit |
| `release.yml` | Tags matching `v*` | Builds 3 platform binaries (`aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`), creates GitHub Release |
| `publish-crates.yml` | Release published | Publishes to crates.io in dependency order |
| `pages.yml` | Release, version tag, or manual dispatch | Deploys docs to Cloudflare Pages |

### Website deployment

Run the site commands from the repository root through the `public` workspace:

```bash
pnpm --dir public install --frozen-lockfile
pnpm --dir public check
pnpm --dir public deploy
```

`pnpm --dir public deploy` builds the Astro site and publishes it to the
production branch of the existing `mvm` Pages project. Use
`pnpm --dir public deploy:preview` for a preview deployment.

Do not use `npx wrangler deploy` for this site. That is the Workers deployment
command; this repository hosts the website as a Pages project and uses
`wrangler pages deploy` through the scripts above.

## Release Process

```bash
# 1. Bump version in root Cargo.toml [workspace.package]
# 2. Update CHANGELOG.md
# 3. Commit and tag
git add -A && git commit -m "release: v0.3.0"
git tag v0.3.0

# 4. Push (triggers release.yml)
git push && git push --tags
```

The deploy guard (`scripts/deploy-guard.sh`) validates the tag matches the workspace version before publishing.
