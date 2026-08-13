# Plan 316 — Local Linux builder-VM gates via `mvmctl __builder-shell-job`

## Status

**OPEN.** Spun out of Plan 315 because the HVF virtio-vsock fix was
complete and merged, but the macOS host still had no local path for running
Linux-native cargo gates. The missing piece is an exposed, scriptable way to
run arbitrary shell commands inside the project builder VM so contributors on
macOS can execute Linux-only checks without waiting for CI.

## Problem

Plan 315 proved the credit-regression fix with macOS tests and x86_64/aarch64
Linux cross-builds, but several gates are only meaningful on real Linux:

- `cargo test -p mvm-vmm` with Linux-only tests (vsock, jailer/seccomp,
  dm-verity, network namespaces, `/dev/kvm` and `/proc/net` paths).
- Crate-level `cargo clippy -p mvm-vmm --all-targets` against Linux-gated
  code.
- Broader workspace checks that the macOS host cannot compile because of
  Linux-only dependencies and features.

The macOS 26 execution tier auto-detects the HVF builder backend and has no
interactive builder-VM shell path. The existing `BuilderShellJob` /
`run_shell_script` machinery already supports libkrun, QEMU, and HVF, but it
is only used internally during builds; there is no CLI entry point for
arbitrary scripts.

## Scope and acceptance

- [ ] Add a hidden `mvmctl __builder-shell-job` command that:
  - accepts a host script path (`--script`) and stages it as `/job/cmd.sh`,
  - binds a host directory read-only at `/work` (default: cwd),
  - binds a host directory read-write at `/out` (default: temp dir),
  - dispatches to the selected builder backend (libkrun/HVF; QEMU may defer).
- [ ] Provide example scripts for common gates:
  - `scripts/linux-gate-mvm-vmm-test.sh` — run `cargo test -p mvm-vmm --quiet`,
  - `scripts/linux-gate-mvm-vmm-clippy.sh` — run `cargo clippy -p mvm-vmm --all-targets -- -D warnings`.
- [ ] Scripts bootstrap the pinned Rust 1.96 toolchain via `nix shell` into
      the persistent `/nix-store` disk so the first run is slow but later
      runs reuse the cache.
- [ ] Verify `mvm-vmm` tests and clippy pass inside the HVF builder VM.
- [ ] Update Plan 315 and `specs/SPRINT.md` to reference this plan.
- [ ] Record any remaining blockers (e.g., full workspace clippy inside the VM)
      honestly; do not claim gates that still require CI.

## Non-goals

- Solving the full workspace all-target Clippy cross-compile blocker inside
  the VM. `mvm-cli/build.rs` cross-compiles embedded host binaries with
  `cargo zigbuild --target aarch64-unknown-linux-musl`; the builder VM image
  lacks `zig`, `cargo-zigbuild`, and the `aarch64-unknown-linux-musl` target.
  Fixing that toolchain mismatch is out of scope and remains covered by CI's
  `lint-core` lane on native Linux.
- Making `__builder-shell-job` a public, documented command. It stays hidden
  because the builder VM is headless and the `/work`/`/out`/`/job/cmd.sh`
  contract is an internal build boundary.
- Adding QEMU backend support if it is not already wired for
  `run_shell_script`.
