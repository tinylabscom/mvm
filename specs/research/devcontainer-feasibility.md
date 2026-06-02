# Devcontainer for mvm — feasibility note

Captures whether a `.devcontainer/` makes sense for this repo, scoped to the
Linux-primary contributor workflow. Research/advisory only — **not a plan, not
a commitment to implement.**

## TL;DR

Worth doing, but with a sharp boundary on scope. A devcontainer cleanly covers
the **edit/build/unit-test loop** (`cargo build / test / clippy / fmt`, `just
ci`) with CI parity. It does **not** cover the **boot-a-microVM loop**:
Firecracker / cloud-hypervisor need `/dev/kvm`, which only works inside a
container on a Linux-KVM host with the device passed through and nested virt
available — not under Docker Desktop on macOS. This mirrors how CI itself
splits its lanes (KVM lanes gated to `main`/release tags).

A devcontainer is a *contributor dev environment*, not the runtime path, so it
does **not** conflict with the CLAUDE.md invariants ("no Docker/containers on
the runtime path", "host Nix is never used by mvmctl"). `mvmctl` running inside
the container still routes all Nix evaluation through a builder VM; the
container is only where `cargo` and the editor run.

## What a devcontainer would replicate

The per-PR Linux lanes in `.github/workflows/ci.yml` have a real system-dep
footprint that today lives only in CI YAML and contributors' heads:

- Rust **stable + nightly** (clippy, rustfmt). `rust-toolchain.toml` pins
  stable; several lanes pull `dtolnay/rust-toolchain@nightly`.
- `libcap-ng-dev` + `lld` — `mvm-libkrun` links against system `libcap-ng`.
- **zig + cargo-zigbuild** via `.github/actions/install-zigbuild` —
  `crates/mvm-cli/build.rs` cross-compiles the embedded host-vm binaries
  (`mvm-host-vm-init`, `mvm-egress-proxy`) as static
  `aarch64-unknown-linux-musl` (Plan 115 / ADR-065).
- **passt** at `/usr/bin/passt` — the Linux networking gateway; the
  `confine_self()` landlock path is fail-closed on its absence.

This is precisely the set a new contributor gets wrong. Baking it into a
devcontainer gives a reproducible inner-loop environment with CI parity. Clear
win.

## The hard boundary: the VM E2E path

- The runtime path is **Firecracker on `/dev/kvm`** (plus the `ch` /
  `workload-spawn` lanes). Those CI lanes are gated to `main` / release tags
  precisely because they need KVM.
- A devcontainer is Docker. Running Firecracker inside it needs
  `--device=/dev/kvm` passed through **and** a host that actually exposes KVM.
  Works on a bare-metal / VM Linux host with nested virt enabled. Does **not**
  work under Docker Desktop on macOS (the container sits inside a lightweight
  Linux VM where nested KVM generally isn't available).

Honest framing for any future README: the devcontainer covers the
edit/build/unit-test loop, not the boot-a-microVM loop. Stating this up front
heads off "Firecracker won't boot in the devcontainer" issues.

## Two things to reconcile before designing one

1. **Nix already exists** (`nix/flake.nix`, exercised by the `nix-flake-check`
   CI lane). If there is (or will be) a `devShell` in there, a devcontainer
   overlaps with it. Prefer having the devcontainer *enter the Nix dev shell*
   over re-declaring toolchain versions in two places that will drift.
2. **`install-zigbuild` is a composite action.** A devcontainer must reuse the
   same pinned zig version, not hardcode a different one, or it reintroduces
   the drift it is meant to kill.

## Recommendation (if pursued later)

Scope it as a **build/test devcontainer** that:

- installs the apt set (`libcap-ng-dev`, `lld`) + zig/cargo-zigbuild + passt to
  match CI,
- declares `--device=/dev/kvm` only as an *opt-in* mount, documented for
  Linux-KVM hosts only,
- defers to the Nix dev shell for toolchain versions if one exists, rather than
  duplicating them.
