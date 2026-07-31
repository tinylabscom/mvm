# Snix (Rust Nix re-implementation) evaluation — decision

Date: 2026-07-31
Status: decision — do not adopt snix now; revisit when it is stable and the
licensing is workable. Recorded so future sessions do not re-run the same
evaluation.

## Context

The goal was a faster, more reliable, Rust-native way to drive the Nix builds
that produce our attestable, hermetic microVM artifacts (kernels, rootfs
images, runtime overlays). snix.dev is a modern Rust re-implementation of the
Nix package manager's components (evaluator, store, builder), advertised as
library-first and Nixpkgs-compatible with binary-cache interoperability. The
question was whether we could use it as a library to replace or accelerate our
`nix build` orchestration.

## Findings

- **License is a hard blocker for library embedding.** Every snix crate
  (eval, store, build, glue) is **GPL-3.0**; only the protobuf definitions are
  MIT. Embedding snix as a library in mvm (MIT OR Apache-2.0) would make the
  linking binary (`mvmctl`) GPL-3.0. That is incompatible with our license
  posture, so the library-first usage the project would want is off the table.
  Using `snix-cli` as a subprocess (like the `nix` CLI) avoids the linking
  issue but yields no architectural benefit over the CLI we already use.
- **Maturity.** The project states plainly that none of its APIs are stable
  and that it is "no full-featured drop-in replacement for Nix yet." Flake
  support is partial/shim-based; our builds are flake-based (kernels, runtime
  overlay, `mkGuest`, initramfs publish path), so snix cannot drive them
  reliably today.
- **Bootstrapping.** snix itself is built with Nix (crate2nix), so adopting
  it would not remove the Nix dependency it is meant to accelerate — and
  building it is itself slow (a large Rust workspace; a timeboxed build of
  `snix.cli.default-cli` did not finish inside 15 minutes).
- **Upside noted for the future.** `snix/boot` boots microVMs off a
  `snix-store` via virtiofs — directly relevant to our microVM use case, and
  worth re-evaluating once the project is stable.

## Decision

Do not adopt snix now. Revisit when it reaches API stability and a license
compatible with embedding (or when a `snix-cli` binary is a proven drop-in
accelerator for `nix build`).

## Speed paths adopted instead

- **The universal initramfs is a deterministic cargo artifact** (PR #1996) —
  built via the cargo-zigbuild guest-agent cache plus a deterministic Rust
  cpio (epoch-zero, sorted, uid/gid 0, deterministic gzip), attested by its
  content hash. No Nix, fast cold-cache boot, fully attestable. Nix is
  retained for kernels, rootfs images, and the runtime overlay, where
  toolchain variance actually matters.
- **Determinate Nix binary caches** (`cache.flakehub.com`,
  `install.determinate.systems`) are already configured on the builder and
  make toolchain/dependency fetches fast.
- **Native arm64 builders** (e.g. the `ubuntu-24.04-arm` runners the kernel
  CI already uses) for aarch64 Nix builds — roughly 4 minutes native vs ~30
  minutes under QEMU user-mode emulation on the x86_64 builder. The aarch64
  initramfs was also verified to build hermetically via that emulation path
  (QEMU binfmt) as a fallback when no arm64 runner is available.
