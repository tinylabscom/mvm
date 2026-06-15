# Plan 199 — host runtime packaging and crate-boundary simplification

**Status:** Workstream A complete; Workstreams B/C pending  
**Owner:** mvm  
**Date:** 2026-06-15

## Goal

Make host installation and runtime dependency boundaries simpler without
weakening the project's source-build, builder-VM, and security guarantees.

The target shape is:

- The default user installation path is a signed release binary, package
  manager, or one-line installer. Host Nix is not part of the normal runtime
  contract.
- A Nix host package for `mvmctl` that builds from this checkout and its
  committed `Cargo.lock`, for users who already choose Nix as an optional
  install frontend.
- Optional release-binary packaging may exist for package managers that need it,
  but it must be labeled as release installation, not as the source-checkout
  build path.
- Native VMM linkage is explicit and opt-in in Nix, not accidentally pulled
  into every host package build.
- The user-facing image API remains `mvm.lib.<system>.mkGuest`; host package
  outputs do not blur into user microVM image outputs.
- Crate-count reduction is driven by ownership and security boundaries, not by
  a cosmetic package count.

## Non-goals

- Do not download mvm-published release binaries from source-checkout builds.
- Do not move Nix builds/evals or microVM operations out of the builder VM.
- Do not make host Nix a prerequisite for normal mvm development or runtime
  use.
- Do not present optional Nix packaging as the beginner installation path.
- Do not merge crates that currently enforce platform, FFI, wasm, guest/host, or
  process-boundary isolation unless a dependency-graph review proves the merge
  preserves those boundaries.
- Do not rename public commands or change the `mvmctl` UX as part of this plan.

## Workstreams

### A. Source-built host package

- [x] Add `nix/packages/mvmctl.nix`, building `mvmctl` from `mvmSrc` and the
      committed `Cargo.lock`.
- [x] Expose `packages.<system>.mvmctl`, `packages.<system>.default`, and
      `overlays.default` from `nix/flake.nix` for Linux and Darwin host systems.
- [x] Keep `lib.<system>.mkGuest` restricted to Linux image systems.
- [x] Add source-grep tests that reject project release downloads in the host
      package and require native libkrun linkage to stay explicit.
- [x] Document the Nix install path in the installation guide as optional,
      preserving the no-host-Nix default.

### B. Native VMM package recipes

- [ ] Add reviewed, source-built Nix recipes for libkrun firmware and the
      libkrun shared library.
- [ ] Expose the native VMM recipes only after their source pins, kernel source,
      cargo vendor hashes, and platform matrix have been verified in the builder
      VM.
- [ ] Wire `mvmctl.override { withNativeLibkrun = true; libkrun = ...; }` as the
      opt-in native package path once the recipes are verified.
- [ ] Add a structural test that no mvm host package uses project release
      tarballs or `binaryNativeCode` provenance.

### B2. Release installation policy

- [x] Document release-binary installation as the primary user path, separate
      from source-checkout Nix builds.
- [ ] Define the release artifact matrix for Linux and macOS, including
      architecture, checksums, signatures, and provenance metadata.
- [ ] Decide whether a Nix expression that installs release binaries is useful
      for Nix users; if added, keep it separate from the source-built package
      and mark `binaryNativeCode` provenance explicitly.
- [ ] Add release verification tests or CI checks proving every published
      archive has a checksum, signature, and matching `mvmctl --version`
      metadata.
- [x] Keep install docs clear that package-manager and one-line installs do not
      require host Nix.

### C. Crate-boundary audit

- [ ] Record the current workspace package count and the reason each tiny crate
      exists.
- [ ] Decide whether `mvm-sdk-macros` should stay as a crate or be removed until
      macro bodies actually ship.
- [ ] Decide whether `mvm-mcp` remains independently useful or should move under
      the CLI surface.
- [ ] Keep `mvm-verify` separate unless the browser verifier stops needing a
      wasm-clean dependency surface.
- [ ] Keep `mvm-guest-helpers` as the grouped in-guest helper crate unless a
      smaller binary packaging split is proven useful.

### D. Verification

- [x] `cargo test --test nix_flake_structure`
- [x] `cargo test --workspace`
- [x] `cargo check --workspace`
- [x] `cargo fmt --all --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Builder-VM follow-up: `nix flake check --no-build` for `nix/`
- [ ] Builder-VM follow-up: build `.#mvmctl` on at least one Linux system
- [ ] Release artifact follow-up: verify signature/checksum metadata for the
      published binary install path

## Security notes

- Source-checkout builds must be reproducible from checked-in source plus pinned
  upstream inputs. A source checkout silently pulling a project release binary
  would bypass local review and CI expectations.
- Native VMM linkage crosses the FFI boundary. It must stay explicit in Nix so a
  host package build cannot accidentally require headers or shared libraries
  that are absent from normal Linux and CI hosts.
- The builder VM remains the Linux execution boundary for Nix builds/evals and
  microVM runtime operations. Host package definitions are inert until evaluated
  through the approved builder path.
- Host Nix remains optional. The default mvm UX still installs and runs from the
  host CLI while the builder VM owns Linux Nix work.
- Binary release installation must be signed and checksummed. Package-manager
  convenience must not replace signature/provenance verification.
- Crate consolidation cannot cross security boundaries just to reduce the
  workspace package count. Guest, host, wasm-clean verifier, native FFI, and
  process-boundary crates remain separate unless the audit proves the merge
  preserves those boundaries.
