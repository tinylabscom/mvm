# Plan 199 — host runtime packaging and crate-boundary simplification

**Status:** Complete — Workstreams A/B/B2/C and builder-VM Nix verification are done
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

- [x] Add reviewed, source-built Nix recipes for libkrun firmware and the
      libkrun shared library. `nix/packages/libkrunfw.nix` pins upstream
      `libkrunfw` v5.5.0 plus Linux 6.12.91 source and substitutes the kernel
      tarball into the upstream Makefile; `nix/packages/libkrun.nix` pins
      upstream `libkrun` v1.18.1 plus its Cargo vendor hash. Both follow the
      reviewed nixpkgs `stdenv.mkDerivation` source-build shape and contain no
      project release-binary provenance.
- [x] Expose the native VMM recipes only after their source pins, kernel source,
      cargo vendor hashes, and platform matrix are explicit in-tree. They are
      Linux-host-only package outputs (`libkrunfw`, `libkrun`,
      `mvmctl-native-libkrun`) and overlay attrs; Darwin keeps the source-built
      non-native `mvmctl` package only.
- [x] Wire
      `mvmctl.override { withNativeLibkrun = true; libkrun = ...; libkrunfw = ...; }`
      as the opt-in native package path. `packages.<linux>.mvmctl-native-libkrun`
      consumes the existing override seam; `packages.<system>.default` remains
      the non-native `mvmctl`.
- [x] Add a structural test that no mvm host package uses project release
      tarballs or `binaryNativeCode` provenance. →
      `no_host_package_uses_release_binary_provenance` in
      `tests/nix_flake_structure.rs` scans **every** `nix/packages/*.nix` (not
      just `mvmctl.nix`) for project-release / `binaryNativeCode` provenance.
      Deliberately project-release-specific (not a blanket `fetchurl` ban) so the
      future source-built `libkrun`/`libkrunfw` recipes — which legitimately
      fetch upstream *source* — stay valid; the strict no-fetch rule remains
      scoped to `mvmctl.nix`.

> **Builder-VM verification complete.** The native recipes carry real upstream
> source hashes, a pinned kernel source hash, and a Cargo vendor hash from the
> reviewed nixpkgs source-build shape. On 2026-06-19 the approved builder-VM Nix
> path verified `nix flake check` for `nix/`, `.#mvmctl`
> (`/nix/store/68xqmybxxlpckymlfqfvc1ka0x2yqvhx-mvmctl-0.16.1`), and
> `.#mvmctl-native-libkrun`
> (`/nix/store/0sg78jmbiv0yll6csmv8201ap167sm6m-mvmctl-0.16.1`).

### B2. Release installation policy

- [x] Document release-binary installation as the primary user path, separate
      from source-checkout Nix builds.
- [x] Define the release artifact matrix for Linux and macOS, including
      architecture, checksums, signatures, and provenance metadata. → documented
      in [`../notes/plan-199-release-artifact-matrix.md`](../notes/plan-199-release-artifact-matrix.md)
      (3 published binary targets + the deferred Intel-mac row; per-target
      sha256 + cosign bundle; combined manifest; signed SBOM; per-arch image set).
- [x] Decide whether a Nix expression that installs release binaries is useful
      for Nix users; if added, keep it separate from the source-built package
      and mark `binaryNativeCode` provenance explicitly. → **Decided: not now.**
      install.sh + Homebrew + `cargo install` cover binary install; the
      source-built `packages.<system>.mvmctl` is the Nix path. Revisit only on
      Nix-user demand; if added it must be a separate `binaryNativeCode`-marked
      package (WS-B's structural test already guards the source package against
      release tarballs).
- [x] Add release verification tests or CI checks proving every published
      archive has a checksum, signature, and matching `mvmctl --version`
      metadata. → `packaging/release/verify-release-assets.sh` (fail-closed:
      per-target tarball + matching sha256 + cosign signature bundle + manifest
      entry + signed SBOM, with `--cosign` validity check and a host-native
      `--expect-version` assertion) wired as the `verify-release` job in
      `release.yml` (needs `release`). Self-tested across happy-path + 6 tamper
      cases (bad checksum, missing signature, missing tarball, not-in-manifest,
      missing SBOM sig, version mismatch).
- [x] Keep install docs clear that package-manager and one-line installs do not
      require host Nix.

### C. Crate-boundary audit

Done 2026-06-16 — full write-up in
[`../notes/plan-199-crate-boundary-audit.md`](../notes/plan-199-crate-boundary-audit.md).
Headline: 17 crates, 328-crate default `mvmctl` closure; merging any two
workspace crates removes **0** closure crates, so crate count is not the
binary-size lever — boundaries are isolation/ownership decisions and are kept.

- [x] Record the current workspace package count and the reason each tiny crate
      exists. (17 crates inventoried; default closure 328; in-closure vs
      separate-target split recorded.)
- [x] Decide whether `mvm-sdk-macros` should stay as a crate or be removed until
      macro bodies actually ship. → **Remove**: zero dependents (orphaned empty
      placeholder); deletion is a pure subtraction across no boundary. Tracked as
      a tested follow-up commit.
- [x] Decide whether `mvm-mcp` remains independently useful or should move under
      the CLI surface. → **Keep the crate**; recommend a future `mcp` cargo
      feature on `mvm-cli` (code-size win only — it adds 0 new closure crates).
      Do not merge: keeps the JSON-RPC surface testable in isolation.
- [x] Keep `mvm-verify` separate unless the browser verifier stops needing a
      wasm-clean dependency surface. → **Keep** (wasm-clean, zero `mvm-*` deps,
      ADR-069; still required).
- [x] Keep `mvm-guest-helpers` as the grouped in-guest helper crate unless a
      smaller binary packaging split is proven useful. → **Keep grouped** (baked
      into the rootfs, never in the host binary; no smaller split proven).

**Surfaced actions (each its own tested follow-up):** (1) delete the orphaned
`mvm-sdk-macros`; (2) feature-gate `mvm-mcp` behind an `mcp` feature.

### D. Verification

- [x] `cargo test --test nix_flake_structure`
- [x] `cargo test --workspace`
- [x] `cargo check --workspace`
- [x] `cargo fmt --all --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] Builder-VM follow-up: `nix flake check` for `nix/`
- [x] Builder-VM follow-up: build `.#mvmctl` on at least one Linux system
- [x] Builder-VM follow-up: build `.#mvmctl-native-libkrun` on at least one
      Linux system
- [x] Release artifact follow-up: verify signature/checksum metadata for the
      published binary install path → `verify-release` job in `release.yml`
      (implemented + self-tested; executes on the next `v*` tag).

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
