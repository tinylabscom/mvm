---
title: Repository Layout
description: What each top-level entry of the mvm repository is for, who consumes it, and which paths are load-bearing.
---

This is a map, not a status ledger. Work status lives in GitHub issues. The
tracked top level is held to an allow-list by `cargo run -p xtask --
check-root-layout`; adding a root entry means editing that list in the same
change.

## Root entries

| Entry | Purpose | Consumed by |
| --- | --- | --- |
| `src/`, `build.rs`, `Cargo.toml`, `Cargo.lock` | The `mvmctl` root package: a thin entry over `mvm-cli` plus the facade re-exports. | cargo, release builds |
| `crates/` | The Rust workspace (see [Architecture](/reference/architecture/)). | everything |
| `xtask/` | Maintenance and claim-gate commands (`cargo run -p xtask -- check-*`). | `Justfile`, CI workflows |
| `third_party/` | Vendored, patched upstream crates. See below. | root `[patch.crates-io]` |
| `specs/` | PRD, ADRs (`specs/adrs/`), stable contracts, and design notes that are useful while an issue is open. | `check-adr-coverage`, `check-spec-hygiene`, `check-claim-catalog` |
| `schema/` | Versioned machine-readable interfaces (Workload IR, host ABI, protocol, policy profiles, SDK surface). | `xtask` generators (`gen_sdk_surface`, `gen_stubs`), SDK codegen |
| `model/` | The conformance register: `claims.toml`, `authorities.toml`, `ledger.toml`. `CONFORMANCE.md` is generated from them. | `check-conformance`, `features/` |
| `features/`, `tests/` | BDD scenarios (`features/suites/`) and root integration tests. | `mvm-conformance`, `cargo nextest` |
| `assets/` | macOS code-signing entitlement profiles (`mvmctl`, `mvm-supervisor`). | `build.rs`, installer tests, release workflow |
| `install.sh`, `uninstall.sh` | The published installer. Paths and hashes are pinned by tests and the release workflow; do not move them. | `tests/install_sh.rs`, `release.yml` |
| `AGENTS.md`, `CLAUDE.md`, `*.sigstore.json` | Contributor and agent instructions with detached signatures. | contributors, CI |
| `Justfile`, `just/` | Recipe entry point and per-area modules (`check`, `tests`, `lints`, `payload`, `release`, ...). | contributors, CI |
| `scripts/`, `bin/` | Shell and Python helpers used by recipes and workflows; `bin/dev` runs this checkout's `mvmctl`. | `Justfile`, workflows, tests |
| `.envrc.example` | Optional worktree-local direnv template; sources `scripts/dev-env.sh` when present. | contributors using direnv |
| `.gitignore` | Keeps local caches, generated outputs, secrets and editor state out of tracked source. | git, contributors |
| `nix/` | Nix library, packages, packaging and host operations. See below. | `flake.nix`, workflows, `mvm-build` |
| `flake.nix`, `flake.lock` | The contributor dev shell. The library flake that workload flakes import is `nix/flake.nix`. | `nix develop` |
| `public/` | The documentation site. | `website.yml` |
| `web/` | Browser-side demos and the WASM audit verifier. | `public/` |
| `examples/` | Runnable example workloads referenced by the docs. | docs coverage suite |
| `.cargo/`, `.config/`, `.githooks/`, `.github/` | Cargo config and guest target specs, nextest config, pre-commit hook, CI. | cargo, nextest, git, GitHub |
| `deny.toml`, `rust-toolchain.toml`, `treefmt.toml`, `cliff.toml` | Dependency policy, pinned toolchain, formatting, changelog generation. | cargo-deny, rustup, treefmt, git-cliff |
| `README.md`, `CHANGELOG.md`, `SECURITY.md`, `LICENSE` | Project front matter. | GitHub, release workflow |

## Verified root cleanup

The root allow-list guards the remaining entries; it is not a reason to move
live inputs merely to make the root shorter. [#5010](https://github.com/tinylabscom/mvm/pull/5010)
reduced `specs/` from 372 tracked files to 87, moved the live conformance
document to `model/`, and retired `docs/` (one obsolete guide removed, one
document moved). [#5059](https://github.com/tinylabscom/mvm/pull/5059) removed
three tracked agent-episode notes and one editor setting, keeping future local
state untracked. Those are measured removals; the remaining `nix/` package
ownership is deliberately unresolved until the image migration and release
gates in #4100 and #4764 are satisfied.

## `third_party/` versus `crates/deps/`

- `third_party/` holds **upstream source we did not write**, vendored only
  because the registry copy cannot be used as is (a one-line portability fix, a
  yanked release, a patched dependency). Each entry carries its license and
  provenance (`ORIGIN.toml`, `MVM-PROVENANCE.md`, or a `*-patches.md` note) and
  is wired in through `[patch.crates-io]` in the root `Cargo.toml`. Removing an
  entry means adopting the fixed upstream release and deleting its patch line.
- `crates/deps/` holds **workspace members that wrap or adapt something
  external**: `libkrun-sys` (the libkrun C FFI plus its safe wrapper) and
  `mvm-macho-sign` (byte-only Mach-O signing adapted from upstream code, with
  its own license and `PROVENANCE.md`). They are ordinary workspace crates for
  build and release purposes, are referenced by path from security and release
  workflows, and are not patch overrides.

The test is whether cargo resolves the crate through `[patch.crates-io]`
(`third_party/`) or as a workspace member (`crates/deps/`). Do not move either
without checking the workflows that name those paths.

## `nix/` by role

The Linux image layer (kernels, base root filesystems, builder image, Stage 0
seeds) belongs to `mvm-images`; the staged boundary is
[ADR-054](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/054-image-boundary-linux-layer.md)
(#4100). Nothing under `nix/` is transferred by this page; where ownership is
still being decided it is listed as such.

| Role | Paths | Notes |
| --- | --- | --- |
| Workload-author library | `lib/mk-guest.nix`, `lib/mkFunctionWorkload.nix`, `lib/factories/`, `profiles/`, `wrappers/` | `mkGuest` stays in mvm (ADR-054 rule 5). Evaluated by `nix/tests/` and `tests/nix_flake_structure.rs`. |
| Guest and host package builds | `packages/`, `lib/mvm-host-binaries.nix`, `lib/crates-io.nix`, `lib/workspace-filter.nix`, `lib/static-crates-cargo-deps.nix` | Some still feed mvm-images' `mvm` flake input until its side of #4100 lands (mvm-images#49, #64); ownership of those is undecided here. `packages/libkrunfw.nix` stays in mvm by decision. |
| Release packaging | `packaging/` (`release/`, `homebrew/`, `aur/`, `nixpkgs/`), `prebuilt-release.nix` | Referenced by `release.yml`, the distro and Homebrew workflows, and `just/release`. Signing and verification paths; do not move. |
| Host operations | `ops/` (bootstrap, systemd, Hetzner runners, permissions) | Scripts that mutate host state live here by rule; referenced by `workspace-shard.yml`. |
| Examples | `examples/` | Referenced by docs and example tests. |
| Flake entry | `flake.nix`, `flake.lock` | The library flake that workload flakes import. |

## Where things are checked

`check-root-layout` (root allow-list), `check-doc-links` and
`check-cli-help-matches-docs` (docs), `check-adr-coverage` and
`check-spec-hygiene` (specs), `check-conformance` (model). Run them with
`cargo run -p xtask -- <gate>`.
