# Plan: Evidence-Backed Linux Environment Capture Frontend

Backing: shipped-source
Validation: `cargo test -p mvm-capture` and capture CLI integration tests

## Goal

Implement the first production-oriented slice of `mvm capture`: a CLI path
that inspects a Linux project, emits a reviewable capture report, resolves it
into the existing canonical MVM IR, renders Nix through the existing
renderer, and records a verification command for later replay.

## Status

Phase 1 complete.

## Design

See `specs/adrs/050-mvm-capture-project-environment.md`.

## Implemented

- [x] New isolated crate `crates/mvm-capture/`.
- [x] Versioned `CaptureReportV1` schema with observations, platform facts,
      unresolved items, and warnings.
- [x] Project-directory collector with bounded traversal (max files, depth,
      file size, total bytes, elapsed time).
- [x] Manifest detection for Cargo, Node, Python, Go, Nix, Docker, and
      existing MVM manifests.
- [x] Secret classification and redaction (`.env` content hashes and paths
      are removed from reports).
- [x] Linux-specific collectors for executable path resolution and Debian
      package ownership via `dpkg -S` / `dpkg-query -W`.
- [x] Deterministic resolution into `mvm_contract::ir::Workload`.
- [x] CLI commands: `mvmctl capture project`, `mvmctl capture resolve`,
      `mvmctl capture verify`.
- [x] `capture verify` renders `flake.nix`, `launch.json`, and
      `workload.json` via `mvm_sdk::compile::compile`.
- [x] Deterministic Rust fixture project under
      `tests/fixtures/capture/rust-hello/`.
- [x] Library tests proving report versioning, secret redaction, canonical IR
      resolution, and Nix rendering.
- [x] Safe, read-only ELF metadata inspection for discovered executables:
      architecture, interpreter (`PT_INTERP`), declared shared libraries
      (`DT_NEEDED`), and GNU build-id (`PT_NOTE`). Discovered executables are
      never run and `ldd` is never invoked.
- [x] Package-provider abstraction: native package ownership/version queries
      moved behind a `PackageProvider` trait with a `dpkg` implementation and
      `rpm`/`pacman`/`apk` stubs.
- [x] Optional `nix-index` resolver: observed executables with no native
      package match are looked up via `nix-locate`; matches are resolved into
      the canonical workload as inferred Nix packages.
- [x] Bounded dynamic tracing: explicit user commands are run under `strace`
      (with `timeout`-enforced wall-clock limit and bounded output size), and
      observed `open`/`connect`/`execve` events are recorded as artifact,
      network, and executable observations.
- [x] Verification status schema and `capture verify` integration: verification
      commands are recorded by default; with `--exec-in-builder-vm` the
      rendered flake is built inside the Linux builder VM via
      `mvmctl __builder-shell-job` and a status report is emitted.
- [x] Documentation: user guide under `public/src/content/docs/guides/capture.md`
      and CLI reference updates in `public/src/content/docs/reference/cli-commands.md`.
- [x] CLI integration tests proving help visibility and the
      project→resolve workflow.
- [x] ADR-050 and this plan.

## Remaining work (next smallest phases)

1. ~~ELF inspection~~ — completed.
2. ~~Package-provider abstraction~~ — completed.
3. ~~Nix-index resolver~~ — completed.
4. ~~Dynamic tracing~~ — completed.
5. ~~Boot-and-replay verification~~ — `capture verify --boot-and-replay` dispatches
   a builder-VM shell job that boots a microVM from the rendered flake and
   replays the verification command as the guest entrypoint. Validated end-to-end
   on the macOS libkrun backend: the verification record is produced and the
   builder-VM shell job is invoked. The actual guest replay does not yet succeed
   because the local source-checkout builder-VM image build fails on a pre-existing
   `mvm-setpriv-static` Nix derivation error (`genericBuild: command not found`),
   which is independent of the capture pipeline.
6. ~~Documentation~~ — completed.

## Acceptance criteria

- [x] Workspace builds and affected tests pass.
- [x] `cargo clippy -p mvm-capture -- -D warnings` passes.
- [x] The secret-redaction fixture creates its own ignored `.env` input, so a
      clean checkout exercises the privacy boundary without relying on an
      untracked developer file.
- [x] Fixture project produces a versioned capture report.
- [x] Report resolves into canonical MVM IR.
- [x] Canonical IR renders through the existing Nix path.
- [x] Unresolved dependencies remain explicit.
- [x] Secret values do not appear in reports, snapshots, IR, or generated Nix.
- [x] Filesystem traversal is bounded.
- [x] No discovered executable is run automatically.
- [x] Linux-specific functionality is isolated from unsupported platforms.
- [x] Full workspace clippy passes with `--all-targets -- -D warnings`.
