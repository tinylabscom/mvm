# Delivery: Evidence-Backed Linux Environment Capture Frontend

Implemented the first slice of `mvm capture`.

- Added `crates/mvm-capture/` with versioned `CaptureReportV1`, bounded
  project-directory scanning, native package ownership behind a provider trait
  (Debian `dpkg` implemented; `rpm`/`pacman`/`apk` stubs), optional
  `nix-index` resolution, bounded `strace`-backed dynamic tracing for explicit
  commands, safe read-only ELF metadata inspection, builder-VM flake-build
  verification, and deterministic resolution into
  `mvm_contract::ir::Workload`.
- Added user guide `public/src/content/docs/guides/capture.md` and updated
  CLI reference `public/src/content/docs/reference/cli-commands.md`.
- Added `mvmctl capture project|resolve|verify` commands in
  `crates/mvm-cli/src/commands/capture/`.
- Reused the existing Nix renderer via `mvm_sdk::compile::compile`; no new
  templating engine was introduced.
- Added deterministic Rust fixture under `tests/fixtures/capture/rust-hello/`
  with fake `.env` secret for redaction testing.
- Added library and CLI integration tests proving report versioning, secret
  redaction, canonical IR resolution, and Nix rendering.
- Added ADR-049 and plan `specs/plans/2026-08-20-mvm-capture.md`.
- Updated `public/src/content/docs/reference/cli-commands.md` and added
  `public/src/content/docs/guides/capture.md`.

Limitations: boot-and-replay verification boots a microVM inside the builder VM
and replays the command as the guest entrypoint; it has been validated end-to-end
on the macOS libkrun backend and produces a verification record, but the actual
guest replay currently fails because the local source-checkout builder-VM image
build fails on a pre-existing `mvm-setpriv-static` Nix derivation error
(`genericBuild: command not found`), which is independent of the capture pipeline;
native package names (dpkg/rpm/pacman/apk) remain unresolved rather than guessed
into `nixpkgs` attributes; CPU-feature extraction from ELF or auxiliary sources is
not yet implemented.
