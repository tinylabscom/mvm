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
- Added a deterministic Rust fixture under
  `tests/fixtures/capture/rust-hello/`; the redaction test creates its fake
  `.env` secret in a separate temporary project.
- Added library and CLI integration tests proving report versioning, secret
  redaction, canonical IR resolution, and Nix rendering.
- Added ADR-050 and plan `specs/plans/2026-08-20-mvm-capture.md`.
- Made the `.env` redaction witness self-contained: it creates the secret file
  in a temporary project and therefore runs identically in a clean CI checkout.
- Raised the all-features workspace closure ratchet by one, from 469 to 470,
  for the new first-party `mvm-capture` crate itself; its third-party
  dependencies were already present in the closure.
- Kept bounded ELF inspection portable across Linux architectures: metadata
  segments beyond the read prefix are omitted with an explicit warning rather
  than rejecting an otherwise valid executable and aborting the capture.
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
