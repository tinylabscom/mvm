# SDK sidecar source build

Backing: shipped-source
Validation: check-sprint-append

## Problem

A contributor checkout can change `crates/mvm-sdk` while continuing to attach
the published, version-keyed `sdk.ext4`. The cached image remains structurally
valid but its guest-facing cdylib does not contain the checkout's host-service
verbs. Launches then fail inside the guest with an unrelated-looking
`unknown method` response.

The sidecar needs glibc and therefore cannot use the host's existing
static-musl Cargo artifact path. Host Nix is not an allowed fallback. The
existing runtime-overlay derivation is the source of truth and must be realized
inside Stage 0 through the project builder VM.

## Contract

- Source builds are explicit: `mvmctl build sdk-sidecar build`; a workload
  launch never boots the builder VM implicitly.
- The builder-VM flake passes through the runtime-overlay flake's
  `sdk-sidecar-image` output instead of copying its derivation.
- Stage 0 copies exactly `sdk.ext4`, `VERSION`, and
  `checksums-sha256.txt` to the host.
- The host verifies that contract and the expected version before replacing a
  cache entry.
- Artifact files and `SOURCE_FINGERPRINT` are promoted together, so provenance
  cannot temporarily misdescribe new bytes.
- `--force` rebuilds; otherwise a matching verified artifact is reused.
- Release binaries retain the existing signed published-download path.

## Work

- [x] Add regressions for CLI parsing, builder-flake passthrough, Stage 0
      sidecar-only copying, atomic provenance installation, version mismatch,
      and empty provenance.
- [x] Add the shared Stage 0 artifact runner and keep kernel builds on that
      runner rather than introducing another bootstrap implementation.
- [x] Add the explicit source-build command and actionable launch diagnostics.
- [x] Prove the Linux Stage 0 tests and Nix evaluation inside the builder VM.
- [x] Run workspace tests/checks, gated-target checks, zero-warning Clippy, and
      repository policy gates.
- [ ] Merge the PR and close issue #2941 through the merged PR link.
