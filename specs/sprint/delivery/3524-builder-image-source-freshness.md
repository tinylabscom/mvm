# Builder image source freshness (#3524)

Status: implementation and host-side validation complete; merge-queue delivery
pending.

## Problem

`ensure_builder_vm_image` accepted a structurally valid configured cache before
the Stage 0 bootstrap path compared its `.mvm-source.sha256` marker with the
current checkout. Its fallback seeding path likewise copied a digest-consistent
host-wide image without checking whether it represented the current Nix inputs
and embedded host binaries. A builder job could therefore boot older PID 1 and
egress binaries even though an explicit bootstrap would rebuild them.

## Resolution

- The generic builder-image loader now accepts the authoritative current
  source fingerprint from the CLI layer that owns Stage 0 and the embedded
  host-binary table.
- Configured and shared cache candidates must carry the matching fingerprint;
  a missing or different marker is a normal cache miss and reaches the existing
  bootstrap fallback.
- An unembedded contributor binary cannot calculate the authoritative binary
  identity. It asks its existing fresh embedded bootstrap helper to run the
  canonical cache-readiness decision before loading the image. A skipped or
  declined preflight fails closed instead of loading an unverified cache.
- A process with no source checkout, and a library embedder that has not
  registered the CLI resolver, retains the previous artifact-only behavior.

## Regression witnesses

- A configured cache recorded against an older source/binary identity is
  refused.
- A configured cache with no source-fingerprint marker is refused.
- A host-wide seed recorded against an older source/binary identity is not
  copied into an isolated cache.
- A release-style cache with no source fingerprint remains loadable when no
  source fingerprint applies.
- A declined source-checkout helper preflight cannot load a structurally valid
  but unverified cache.
- The pre-existing `ensure_builder_vm_image` manifest, seed, and auto-bootstrap
  tests remain green.

## Validation

- Test-first compile failed on the missing freshness helpers, proving the new
  regressions preceded implementation.
- `cargo test -p mvm-build builder_vm_image::tests:: -- --test-threads=1`:
  7 passed.
- `cargo test -p mvm-build ensure_builder_vm_image -- --test-threads=1`:
  7 passed.
- `cargo check -p mvm-cli`: green.
- `cargo check --workspace`: green.
- `cargo test --workspace -- --test-threads=1`: every unit and integration
  suite passed; the final `mvm-build` rustdoc step encountered a transient
  E0463 artifact lookup for `mvm_sdk`.
- `RUSTC_WRAPPER= cargo test -p mvm-build --doc`: green after a direct rebuild
  (0 failed), closing the only failure from the combined workspace run.
- `cargo clippy --workspace --all-targets -- -D warnings`: green with zero
  warnings.
- `just check-gated`: green for the Linux workspace/all-target cross-check and
  the `mvm-conformance` BDD feature target.
- `cargo fmt --all --check`: green.
- `cargo run -q -p xtask -- check-all`: green.
