# Fresh installs require a release signature without host `cosign`

Epic #3277 closure.

The remaining install-lifecycle gap was the first run on a host with neither
`mvmctl` nor `cosign`. The installer could verify the release-manifest checksum,
but the manifest arrived over the same channel and signature verification was
only a warning.

The stable installer now carries a SHA-256 trust anchor for each archive of its
baked release. The release deployment step verifies the published checksum
manifest's bundle under the exact release-workflow tag identity, then replaces
all three anchors before deploying `install.sh`. A fresh install checks that
anchor before extracting or executing only the archive's `mvmctl` as a
temporary verifier. If that legacy archive predates `env verify-release`, the
installer downloads a temporary cosign with a code-reviewed version and
target-specific SHA-256, verifies its bytes before execution, and uses it for
the same exact-tag check. The full payload is extracted or installed only
after signature verification succeeds.

An explicit non-default version cannot reuse the baked release's trust anchor.
It may receive `MVM_TRUSTED_ARCHIVE_SHA256` from an independent source;
otherwise the installer skips its in-archive verifier and uses the pinned
temporary cosign, so no archive byte executes before signature verification.
Every route requires the bundle; there is no unsigned fallback. A mismatched
supplied hash, invalid verifier hash, missing bundle, or invalid signature
refuses without installing the payload.

## Witnesses

- `fresh_install_bootstraps_signature_verification_from_a_trusted_archive_hash`
- `fresh_install_without_an_archive_hash_never_executes_the_payload_before_verification`
- `fresh_install_refuses_a_wrong_trusted_hash_before_executing_the_payload`
- `fresh_install_refuses_a_missing_signature_bundle`
- `fresh_install_bootstraps_pinned_cosign_for_a_legacy_release`
- `fresh_install_refuses_a_mismatched_bootstrap_cosign_hash`
- `workers_bakes_a_trusted_archive_hash_for_every_installer_target`
- `features/suites/s34_install_lifecycle/fresh_install_integrity.feature`
- `scripts/installer-compat/installer-compat.test.sh`

## Validation

- `cargo test --test install_sh`: 57 passed.
- `cargo test --test release_assets`: 51 passed.
- `sh scripts/installer-compat/installer-compat.test.sh`: passed.
- `just check-gated`: passed.
- `cargo run -p xtask -- check-all`: 74 gates passed.
- `cargo run -p xtask -- check-claim-catalog`: 20 claims and 120 witnesses
  passed.
- `just ci`: formatting, warnings-denied Clippy, 14,663 nextest tests, every
  doctest, the TypeScript build, and 256 runnable BDD scenarios passed; one
  scenario was skipped, with 79 explicitly excluded live, bundle, or work-in-
  progress scenarios reported by the harness.
