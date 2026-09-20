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
temporary verifier. That authenticated verifier must support
`env verify-release`, and it must accept the downloaded bundle under the exact
selected tag before the full payload is extracted or installed.

An explicit non-default version cannot reuse the baked release's trust anchor.
It needs `MVM_TRUSTED_ARCHIVE_SHA256` from an independent trusted source, an
already installed verifier, or host `cosign`. Every route requires the bundle;
there is no unsigned fallback. A missing anchor, mismatched hash, missing
bundle, or invalid signature refuses without installing the payload.

## Witnesses

- `fresh_install_bootstraps_signature_verification_from_a_trusted_archive_hash`
- `fresh_install_refuses_without_a_verifier_or_trusted_archive_hash`
- `fresh_install_refuses_a_wrong_trusted_hash_before_executing_the_payload`
- `fresh_install_refuses_a_missing_signature_bundle`
- `workers_bakes_a_trusted_archive_hash_for_every_installer_target`
- `features/suites/s34_install_lifecycle/fresh_install_integrity.feature`
- `scripts/installer-compat/installer-compat.test.sh`

## Validation

- `cargo test --test install_sh`: 55 passed.
- `cargo test --test release_assets`: 50 passed.
- `sh scripts/installer-compat/installer-compat.test.sh`: passed.
- `just check-gated`: passed.
- `cargo run -p xtask -- check-all`: 74 gates passed.
- `cargo run -p xtask -- check-claim-catalog`: 20 claims and 120 witnesses
  passed.
- `just ci`: formatting, warnings-denied Clippy, 14,663 nextest tests, every
  doctest, the TypeScript build, and 256 runnable BDD scenarios passed; one
  scenario was skipped, with 79 explicitly excluded live, bundle, or work-in-
  progress scenarios reported by the harness.
