# Drop the release step that signed image manifests nothing produces

Backing: shipped-source
Validation: cargo nextest run -p mvmctl --test release_assets

`release.yml` carried a "Sign image manifests" step that cosign-signed
`artifacts/*-image-*.manifest.json`. No job in the workflow writes a file with
that name, and no `mvmctl` path reads one: the per-variant manifest verifier
was retired in favour of image sets, which `mvmctl image boot verify` checks
offline. The step therefore took its empty-glob branch on every release,
printed a warning, and reported success having signed nothing — which reads in
the run log like a signature the release does not make.

The step is deleted. The dry-run test in `tests/release_assets.rs` no longer
lists it among the tag-gated steps, and a new test,
`the_release_does_not_sign_image_manifests_nothing_produces`, fails if the
workflow names `*-image-*.manifest.json` again. Signing a published image set
belongs where the set is published, not in the CLI release.

The remaining `cosign sign-blob` invocations (tarballs, checksum manifests,
SBOM, builder pack manifests) are unchanged, and
`every_signed_release_blob_uses_the_one_bundle_format` still finds all of them.
`actionlint` passes on the edited workflow.
