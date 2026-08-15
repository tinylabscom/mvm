# Signed checksum manifests

Every prebuilt artifact download — builder VM, default microVM, kernel, release
tarballs — hashes the file and compares it against a `sha256sum`-format manifest
fetched from the same release URL. The manifest itself was unsigned. TLS
authenticates the transport, not the publisher, so whoever could serve a swapped
artifact could serve a matching manifest beside it and the comparison would still
pass. The manifest was the weak link precisely because everything below it
inherited its trust.

The gap was known and written down. `artifact_verify.rs` said the real defence
was "signing … on the checksum file itself in a future iteration", and
`stage0_cache.rs` said the builder VM download was the tarball treatment "minus
cosign signing … as a follow-up". Neither follow-up had happened. This is it.

## Producer

`release.yml` signs three more blobs in the existing `cosign sign-blob
--new-bundle-format` loop — `builder-vm-*-checksums-sha256.txt`,
`default-microvm-*-checksums-sha256.txt`, and the combined
`checksums-sha256.txt` — and publishes each `.bundle` beside its manifest. The
image manifests stay globs so `nullglob` drops them when the image job that
would have produced them failed; image signing is best-effort exactly as image
publication already is.

`kernel-build.yml` did no signing at all. It now signs
`kernel-<arch>-checksums-sha256.txt` on the tag path. `id-token: write` is scoped
to the job rather than the workflow, because the workflow calls the BDD suite as
a reusable workflow and that call would otherwise inherit an OIDC token it has no
use for.

## Consumer

`fetch_expected_hashes` takes a `ChecksumManifest { base_url, asset, version }`
instead of a joined URL — the verifier needs the pieces separately to locate the
bundle and to pin the tag-bound signing identity, and both call sites already
held them separately, so the struct removed a line at each rather than adding
one. Order is download → verify → parse: a manifest that fails the signature is
refused with nothing read out of it.

Verification reuses `mvm_build::release_signature::verify_release_archive_signature`,
the same identity-pinned Sigstore path the runtime overlay and SDK sidecar
already go through. No second verifier, no second bundle-name helper, no new
dependency. A refusal bumps the existing `sig_invalid` counter, which also emits
the `ImageVerifyFailed` audit line — a bad signature is attack-shaped, not a
network blip.

`update.rs::download_kernel` gets the same treatment.

## The two escape hatches are now actually independent

`MVM_SKIP_HASH_VERIFY` and `MVM_SKIP_COSIGN_VERIFY` were already documented as
deliberately separate — waiving *who published* is a strictly larger concession
than waiving *what the bytes hash to*. Wiring the signature rung in is what makes
that real: the hash hatch no longer disables publisher verification, because the
publisher check now sits above it.

**Behaviour change worth knowing.** On the kernel path, `MVM_SKIP_HASH_VERIFY=1`
previously skipped the manifest fetch outright, so it also happened to work when
the manifest 404'd. It no longer does — a missing manifest is fatal regardless of
that hatch. This makes the kernel path consistent with the image path, which has
always fetched the manifest unconditionally and only ever let the hatch waive the
digest comparison. The kernel path was the outlier.

## The release gate could not see any of this

`verify-release-assets.sh` asserted each manifest *exists* but never that it was
signed, so a release that silently skipped signing would still have passed
`verify-release` — the exact failure this work exists to prevent, invisible to the
check meant to catch it. Added `require_signed_manifest`: the bundle must exist,
and under `--cosign` it must verify.

## Not done

- `mvm-build` carries a second, separate `fetch_expected_hashes` used by
  `initramfs.rs` and `runtime_overlay.rs`. It is untouched here. Those paths
  fetch archive checksums for artifacts whose tarballs are already independently
  cosign-verified, so the anchor is not missing the way it was for the image
  blobs — but the duplication itself is worth collapsing.
- `runtime-overlay-*.tar.gz.sha256` and `sdk-sidecar-*.tar.gz.sha256` stay
  unsigned: single-line sidecars for a tarball that already carries its own
  signature, so swapping one gains nothing.
