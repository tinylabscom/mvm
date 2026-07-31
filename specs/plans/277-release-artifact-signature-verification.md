# Plan 277 — Cosign-verify the downloaded runtime overlay and SDK sidecar

**Status: COMPLETE**

Follow-on to plan 273. That plan closed the *acquisition* gap — an installed
`mvmctl` can now fetch a published SDK sidecar instead of refusing — and left
one gap open explicitly: the fetched archive is sha256-pinned but not
signature-verified. This plan closes it, for the runtime overlay and the SDK
sidecar together, because they share one transport and have the identical hole.

## Why sha256 alone is not enough

The digest an installed binary checks against comes from
`<asset>.tar.gz.sha256`, fetched over HTTPS from the same base URL as the
archive. That authenticates the *transport*, not the *publisher*. Anyone who
controls what that base URL serves — a private mirror set through
`MVM_OVERLAY_BASE_URL`, a compromised release, a hijacked CDN edge — serves a
matching pair and the check passes. The archive then becomes the guest's
`/mvm/runtime` (every workload) or `/mvm/sdk` cdylib (any workload bound to an
SDK-served host service), which is arbitrary code inside the sandbox.

The project already has the primitive that closes this: the release workflow
cosign-keyless-signs its blobs, and `mvm_core::crypto::image_verify::
verify_signed_payload` verifies a Sigstore bundle against an embedded trust
root, offline, with no new dependency. It simply was never pointed at these two
artifacts.

## Two findings that shape the work

**1. The published bundles are in the wrong format.** `release.yml` signs
`artifacts/*.tar.gz` with plain `--bundle` (the legacy shape). The workflow's
own comments record that the in-binary Rust verifier *rejects* that shape and
requires `--new-bundle-format`; every artifact that stack already verifies (dev
image manifests, packs, revocation lists) is signed that way. Pointing the
verifier at today's `runtime-overlay-<arch>.tar.gz.bundle` would fail to parse
100% of the time.

The legacy bundles were initially kept for `mvmctl-*.tar.gz.bundle`, which is
consumed by the **cosign CLI** (`install.sh`, and `mvmctl update`, which shells
out to `cosign verify-blob`). That split was then collapsed — see the amendment
below.

**2. Nothing is at risk of breaking.** The latest release (v0.17.0) publishes
the runtime overlay as *loose files* (`.ext4`/`.verity`/`.roothash`/`.VERSION`),
not as a tarball at all — the tarball transport post-dates it, and no published
release has ever carried a `runtime-overlay-*.tar.gz` or a `sdk-sidecar-*.tar.gz`.
There is therefore no working download to regress, and mandatory verification
costs zero compatibility if it lands before the first release that ships the
tarballs. That is now.

## Decision: fail closed, both artifacts, no degraded acquire

An archive whose signature cannot be verified is not installed. This matches the
posture the rest of the project already takes (`Users opt out of security, never
opt in`) and the discipline plan 273 established for the sidecar.

Concretely that means a build without `mvm-core/manifest-verify` refuses to
*download* an overlay or sidecar. Released binaries are built
`--features host,user,...` and `user` enables `manifest-verify`, so every binary
an end user actually downloads can verify. A default-feature contributor build
resolves these artifacts by *building* them, not downloading; a contributor who
deliberately forces the download path (`MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=download`)
gets a refusal naming both fixes. `MVM_SKIP_COSIGN_VERIFY=1` remains the
documented emergency-rotation escape, never set in CI.

Note the escape hatch is currently documented but not read anywhere in code —
this plan is what makes it real, mirroring how `MVM_SKIP_HASH_VERIFY` is
honored by `verify_file_sha256`.

## Where the rung sits in the ladder

Plan 273's ladder gains one rung, placed after the digest check and **before any
extraction**, so an unauthenticated tar is never parsed:

1. Archive checksum sidecar pre-commits the digest (fetched before the payload)
2. Archive hashes to that digest
3. **Archive verifies against the release-signing identity** ← new
4. Every archive member is allow-listed and present
5. The archive's own manifest agrees with the extracted bytes
6. The installed entry satisfies the resolver

## Tasks

- [x] **Task 1 — Sign the image tarballs in the format the verifier parses.**
  (Amended — see below: the split this task introduced was collapsed to a single
  format.) Attach
  `runtime-overlay-*.tar.gz.bundle` / `sdk-sidecar-*.tar.gz.bundle` to the
  release. Extend `tests/release_assets.rs` to pin the bundle asset names and
  assert the image tarballs are signed in the new format — the failure mode is
  invisible until a real download, so it needs a static witness.

- [x] **Task 2 — `mvm_build::release_signature`.** One helper both downloaders
  call: fetch `<asset>.bundle`, verify the local archive bytes against every
  `release_trust::accepted_release_identities(version)` candidate under
  `RELEASE_OIDC_ISSUER`, honor `MVM_SKIP_COSIGN_VERIFY`. Reuses `curl_download`
  and the existing `verify_signed_payload` primitive — no new dependency, no
  second downloader. Typed refusals that name the asset and never echo bundle
  bytes.

- [x] **Task 3 — Wire it into both download paths** at rung 3, before
  extraction, so a refusal leaves nothing in the cache.

- [x] **Task 4 — Docs + rollup.** ADR-018's acquisition paragraph, the
  `MVM_SKIP_COSIGN_VERIFY` env-var row (scope it to what now honors it), plan
  273's deferred-gap note, `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`.

## Test contract

- A missing `.bundle` refuses **before** extraction and caches nothing.
- A malformed/garbage bundle refuses (discriminating only under
  `manifest-verify`, so that case runs feature-gated — a test that cannot tell a
  bad signature from a disabled verifier is not a witness).
- The refusal names the asset and carries no bundle bytes.
- `MVM_SKIP_COSIGN_VERIFY=1` admits, and logs that it did.
- A build without `manifest-verify` refuses the download with a message naming
  both remedies.
- The ordering witness: signature is checked before any tar member is read.

Offline tests cannot mint a *valid* Sigstore signature — that needs Fulcio and
Rekor — so the positive path is exercised with the documented skip hatch and the
real signature check is witnessed in the rejecting direction plus the existing
`pack-signing-smoke.yml` lane, which already round-trips a genuine keyless
signature through this same verifier.

## Amendment (2026-07-31) — one bundle format, no legacy

The two-format split above was deliberate but unnecessary, and this project does
not carry backwards compatibility. It is collapsed: **every** `cosign sign-blob`
in `release.yml` now passes `--new-bundle-format`, including the mvmctl binary
tarballs and the SBOM.

The split rested on an assumption that was never tested — that the cosign CLI
consumers needed the legacy shape. They do not. `cosign verify-blob --bundle`
documents the Sigstore bundle as its *preferred* input, and a keypair round-trip
against cosign v3.1.1 confirms it: signing with `--new-bundle-format` and
verifying with a plain `cosign verify-blob --bundle` reports `Verified OK`. So
`install.sh`, `mvmctl update`, and `verify-release-assets.sh` all keep working
unchanged, against one format instead of two.

What this buys: no per-artifact branching in the signing step, no way to sign an
artifact with the shape its verifier cannot read, and one invariant to gate
instead of a two-sided split. `tests/release_assets.rs::
every_signed_release_blob_uses_the_one_bundle_format` asserts every signing
invocation carries the flag; it was confirmed to go red when a bare `--bundle`
is reintroduced and green when restored.

The cost, stated plainly: a host verifying by hand needs cosign >= v2.4 (when
`--new-bundle-format` landed). There is no legacy fallback and that is
intentional.

## Amendment (2026-07-31, second) — close the loop before a release, not after

Everything above is proven against staged fixtures and static workflow
assertions. Nothing had ever exercised the real chain — Nix build → tarball →
`--new-bundle-format` sign → attach → fetch → sha256 → signature → extract →
install → resolve — because no published release has ever carried these
tarballs. The first real run would have been a `v*` tag push, and because the
ladder is fail-closed, a mistake there strands every download rather than
degrading.

Two lanes now cover it, at different costs and different times:

- **`pack-signing-smoke.yml`** (dispatch) signs a release-shaped tarball with the
  exact `cosign sign-blob --new-bundle-format` invocation `release.yml` uses and
  feeds the real bundle through the downloader's verifier via the
  `verify-release-archive-signature` example. A companion step asserts a
  *legacy* bundle is **refused** — without it the gate would still pass if the
  verifier ever silently accepted both shapes, and would be measuring nothing.
  Scope: the signature-format contract, against a real bundle. Extraction,
  manifest re-check, install, and resolve stay fixture-covered.

- **`release.yml`** runs the whole ladder over its own artifacts, after signing
  and before `gh release create`, via the `download-release-artifact` example
  over a `file://` URL. That is the one context where the signing identity
  genuinely is the tagged release workflow's, so it needs no trust override.
  A missing artifact is skipped — image jobs are best-effort — but an artifact
  that is present and cannot be consumed fails the release before publish.

`verify_release_archive_bytes` is the seam that makes the first lane possible:
the identity set is a parameter, the same shape `mvm_core::packs::verify` takes
a `KeylessTrust`. Production always passes `release_trust`'s set.

`tests/release_assets.rs::the_release_consumes_its_own_artifacts_before_publishing_them`
pins the ordering so the self-check cannot drift after signing or before publish.
