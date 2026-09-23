# Image-set dual-publish compatibility window (#3368)

## Window

`tinylabscom/mvm-images` is the canonical producer and host for the
`0.18.0-rc.2` release line targeted on 2026-09-23. The window begins when that
release is actually published; the `mvm` CLI release workflow then mirrors the
required legacy asset matrix through **2026-12-31 23:59 UTC**. New CLI
releases on or after **2027-01-01** may remove the mirror only through W8 after
the release evidence below is complete. Historical GitHub releases are never
deleted or overwritten, so a supported binary keeps its original immutable URL.

The support window covers the previously released `0.17.x` line and the
`0.18.0` release-candidate line. New binaries resolve the signed root pinned in
`crates/mvm-core/images.lock` under `tinylabscom/mvm-images`. The older runtime
overlay and SDK-sidecar code continues to compose URLs below
`tinylabscom/mvm/releases/download/v<CLI version>`; every CLI release during the
window therefore carries the compatibility mirror.

## Publication contract

The CLI release workflow reads the canonical repository, tag, manifest digest,
workflow and tag ref from the single image lock. It verifies the root digest and
the exact tag-bound Sigstore identity before downloading members. It then
copies, rather than rebuilds, the required 24-asset legacy matrix into the CLI
release. Bundles consumed by old clients are re-signed by the CLI release
workflow because those clients trust its `v*` identity; the payload and checksum
bytes remain identical to the canonical release.

`xtask image-mirror` compares the canonical and mirrored copies after the CLI
release has been published. It refuses missing, empty, symlinked or differing
assets and also checks every mirrored member named by the signed root against
its declared size and SHA-256 digest. A failed comparison makes the release run
red; there is no fallback to independently built bytes.

## Rollback

Before advancing the image pin, retain the previous reviewed `images.lock`.
The same installed binary can restore its default workload image with:

```text
mvmctl image boot update --lock /path/to/previous-images.lock --force
```

The override accepts only a strictly older image-set version from the same
canonical repository and workflow as the compiled lock. The normal acquisition
boundary still verifies the exact root digest, tag-bound signature,
compatibility, completeness and member bytes before atomically replacing the
cache. A changed producer/workflow, same/newer version, malformed lock or
failed acquisition is refused and leaves the current cache intact.

The first canonical pin is `image-set/v0.1.0`, so there is not yet an older
published `mvm-images` set to exercise live. Unit and workflow-contract tests
exercise the rollback selection and refusal paths without rebuilding the CLI;
the first pin advance must add the live previous-set boot evidence here.

## Evidence boundary

Local checks prove the workflow contract, route separation, mirror comparator,
and rollback selection/refusals. They do **not** prove that `0.18.0-rc.2` has
been published or that its remote assets are equal. W7's first plan checkbox and
issue closure remain open until the tag workflow publishes the canonical-backed
mirror and its post-publish comparison passes. Physical HVF and KVM boot
evidence remains governed by W6 rather than being inferred from this change.
