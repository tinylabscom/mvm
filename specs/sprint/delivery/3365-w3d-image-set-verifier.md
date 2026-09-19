# Verifying a published image set from the command line

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli --features manifest-verify -E 'test(/image::boot::verify/)'

W3b built the verifier. This puts it in front of a person, and retires the model
it replaces.

```text
mvmctl image boot verify --manifest <file> --bundle <file> --lock <file> \
  --artifacts <dir> [--require-complete] [--json]
```

The command reads the four inputs and calls
`mvm_core::image_set::verify_image_set`. It adds no check of its own: every
stage stays in `mvm-core`, in the order W3b fixed. What it adds is the answer to
"how far did the set get". `ImageSetError::stage` classifies every refusal into
one of the verifier's stages — `manifest-digest`, `signature`, `parse`,
`structure`, `lock-match`, `completeness`, `artifacts`, `revocation` — and the
command leads with it:

```text
image set refused at the signature stage: no signature over the image set manifest verifies under …
```

The match is exhaustive, so a new refusal cannot ship without being placed.
`--json` prints the verdict (`verified`, `stage`, `reason`) for a refusal too,
and the exit code still fails, so a script never has to parse text to learn the
outcome. It is offline: no network, and it does not touch the boot image cache.

It lives under `image boot` because that subtree is where the boot image is
inspected and replaced, and an image set is what will replace it.

## The older model is gone

`crypto::image_verify` carried a second, string-typed image manifest —
`SignedManifest`, `RevocationList`, `parse_manifest`, `verify_manifest`,
`check_version_pin`, `check_not_after`, `check_revocation`, and the
`verify_artifact` / `ArtifactDigest` pair that only it used. Its only caller in
this repository or `mvmd` was the `verify-signed-manifest` example. Removed,
with the example. What the module still does is what everyone else calls it
for: the cosign primitive (`verify_signed_payload` and the shared identity
loop) and streaming SHA-256.

## The live witness moved rather than disappeared

`pack-signing-smoke.yml` ran that example against a real `cosign sign-blob`
bundle. It now writes a one-member image set over the dummy kernel, signs it
the same way, writes a lock pinning the digest of exactly the signed bytes, and
runs `mvmctl image boot verify`.

A lock names a signing identity at a **tag** ref; a branch ref does not parse,
by design, since a signature minted on a branch is not a release. The nightly
run signs as `pack-signing-smoke.yml@refs/heads/main`, which no lock can accept.
So the lane now also runs on release-tag pushes, where its identity is
tag-bound, and does the full round-trip there: exit 0, then a tampered artifact
refused at the `artifacts` stage. Nightly, it checks the real branch-minted
bundle against a lock naming the same workflow at a tag, and requires a refusal
at the `signature` stage — after the digest stage accepted the bytes. The
bundle-format round-trip itself stays covered nightly by the four other steps,
which call the same primitive.

## What the tests show

In `mvm-cli`: the workflow's manifest shape parses and passes
`validate_structure`, so the YAML and the parser cannot drift apart silently; a
manifest the lock does not pin is refused at the digest and the message leads
with the stage; an unreadable bundle, an unparseable lock (a branch-ref lock
included) and a non-directory artifact path are each refused before
verification and named. Against the committed `v0.18.0-rc.1` release bundle,
the signing workflow's identity passes the signature and stops at the parse,
and another workflow's identity is refused at the signature. In the root
package, the help lists every input, a missing input is a usage error, and the
real binary refuses an unpinned manifest with `--json` output and a nonzero
exit. In `mvm-core`, the W3b refusal tests now also assert the stage each one
reports.

## Not here

A published image set does not exist yet, so nothing verifies one outside the
smoke lane. The command takes no revocation list: no revocation channel is
live, and wiring one is gated on W6.
