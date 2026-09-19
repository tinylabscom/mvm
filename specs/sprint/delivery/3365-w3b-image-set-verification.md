# Verifying a published image set, offline

Backing: shipped-source
Validation: cargo nextest run -p mvm-core --features manifest-verify -E 'test(/image_set/)'

W3a defined what an image set is. This is what refuses one.

`mvm_core::image_set::verify_image_set` takes the published manifest bytes, the
detached cosign bundle beside them, the checked-in lock and a directory of
artifacts, and runs six stages in a fixed order. The order is the design:

1. hash the raw bytes and compare to the lock's pinned digest — **before**
   anything parses them. Tampering and replay of an older, validly signed set
   are the same refusal here, and an attacker-chosen manifest never reaches a
   parser;
2. check the detached signature over those same bytes under the identity the
   lock names;
3. parse;
4. `validate_structure` and `check_against_lock`, plus completeness and host
   protocol compatibility when the caller supplies them;
5. every member artifact on disk, size first (a stat, so a truncated rootfs is
   refused without hashing hundreds of megabytes) then digest;
6. revocation of the set digest or any member pack hash, keyed on the signer the
   *lock* names rather than the one the manifest claims.

There is one entry point and it runs every stage. The optional inputs only add
checks; none of them can remove one.

## One identity loop, not three

A keyless trust root is a set of accepted identities, so every caller needs a
"try each, report the last failure, refuse an empty set" loop. Three existed:
in `packs`, in `pack_revocation`, and about to be written a fourth time here.
They are now one function, `verify_signed_payload_under_any_identity`, and the
two existing callers were moved onto it.

## What the tests prove

23 tests. The ones that matter most are the negative ones: a single flipped
byte is refused by the digest; bytes that are not JSON at all still fail at the
digest rather than the parse, which is how the ordering is pinned; a bundle
signed by a different workflow is refused, using the real `v0.18.0-rc.1`
CLI-signed bundle committed for this purpose, with a control test proving the
same machinery accepts the correctly signed payload; artifacts that are
missing, truncated or altered are each refused by name; a revoked set digest and
a revoked member pack hash are refused, while a revocation naming something
else, or issued under another signer, admits the set.

With `manifest-verify` off, verification refuses and names the feature. It never
passes.

## Not here

Retiring the older `SignedManifest` model is sequenced with the verifier command:
`pack-signing-smoke.yml` runs its example against a real bundle, so that family
is a live witness rather than dead code, and retiring it means moving the lane.
