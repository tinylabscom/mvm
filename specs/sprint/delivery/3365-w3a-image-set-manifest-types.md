# Image-set manifest and lock types

Backing: shipped-source
Validation: cargo nextest run -p mvm-core -E 'test(/image_set|release_version/)'

The image release train publishes a dozen assets that the host selects by name,
under a tag kept in step by hand across Rust constants, workflows and tests.
Nothing describes the set as a whole, so nothing can refuse a partial one, a
set built for a protocol the host does not speak, or a validly signed older set
served in place of the pinned one. This is the model that W3's verification,
lock and consumers are built on.

## What exists now

`mvm_core::image_set` holds types and pure checks only — no network, no
signatures, no consumers yet:

- `ImageSetManifest`: schema and set version, producer repository, workflow,
  tag and commit, the embedded `mvm` commit, declared guest-agent protocol range
  and builder cache contract, Nix inputs (reusing the pack model's identities),
  revocation channel, optional lineage, and members.
- `ImageSetMember`: a role, a guest architecture or an explicit
  architecture-independent target, a boot protocol for bootable roles, typed
  artifacts with digests and sizes, required guest devices, the member's
  `PackManifest` hash and SBOM. No member is named after a host OS.
- `ImageLock`: repository, immutable tag, manifest asset and digest, and the
  expected signing identity.
- `validate_structure`, `require_complete`, `check_protocol_compatibility`,
  `select_member` and `check_against_lock`, each refusing with an error that
  names what differs. The digest comparison against the lock is what refuses
  tampering and replay of an older set.

Every type round-trips and refuses unknown fields; every check has its refusal
paths tested (68 tests with the version model).

## One version model, not two

The updater in `mvm-cli` already ordered releases by semver precedence. Rather
than add a second parser, that model moved down to `mvm_core::release_version`
with an explicit syntax choice: `Lenient` for tags the updater reads (leading
`v`, build metadata dropped), `Strict` for the image set's published versions.

## Not yet

Signature and artifact verification, revocation, the checked-in lock file and
generated pins, and an offline verifier are the W3b–W3d slices in the plan.
