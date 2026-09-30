# Issue #3716: registry-pack lock foundation

## Delivered

`mvm_core::registry_pack` now owns the identity and first trust decision for
user-facing product packs without overloading the existing runtime/build
artifact pack subsystem.

- `PackReference` accepts only canonical `namespace/name[@version]` values.
- Versions use the repository's strict semantic-version parser.
- `PackPin` cannot be constructed without an exact version.
- `PackLockfile` carries an explicit schema version and only one pin per
  namespace/name coordinate.
- Manifest verification hashes the raw fetched bytes and refuses an unpinned
  pack, a requested version that differs from the pin, or digest drift.
- JSON decoding refuses unknown fields, unsupported schema versions,
  unversioned pins, and duplicate coordinates.

This type is intentionally separate from `mvm_core::packs::PackManifest` and
`PackIndex`. Those types select MVM runtime/build artifacts by kind,
architecture, and backend and allow compatible cache fallback. A product-pack
lock must instead select one exact namespace/name/version and fail closed.

## Tests

Eight unit tests cover:

- versioned and unversioned reference round trips;
- malformed, ambiguous, non-canonical, and whitespace-bearing references;
- unversioned lock-entry refusal;
- lockfile serialization and strict deserialization;
- duplicate package-name refusal across versions;
- exact digest acceptance for versioned and lock-selected requests;
- missing pin, requested-version drift, and changed manifest-byte refusal.

## Remaining PS-06 work

The signed product-pack manifest, publisher trust policy, registry fetch and
atomic promotion, CLI discovery/lifecycle verbs, signed-plan admission binding,
policy-profile composition, and the initial `mvm-templates` packs remain open.
Profile composition follows PS-05 so this slice does not duplicate the policy
types being delivered there.
