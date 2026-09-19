# A locally built image set, read by the release parser at its own tier

Backing: shipped-source
Validation: cargo nextest run -p mvm-core -p mvm-build -p mvm-cli -E 'test(image_set) | test(image_source) | test(image::boot::verify)'

Slices W5b and W5c of the sibling-checkout workflow (#3364). W5b, in
`mvm-images` (tinylabscom/mvm-images#6), builds every image role against a
local mvm checkout named with `--override-input mvm path:<dir>`, and emits a
manifest for the result. W5c, here, reads that manifest with the same parser
and structural checks as a released set, classifies it `local-dev`, and refuses
it whenever it no longer describes what is on disk. No image consumer reads a
local set yet; W5f–W5k move them.

## What changed

- `ImageSetManifest.producer` is either a release (repository, workflow, tag,
  source commit, unchanged on the wire) or `{"local_checkouts": {"images":
  ..., "mvm": ...}}`, each checkout recorded as commit plus working-tree state.
  The two share no field, so a producer naming both, or neither, does not
  parse. `RepoIdentity` and `WorktreeState` moved from `mvm-build` into
  `mvm_core::image_set` so the manifest and a fresh probe are one type.
- The fields only a release can carry — `revocation_channel`, `supersedes`,
  and each member's `pack_hash` and `sbom` — are optional in the schema and
  enforced by `validate_structure`: required of a release, refused on a local
  set. A local set must also name its mvm checkout's commit as
  `mvm_source_commit`. Released manifests serialize exactly as before; the
  pack-signing smoke workflow's fixture parses unchanged.
- `verify_image_set` refuses a local producer at a new `provenance` stage,
  before it compares anything with the lock. `VerifiedImageSet` carries the
  matched release producer and reports `verified-release`.
- `verify_local_image_set` parses, validates structure, then refuses: a
  release producer (`provenance`), identities that differ from the re-read
  checkouts (`freshness`, image checkout first), any member for another
  architecture (`selection`), a missing required role (`completeness`), and —
  shared with the release path — any artifact that is not a regular file in the
  set's directory. Artifact names already cannot leave the directory. The
  result is a `LocalImageSet`, always `local-dev`.
- `LocalImageCheckout::read_local_image_set` re-verifies the selection, reads
  the paired mvm checkout's identity (canonical root of its own work tree),
  reads `image-set.json` only from a regular file, and calls the verifier. It
  is declared dormant in `xtask/dormant-controls.toml` until a consumer uses it.
- The working-tree fingerprint now requests its status listing and diff with
  every option git configuration could change spelled out (prefixes, renames,
  relative paths, abbreviation, hunk shape, algorithm, submodules, order), so
  two hosts fingerprint one tree the same way.

## Evidence

The mvm-core image_set suite (125 tests) passes, and 32 of those tests are new.
They cover the producer's wire shape both ways, mixed and partial producers,
the closed `WorktreeState` form, and every structural rule each producer
brings. They also check that the release verifier refuses a local set even
with a lock pinning its bytes, and they exercise each `verify_local_image_set`
refusal: release claim, stale image commit, stale mvm fingerprint, a
dirty-then-clean tree, wrong architecture, mixed architectures, missing role,
traversal names (`../escape`, `/etc/passwd`, `nested/file`, `..`, `.`),
symlinked artifact, directory artifact, changed artifact, missing artifact,
unparseable bytes, and a disjoint protocol range. A literal copy of the
emitter's output parses and verifies.

The mvm-build `image_source` suite has 35 tests. The new ones run the
end-to-end reader on real git checkouts: accepted when fresh; refused after an
mvm edit, after an mvm commit, for another recorded image state, after an image
edit (caught by `reverify`), for a missing role, for another architecture, for
a symlinked manifest or artifact, for a missing manifest, and for an mvm path
that is not a checkout root. A pinned fingerprint for a fixed dirty tree equals
the value the Python emitter pins for the same tree.

Across hosts, `runtime-overlay.default` was built on Linux against a clone of
mvm at `11e5ff4` with the override, then emitted. The set was read on macOS by
this code and accepted at `local-dev`. It was refused for wrong architecture,
missing role, a rewritten release producer, a symlinked artifact and a stale
mvm tree. A set emitted on Linux from a dirty mvm tree was accepted on macOS
against the identical edit, which shows the Python and Rust fingerprints agree
across git 2.43 and 2.53.
