# SDK sidecar: fetch the published signed sidecar when the tree's source fingerprint matches

Backing: shipped-source
Validation: `cargo test -p mvm-cli sdk_sidecar`; adopt arm exercised
end-to-end against the published image-set/v0.2.3 on 2026-10-01.

The Linux release e2e spent 23–27 minutes of every run pair-building the
source-matched SDK sidecar — its largest preparation cost after the W1
builder-image fetch landed. The proposal: adopt the published, signed sidecar
when its recorded host-services source fingerprint matches the tree, and
pair-build only when it differs, so a guest C-ABI change still gets compiled
and tested while the common case stops rebuilding identical bytes.

## Where the pieces landed

- **Producer** (`mvm-images`, `scripts/assemble-release.py`): ports mvm's
  `sdk_cdylib_source_fingerprint` input list and stamps the fingerprint on
  every SDK sidecar member (glibc+musl, both arches) inside the signed
  image-set manifest. Live since image-set/v0.2.2; image-set/v0.2.3 carries it
  on all four sidecar members.
- **Schema** (mvm#3829): `ImageSetMember.source_fingerprint` (+ `build_mode`
  for the dev-slot members image-set/v0.2.3 now publishes).
- **Consumer** (mvm#3842): `mvmctl build sdk-sidecar build` under
  `MVM_FETCH_UNCHANGED_IMAGES=1` fingerprints the tree, adopts both libcs'
  published members on a match (digest-verified, fetch failures propagate,
  never a silent downgrade), and pair-builds on a mismatch or an older set
  without the field. The dev-image leg followed in mvm#3878.

## Verification (2026-10-01)

- Producer/consumer function parity: the Rust consumer function recomputed at
  image-set/v0.2.3's `mvm_source_commit` (0f33c057) reproduces the published
  fingerprint `d64580e2…` exactly.
- Positive path, end-to-end: from a tree at 0f33c057 the arm acquired the
  pinned set (signature verified), matched the fingerprint, and installed the
  published glibc+musl sidecars; installed `sdk.ext4` digests match the
  published signed checksum manifests. No build ran.
- Negative path in CI: the v0.20.0 release lane (sdk-sidecar phase 1526 s)
  and the 2026-10-01 Extended CI nightly (1828 s) both pair-built, correctly —
  19 commits touching the cdylib fingerprint inputs landed between 0f33c057
  and the tag, and both trees recompute to `6ccf93d3…` ≠ `d64580e2…`.

## What this change fixes

The arm's report — `adopted the pinned set's SDK sidecars …` or `… built from
different sources; pair-building` — was emitted at `ui::info`, which is
verbosity-gated, so the non-verbose e2e log showed neither it nor any reason
when the arm fell through (`detect`/`fingerprint`/`acquire` bails were silent
by construction). The plan requires the suite to report which arm ran the way
`doctor` reports the boot-image arm. Both reports are now always-on
`ui::notice` lines, and the fingerprint/acquire bails name their reason at
notice level before pair-building. Behavior is unchanged: the safe direction
(fall through to the local pair build) is still the only fall-through.

## What remains

- The re-measure box in
  `specs/plans/2026-09-27-release-e2e-under-image-target.md` stays open: an
  adopt-arm measurement needs a release-window run whose tree matches the
  pinned set's fingerprint, and none has overlapped yet. The always-on report
  makes the next one visible in the log.
- The e2e's `dev-image` phase does not pass `MVM_FETCH_UNCHANGED_IMAGES=1`
  yet; the dev-image leg (mvm#3878) is implemented but not adopted by the
  suite.
- The match window is narrow at the current merge pace (the declared inputs
  include all of `mvm-core`/`mvm-agentd` sources); the plan's open question
  records the observation for a possible input-list revisit.
