# Image-set contract: dev build variants and source fingerprints

Backing: shipped-source
Validation: cargo nextest run -p mvm-core -p mvm-build --lib;
`cargo clippy -p mvm-core -p mvm-build --all-targets -- -D warnings`

Follow-up plan `specs/plans/2026-09-27-release-e2e-under-image-target.md`,
contract box.

## What changed

`ImageSetMember` gains two optional fields, both `skip_serializing_if` absent
so existing sets keep parsing and validating unchanged:

- `build_mode` — which build of its role a member carries. Only `dev` exists
  today (`MemberBuildMode`, `#[non_exhaustive]`); absent is the production
  build. Only workload-kernel and workload-rootfs members may carry it: every
  other role has one build, and a dev marker there is refused naming the
  role. Member identity in the duplicate check includes the build mode, so
  the dev and prod variants of one workload base publish beside each other
  in one atomic set.
- `source_fingerprint` — the fingerprint of the sources the member was built
  from, computed at the producing commit by the same function a consumer
  runs on its own tree. Today only the SDK sidecar publishes one; the
  release e2e (and the source-matched acquisition path) adopt the published
  bytes when their fingerprint matches and pair-build when it differs
  (#3457 step 2).

`ImageSetRequirement::current_train` gains no requirement: the dev members
are an addition, not a gate, so a set without them — every set published so
far — validates exactly as before.

## Why this shape

- Same set, same atomicity: the dev slot is a build-time variant, not a
  trust tier, so it rides the one immutable release rather than a parallel
  channel (the follow-up plan's open question, answered in the plan).
- Optional fields, not a schema bump: adding data is backward compatible,
  and the initramfs-role ordering lesson applies in reverse — mvm must parse
  these fields before mvm-images can emit them, so this lands first and the
  producer advances its pin to a commit that carries it.

## Tests

- a dev workload base publishes beside its prod build (both accepted; two
  dev builds of one base still refused as duplicates)
- a dev build mode on a non-workload role is refused
- `build_mode`/`source_fingerprint` round-trip snake_case, absent stays
  absent, and only the fingerprinted member serializes the field
