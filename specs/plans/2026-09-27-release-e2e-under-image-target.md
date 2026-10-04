# Bring the release e2e back under the image-prep target

Backing: preview
Validation: each box ticks only with the measured evidence its text names;
unchecked boxes remain in progress.

**Status:** IN PROGRESS — 2026-10-01: the contract (mvm#3829), the producer
emission (image-set/v0.2.2 onward), the dev-slot members (image-set/v0.2.3),
and the consumer fetch arms (mvm#3842 sidecar, mvm#3878 dev image) have all
landed and been verified against the published sets; the sidecar arm's
reporting gap found during verification is fixed in the mvm branch
`fix/3457-sidecar-arm-reporting`. What remains: the re-measure box (no
release-window run has yet matched the pinned set's fingerprint) and the
merge-queue boxes below. 2026-10-04: the release lane moves to the pinned set;
see "Decision 2026-10-04" below.
**Date opened:** 2026-09-27
**Parent:** `specs/plans/2026-09-16-image-repository-extraction.md` (W8 re-measure)

The W8 re-measure records the release gate's remaining image cost: after the
cutover, the Linux documented-surface e2e lane still pair-builds the SDK
sidecar (~24 min) and the dev default-tenant image (~42 min) from an
`mvm-images` checkout on every release, because neither artifact is fetched
from the signed image set even when the tree matches the set's inputs. This
plan removes that rebuild from the common case. It is `Backing: preview`:
boxes tick only when the named evidence exists, and nothing here asserts an
outcome in advance.

Non-goals: sharding the 313-scenario live suite (separate decision, tracked
as its own item at the end); changing what the released CLI consumes (it
already consumes published set members); touching GitHub release history.

## Why the rebuild remains

The release e2e runs from a source checkout, so every image-class artifact
resolves through the source/pair path:

- the SDK sidecar the service-plane scenarios load is built from the
  `mvm-images` checkout the lane takes at the pinned ref
  (`e2e-docs.yml`), to match the host-services C ABI exactly;
- the dev default-tenant image has no published member at all — the
  `mvm-images` set publishes the `prod` variant, so the dev slot is always
  a pair build.

Both builds are correct and stay on the critical path only because the
published set cannot yet answer "is this artifact the one my tree would
build?"

## Work

- [x] **Contract: the image-set schema carries dev build variants and source
      fingerprints.** `ImageSetMember` gains two optional fields —
      `build_mode` (only `dev` exists today; absent is the production build,
      and only workload-kernel/rootfs members may carry it) and
      `source_fingerprint` (today the SDK sidecar's cdylib fingerprint).
      Member identity includes the build mode, so the dev and prod variants of
      one base publish beside each other in one atomic set; `current_train`
      requires nothing new, so existing sets keep validating unchanged. This
      is the mvm half of the producer item below; the producer emits the
      fields once its pin carries this schema.
- [x] **Producer: publish the dev default-tenant variant as a set member.**
      `mvm-images` adds the dev-slot default-tenant image (both guest
      architectures) to the atomic image set it publishes, with the same
      digest/size/compatibility metadata as every other member. Owned by
      the image-repo session; coordinated there, not in this plan. Until
      this lands, the e2e's dev-image pair build cannot move.
      *Ticked 2026-10-01:* the published image-set/v0.2.3 manifest carries
      `workload_kernel`/`default_tenant` and `workload_rootfs`/`default_tenant`
      members with `build_mode: dev` on both guest architectures, each with
      the usual digest/size artifact metadata.
- [x] **Producer: record the SDK sidecar source fingerprint in the signed
      set.** Per #3457 step 1: each sidecar member's metadata carries the
      `sdk_cdylib_source_fingerprint` computed by the same function at the
      producing commit, inside the signed manifest so the signature covers
      it. (The over-approximation behavior noted in
      `.agent-memory/notes/sdk-sidecar-fingerprint-over-approximates-on-purpose.md`
      stays: a fingerprint match means "build only if you must", never
      "skip verification".)
      *Ticked 2026-10-01:* image-set/v0.2.2 and image-set/v0.2.3 carry
      `source_fingerprint` on all four sidecar members (glibc+musl on both
      arches) inside the signed manifest. The fingerprint recomputed with the
      consumer's Rust `sdk_cdylib_source_fingerprint` at v0.2.3's
      `mvm_source_commit` (0f33c057) reproduces the published value
      (d64580e2…) exactly, so producer port and consumer function agree.
- [x] **Consumer: fetch both when the fingerprint matches, build when it
      differs.** The release e2e computes the tree's host-services C ABI
      fingerprint; on a match it acquires the sidecar and the dev image as
      signed set members (digest- and size-checked, compatibility refused
      before boot, exactly the Wave 0.5b path); on a mismatch it pair-builds,
      so a guest C-ABI change still gets compiled and tested. The suite
      reports which arm ran, the way `doctor` reports the boot-image arm.
      *Ticked 2026-10-01 for the sidecar arm:* `build sdk-sidecar build`
      under `MVM_FETCH_UNCHANGED_IMAGES=1` (mvm#3842) verified end-to-end —
      from the tree matching the pinned set's fingerprint it acquires the
      set, matches, and installs the published glibc+musl sidecars with
      digests verified against the signed checksum manifests and no build;
      from a mismatched tree it pair-builds. The arm report and every
      fall-back reason are always-on lines (mvm `fix/3457-sidecar-arm-reporting`);
      before that fix they were verbosity-gated `info` lines, invisible in
      the e2e's non-verbose log. The dev-image leg is implemented (mvm#3878)
      but the e2e's `dev-image` phase does not pass the knob yet; wiring it
      is follow-up work, tracked by the re-measure box staying open.
- [x] **Tests.** Positive: a matching fingerprint fetches and verifies with
      no build; both cache and cold path. Negative: a changed host-services
      source pair-builds; a member failing verification is refused, never
      booted. Edge: fingerprint absent from an older set (pair-build path).
      *Ticked 2026-10-01:* mvm#3842 added the `fetch_unchanged` suite
      (matching fingerprints on both libcs adopt; a mismatch or an absent
      field pair-builds; the knob defaults off) beside the
      `published_image_set` verification tests; the positive path was
      additionally exercised end-to-end against the published image-set/v0.2.3
      on 2026-10-01 (adopt arm installed both libcs, digests verified), and
      the negative path by two CI runs on mismatched trees (v0.20.0 release
      lane and the 2026-10-01 Extended CI nightly), both of which
      pair-built as designed.
- [ ] **Re-measure.** Two green release runs record the lane's image-prep
      phase against the W8 re-measure table; the parent plan's ≥25-minute
      box ticks only if the measured improvement clears it.
      *Recorded 2026-10-01 (pair-build arm, by design):* the v0.20.0 release
      lane's green Linux documented-surface job ran the sdk-sidecar phase in
      1526 s (~25.4 min, pair-build), and the 2026-10-01 Extended CI nightly
      in 1828 s (~30.5 min, pair-build; the job later failed for unrelated
      reasons). Both trees genuinely mismatch the pinned image-set/v0.2.3:
      19 commits touching the cdylib fingerprint inputs landed between the
      set's `mvm_source_commit` (0f33c057) and the v0.20.0 tag, and the
      tree fingerprint recomputed on both trees (6ccf93d3…) differs from the
      set's (d64580e2…). No adopt-arm measurement exists yet: one needs a
      release-window run whose tree matches the pinned set's fingerprint,
      which the always-on arm report (mvm `fix/3457-sidecar-arm-reporting`)
      now makes visible. The width of the match window is the
      over-approximation open question below: at the observed merge pace the
      cdylib inputs churn within days of a set publish, so the ≥25-minute
      saving may accrue on fewer runs than the plan assumed.
      *2026-10-04:* the release lane now adopts the pinned set under
      `MVM_FETCH_UNCHANGED_IMAGES=pinned` (decision above), so its image-prep
      phase no longer depends on a fingerprint match. This box still ticks
      only after two green release runs under that arm are measured.

## Decision 2026-10-04: the release lane boots the pinned set

The maintainer decided on 2026-10-04 that the release workflow's
documented-surface lanes adopt the pinned, signed image set's SDK sidecars
and dev default image instead of pair-building them from the tree. A release
tests what its users get, which is the new CLI against the set
`crates/mvm-core/images.lock` pins, not a pair build of guest sources the set
does not carry. Guest-source changes keep being pair-built and booted by the
merge queue's guest-image-boot lane, which this decision does not touch.

Why fetch-when-unchanged could not carry the release lane: its match window
is too narrow at the current merge pace. Twelve commits touching the cdylib
fingerprint inputs (`Cargo.lock`, `Cargo.toml`, and `mvm-contract`,
`mvm-core`, `mvm-agentd`, `mvm-host-services`) landed on `main` between
2026-10-02T21:37Z and 2026-10-03T20:31Z, about 22 hours: `ce6433ce5e`,
`af1f5afd7d`, `65e52f6c6a`, `e3579647ac`, `1673510385`, `eb05b2f8ad`,
`5aea865efb`, `fe84cbcf2a`, `c187f53993`, `1603f729c8`, `baf9248c34`,
`0fce7cb506`. Each one moves the tree's fingerprint away from the one
recorded in any published set, so a release-window run almost never matches.

How it is wired:

- `MVM_FETCH_UNCHANGED_IMAGES=pinned` is a third value of the existing knob,
  next to `1` (fetch-when-unchanged) and unset (pair-build, the default). It
  skips only the fingerprint equality. The root is still digest-pinned,
  signature-verified and refused when its signed compatibility declaration
  excludes the CLI; every member is still size- and digest-checked; the dev
  image is stamped `source=fetched` with the set tag. Under `pinned`, a
  refused set or a set lacking the members fails the step and names the
  reason (for an incompatible set, the declared range); it never falls back
  to a pair build. Both verbs print one line naming the arm, the knob and how
  the tree's fingerprint compares with the set's.
- `e2e-docs.yml` gains a `boot_pinned_images` input, default off.
  `release.yml` sets it, which selects `pinned` and skips the mvm-images
  checkout; Extended CI leaves it off and keeps pair-building nightly.
- A source-checkout launch now also resolves an SDK sidecar the verb adopted
  into the pinned set's member cache. Without that, the adopt arm installed
  bytes that a source-channel launch never looked at.

Scenario dependence on newer guest behaviour, checked against
`image-set/v0.2.4` (built from mvm `4e65b22`) by reading the range
`4e65b22..4075b8fbf1`: the documented-surface scenarios that load the real
sidecar (`s30_service_plane/host_kv.feature` round-trip and unbound refusal;
`declared_bindings.feature` mounts it without loading it) and the one that
boots the dev image (`s5_lifecycle/transient_sandbox_boot.feature`) exercise
no change in that range. No commit in it touches `crates/mvm-host-services`,
the cdylib's guest modules, the broker wire types or the guest-agent protocol
(2..=2 at both ends), and the dev rootfs's own boot path is replaced by the
tree-built initramfs and runtime overlay. This reading is preview evidence: a
live run against v0.2.4 has not been recorded yet, and `main` still pins
`image-set/v0.2.3`, built from `0f33c057`, whose range to `main` is wider and
was not read scenario by scenario.

## PR merge time (measured 2026-09-29, the other half of the goal)

The merge-queue run itself is ~31 min when runners are free; the 50-minute
perception is queue wait behind other merges. One merge-group run (36367678633)
decomposed:

| Lane | Duration | Note |
|---|---:|---|
| Guest image boots (mvm-images) | 31 min | builds the pair from the checkout on **every** merge, even Rust-only PRs; its heavy step ignores the path scope the setup steps honor |
| Test workspace | 23.5 min | full nextest suite, one runner |
| BDD live witness / BDD conformance | 18.5 / 17.7 min | parallel |
| Test workspace (aarch64) | 17 min | parallel |

- [x] **Path-scope the guest-image-boot lane's heavy step.** It already
      `needs: [scope]`; gate the build/boot step on `scope.nix` the way the
      boot-latency lane skips docs-only PRs, so Rust-only merges stop paying
      a 31-minute image build. The lane still runs on every image-relevant
      change and on dispatch.
      *Ticked 2026-10-03:* mvm#3841 added a `guest_image` scope output
      keyed to the same four crates the SDK sidecar fingerprint hashes, plus
      the guest recipes, workspace manifests, toolchain and `build.rs`. Merge-group
      runs 37084235500, 37088464972, 37093028421 and 37095353724 (all
      host-only) report the lane as `skipped`, and it no longer appears among
      the longest jobs.
- [x] **Shard `Test workspace`.** Split the nextest suite across two runners
      (~23.5 min -> ~12 min) if the queue remains the bottleneck after the
      image lane is scoped.
      *Ticked 2026-10-03 as landed; the expected saving did not appear:*
      mvm#3875 runs the suite as two shards. In the merge-group runs above,
      each shard still takes 19.4–21.4 min, not ~12, because each shard
      compiles the whole test workspace on its own runner, and the compile
      dominates. `Test workspace` remains the merge-group critical path, with
      `Lint feature coverage` (~17.5 min) and BDD conformance (~19.8 min)
      close behind.

**Merge-group wall after both levers (2026-10-03).** Over the 20 most recent
green `merge_group` runs of `ci.yml` (2026-10-02 15:24Z → 2026-10-03 04:05Z,
all first attempts, `run_started_at` → `updated_at`): median 21.7 min, 3 of
20 under 20 min, range 12.7–38.0 min. The guest-bins plan's queue-wall
tripwire (below 20 min over at least ten runs) is therefore **not met** on
this evidence. The next lever is the shard compile, not more shards: a
third shard pays the same compile a third time.

## Separately tracked (not this plan)

- [ ] **Suite sharding.** If the live scenario phase (~1 h) remains the
      critical path after the image legs are gone, shard the
      documented-surface suite per the parent plan. Deliberately not
      bundled with any box above.

## Open questions

- Does the dev default-tenant member publish on the same `image-set/v*`
  cadence as prod, or does a dev-slot member warrant its own promotion
  rule? (Leaning: same set, same atomicity; the dev slot is a build-time
  concern, not a trust tier.) — *answered 2026-09-29: same set; the
  member's `build_mode` field marks the variant, so one release carries
  both builds atomically.*
- The fingerprint gate keys on the host-services C ABI only; a change in
  the sidecar's non-ABI inputs (packaging, glibc/musl toolchain) still
  over-approximates to a rebuild. Acceptable for v1; revisit if the
  over-approximation shows up in the re-measure. — *2026-10-01: it showed
  up earlier than expected — not from non-ABI inputs but from the breadth of
  the declared inputs: all of `crates/mvm-core/src` and `crates/mvm-agentd/src`
  churn on ordinary feature work (19 input-touching commits in the ~2 days
  between image-set/v0.2.3's source commit and the v0.20.0 tag), so the match
  window is narrow at the current merge pace. The re-measure box records the
  details; revisit the input list if the window, not the arm, becomes the
  bottleneck.
