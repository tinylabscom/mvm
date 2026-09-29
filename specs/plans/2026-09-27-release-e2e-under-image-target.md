# Bring the release e2e back under the image-prep target

Backing: preview
Validation: each box ticks only with the measured evidence its text names;
unchecked boxes remain in progress.

**Status:** NOT STARTED
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
- [ ] **Producer: publish the dev default-tenant variant as a set member.**
      `mvm-images` adds the dev-slot default-tenant image (both guest
      architectures) to the atomic image set it publishes, with the same
      digest/size/compatibility metadata as every other member. Owned by
      the image-repo session; coordinated there, not in this plan. Until
      this lands, the e2e's dev-image pair build cannot move.
- [ ] **Producer: record the SDK sidecar source fingerprint in the signed
      set.** Per #3457 step 1: each sidecar member's metadata carries the
      `sdk_cdylib_source_fingerprint` computed by the same function at the
      producing commit, inside the signed manifest so the signature covers
      it. (The over-approximation behavior noted in
      `.agent-memory/notes/sdk-sidecar-fingerprint-over-approximates-on-purpose.md`
      stays: a fingerprint match means "build only if you must", never
      "skip verification".)
- [ ] **Consumer: fetch both when the fingerprint matches, build when it
      differs.** The release e2e computes the tree's host-services C ABI
      fingerprint; on a match it acquires the sidecar and the dev image as
      signed set members (digest- and size-checked, compatibility refused
      before boot, exactly the Wave 0.5b path); on a mismatch it pair-builds,
      so a guest C-ABI change still gets compiled and tested. The suite
      reports which arm ran, the way `doctor` reports the boot-image arm.
- [ ] **Tests.** Positive: a matching fingerprint fetches and verifies with
      no build; both cache and cold path. Negative: a changed host-services
      source pair-builds; a member failing verification is refused, never
      booted. Edge: fingerprint absent from an older set (pair-build path).
- [ ] **Re-measure.** Two green release runs record the lane's image-prep
      phase against the W8 re-measure table; the parent plan's ≥25-minute
      box ticks only if the measured improvement clears it.

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

- [ ] **Path-scope the guest-image-boot lane's heavy step.** It already
      `needs: [scope]`; gate the build/boot step on `scope.nix` the way the
      boot-latency lane skips docs-only PRs, so Rust-only merges stop paying
      a 31-minute image build. The lane still runs on every image-relevant
      change and on dispatch.
- [ ] **Shard `Test workspace`.** Split the nextest suite across two runners
      (~23.5 min -> ~12 min) if the queue remains the bottleneck after the
      image lane is scoped.

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
  over-approximation shows up in the re-measure.
