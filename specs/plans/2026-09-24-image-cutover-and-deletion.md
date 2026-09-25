# Image cutover window and in-tree image deletion (W7 + W8)

Backing: preview
Validation: each wave lands with the tests and measured evidence named in
its boxes; unchecked waves remain in progress.

**Status:** IN PROGRESS — W7 complete (window closed 2026-09-25); W8 open
**Date opened:** 2026-09-24
**Issues:** #3368 (W7 dual-publish window), #3366 (W8 cutover and deletion)
**Parent plan:** `specs/plans/2026-09-16-image-repository-extraction.md`
  (W1–W6 complete; W6 landed as #3633, pin `image-set/v0.1.0`)

This plan carries the execution detail for the extraction plan's final two
workstreams. The extraction plan remains the source of truth for intent and
acceptance; this document sequences the work and records the deletion
inventory. W7 and W8 deliberately stay in separate PRs and separate merge
windows: no PR combines the trust-root switch (done in W6) with deletion of
the old producer, and no W8 PR lands before the compatibility window below
closes.

## Current state after W6

- `crates/mvm-core/images.lock` pins `tinylabscom/mvm-images`
  `image-set/v0.1.0` by signed-root digest `9bb4f0b…` with the exact
  release-workflow identity; the previous `mvm` boot-image release and
  signing identity remain in the explicit `legacy` lock entry.
- Every acquisition route (Stage 0, builder/default images, workload
  kernels, image update/check, CI download lanes, WebLinux) resolves the one
  lock and refuses incompatible protocols before member downloads.
- Merge-queue lanes witness the published path end to end: the boot-latency
  lane fetches, cosign-verifies, and hash-checks the pinned x86_64 members
  before booting, and the guest-image-boot lane builds from `mvm-images`
  with the `mvm` input overridden to the queue's checkout.
- Image construction lives entirely in `mvm-images`. What remains in `mvm`
  is the in-tree producer vestige (`nix/images`, its release machinery, and
  the build arms that still know how to invoke it) — that is W8's target.

## W7 — dual-publish compatibility window

Goal: for at least one full image and CLI release, new CLIs consume the
locked `mvm-images` manifest while old (pre-W6) CLIs keep working against
the legacy `mvm` release URLs, and we can demonstrate both, compare digests, and
roll back without rebuilding a CLI.

### W7.1 Mirror the pinned set into `mvm` releases

- [x] Extend the `mvm` release workflow with a mirror job that downloads the
      locked image-set members (both architectures, plus the default-image
      trio the legacy release used to carry) from the `mvm-images` release
      and attaches them to the `mvm` release under the historical asset
      names. The job reads every URL and digest from `images.lock` — never
      from a mutable latest release.
      *Done:* `release.yml`'s "Mirror the locked image set into this release"
      step replaces the old attach step, which asked `tinylabscom/mvm` for the
      lock's `image-set/v0.1.0` tag — a release that exists only in
      `mvm-images`, so the next CLI release would have failed there. Repository
      and manifest name come from `scripts/locked-image-tag.sh`, the tag from
      `xtask release-boot-image tag`, and the attached names from
      `xtask release-boot-image mirror-assets` (38 assets). The mirror is
      load-bearing for current CLIs too, not only old ones:
      `download_runtime_overlay`, `download_sdk_sidecar` and
      `download_initramfs` still resolve `…/tinylabscom/mvm/releases/download/v{version}/`.
- [x] Gate the mirror on a digest comparison: every mirrored asset's
      SHA-256 must equal the corresponding member digest in the signed root
      (and the legacy default-image trio's recorded digests). A mismatch
      fails the release, loudly, before publication.
      *Done:* two gates, both before signing. The `mvmctl` being released runs
      `image boot verify --require-complete` over the whole set; `--lock` is
      now optional and defaults to the lock compiled into the binary, so the
      check is "would this CLI accept these bytes". Then
      `xtask release-boot-image validate` checks each mirrored file: members by
      the root's digest and size, checksum manifests line by line (member lines
      must agree with the root, every listed file must hash to its line),
      `.sha256` sidecars against the root, and it refuses any file nothing
      anchors — which is why `default-microvm-*.sbom.txt` is not mirrored.
      Real-bytes evidence (2026-09-24, against the published
      `image-set/v0.1.0`): `image boot verify` verified all 29 artifacts under
      signer key id `6996feb9248dd8eee1e335470cbff52a`; the mirror gate
      accepted the 38 legacy-named assets and refused a one-byte edit to
      `default-microvm-meta-x86_64.json`.
- [x] Tests: the digest-comparison helper accepts equal digests, refuses
      missing members, refuses size mismatches, and refuses a root whose
      member list does not cover the legacy trio.
      *Done:* 13 tests in `xtask/src/release_boot_image.rs` (accept; tampered
      member; wrong size; missing and empty required asset; uncovered legacy
      name; unpinned root; checksum manifest disagreeing with the root;
      drifted auxiliary; sidecar disagreeing with the root; unanchored file;
      tag drift; list coverage), one in `image boot verify` for the compiled
      default, and three `tests/release_assets.rs` structure tests: the source
      repository is read from the lock, and verify → gate → attach all precede
      signing.

### W7.2 Define and collect the health signals

- [x] Record the window's exit criteria before it opens, in this file:
      `guest-image-boot` and boot-latency lanes green on every merge during
      the window; at least one `update-image-pin.yml` dry-run verification
      green; download counts on the `mvm-images` release observed via the
      GitHub API at window open and close; zero reported 404s against
      legacy asset URLs (GitHub release asset traffic plus issue tracker).
      *Recorded; window opened 2026-09-24T19:24:38Z.* Baseline, from the
      releases API: `mvm-images` `image-set/v0.1.0` 182 asset downloads
      (`image-set.json` 39); legacy `mvm` `boot-image/v0.1.5` 5,118;
      `v0.18.0-rc.1` 418. No open issue reports a 404. GitHub exposes no
      per-asset 404 counter, so "zero 404s" is observed through the issue
      tracker and the boot lanes, not through release traffic. The
      pin-update dry run could not have gone green: its inline lock rewrite
      named `[stage0_kernel.aarch64]` / `asset`, sections the lock does not
      have, so every run — including the weekly schedule — exited before
      proposing anything, and it never advanced `[stage0_kernel]`'s tag. It
      now calls `xtask repin-image-lock`, which re-parses the lock it writes
      (6 tests; idempotent on the real `image-set/v0.1.0` root).
- [x] Window length: one full CLI release train plus the observations
      above; extend once if any signal is unavailable, not silently.
      *Closed 2026-09-25T15:07:55Z* after one CLI release train
      (`v0.18.0-rc.2`) and one image release (`image-set/v0.1.1`); every
      signal was available, so the window was not extended. Evidence is in
      "W7 window close" below.
      *2026-09-24:* the producer revocation channel is live —
      `revocation-list/v1` (tinylabscom/mvm-images#27 moved signing off the
      `revocations/` prefix, whose tags made the channel's own `revocations`
      release tag uncreatable), verified with `cosign verify-blob` against
      `revocations.yml@refs/tags/revocation-list/v1`. The first release-train
      attempt, `v0.18.0-rc.2` (run 36073659591), was cancelled after the
      macOS documented-surface lane failed to compile: `main` did not build
      with the release feature set (`release-artifact-bootstrap` +
      `manifest-verify`) because W6 had made `builder_vm_artifact_names`
      test-only while the builder-pack fetch still uses it. CI checked the
      bootstrap feature alone; it now checks the combination.

### W7.3 Rollback drill

- [x] On a branch, point `images.lock` at the previous selection (the
      explicit `legacy` entry) and run the acquisition/boot lanes
      (guest-image-boot, boot-latency, image check) against it in CI.
      Restore the pin afterwards. The drill must not require rebuilding a
      CLI and must not touch the merge queue's protected state.
      *Done 2026-09-25, against `image-set/v0.1.0` rather than `legacy`* (the
      finding below): forward to `image-set/v0.1.1` through the queue as
      #3677 (merge-group run 36089819238), back to `v0.1.0` by
      `xtask repin-image-lock` on `drill/w7-rollback-to-image-set-v0.1.0`
      (dispatch run 36093777305, green on its second attempt after a
      transient Nix store error in the flake check). Both boot lanes passed
      in both directions;
      no CLI was rebuilt and `main` was never moved back.
- [x] Record the drill result in `specs/sprint/delivery/`.
      *Done:* `specs/sprint/delivery/3368-w7-window-close.md`.

*Finding (2026-09-24), before any drill run:* the drill cannot target the
`legacy` entry as written. A lock whose `[image_set]` names
`tinylabscom/mvm` `boot-image/v0.1.5` would parse, but that release publishes
no `image-set.json`, so there is no root digest to pin and every current
acquisition path refuses at the manifest stage before touching a member. The
`legacy` entry is a trust record for pre-W6 CLIs, which never read the lock;
it is not a rollback target for current ones. The drill therefore needs a
second verified `image-set/v*` release in `mvm-images` to move between: pin
it through `update-image-pin.yml`, dispatch `ci.yml` on that branch (both
`Boot latency ceiling` and `Guest image boots (mvm-images)` run on
`workflow_dispatch`, so the queue is untouched), then restore
`image-set/v0.1.0` by lock edit alone and run the lanes again.

### W7.4 Migration and support-window documentation

- [x] Publish the support window in the docs site and the `mvm` release
      notes: which CLI versions consume which URLs, the legacy-URL
      retirement date, and the pin-update cadence (`update-image-pin.yml`).
      *Done:* `public/src/content/docs/reference/releases.md` §"Image
      releases and the support window" (per-version URL table taken from
      the source at each tag; no release is deleted; `legacy` lock entry
      kept until 2026-12-31; weekly Monday 09:23 UTC pin proposals), and a
      matching section in the release-notes prefix
      `nix/packaging/release/runtime-overlay-operational-note.md`.
- [x] The docs must state plainly that image construction is no longer
      possible from the `mvm` tree after W8 — contributors land image
      changes in `mvm-images`.
      *Done:* same section; the contributor guides already point image work
      at the `mvm-images` sibling.

Which CLI reads what, from the source at each tag (2026-09-24):

| CLI | builder / default image / kernels / Stage 0 | overlay / sidecar / initramfs |
|---|---|---|
| v0.16.1, v0.17.0 | `tinylabscom/mvm` own `v{version}` | own `v{version}` |
| v0.18.0-rc.1 | `tinylabscom/mvm` `boot-image/v0.1.5` | own `v{version}` |
| main | `mvm-images` `image-set/v0.1.0` via `images.lock` | own `v{version}` |

No old CLI 404s as long as existing releases stay published, which is a
non-goal to change.

Acceptance (carried from the parent plan): no supported CLI version
receives a 404 or accepts differently signed bytes during the transition.

### W7 window close (2026-09-25)

The window ran from 2026-09-24T19:24:38Z to 2026-09-25T15:07:55Z. Every exit
criterion recorded in W7.2 was met:

- **Boot lanes.** 17 merge-group runs completed in the window (a further one,
  #3675, was still in the queue at close). `Guest image boots (mvm-images)`
  passed on 17 of 17. `Boot latency ceiling` passed on 16 and was skipped on
  the documentation-only #3668 by its path scope; it failed on none.
- **Pin-update dry run.** `update-image-pin.yml` dispatch run 36065248466
  passed, reporting that `images.lock` already pinned `image-set/v0.1.0` — the
  first green run the workflow has had. Run 36085954556 then verified the
  `image-set/v0.1.1` root and pushed the lock advance, and failed only at its
  last step, opening the pull request, which the repository did not permit;
  the pushed branch was opened by hand as #3677.
- **Download counts** (GitHub releases API, all assets summed):

  | Release | Window open | Window close |
  |---|---:|---:|
  | `mvm-images` `image-set/v0.1.0` | 182 (`image-set.json` 39) | 390 (67) |
  | `mvm-images` `image-set/v0.1.1` | not yet published | 481 (108) |
  | `mvm` `boot-image/v0.1.5` (legacy) | 5,118 | 5,139 |
  | `mvm` `v0.18.0-rc.1` | 418 | 488 |

  The legacy release and the pre-W6 CLI release kept serving downloads while
  the image-set roots were read by new CLIs: old CLIs used the legacy URLs,
  new ones the locked manifest.
- **404s.** No open or closed issue reports a 404 against a legacy asset URL.
- **Release train.** `v0.18.0-rc.2` (release run 36134611204) published 68
  assets. Its mirror step verified the pinned `image-set/v0.1.1`, all 29
  artifacts, with the `mvmctl` being released before anything was signed.
  Its `verify-release` job waited for the workload kernels, which
  `kernel-build.yml` attaches separately (dispatch run 36150025746, green),
  and, re-run once they were attached, failed on three asset-set checks,
  none of them in the mirror:
  - The verifier required a per-archive `mvmctl-<target>.tar.gz.sha256` that
    `release.yml` never uploads. `v0.18.0-rc.1`'s `verify-release` failed on
    the same check, so the job has never passed. Nothing downloads the file:
    the installer and `mvmctl update` read the signed
    `checksums-sha256.txt`. The fix, checking each archive against that
    manifest, rides with Wave 3's rewrite of the verifier.
  - The kernel checksum manifests are signed by `kernel-build.yml`, and the
    verifier accepts only the `release.yml` identity.
  - The builder-VM `pack-manifest.json` that `release.yml`'s attested-pack
    job adds is absent from the mirrored builder-VM checksum file, which
    comes from the image set.

  The last two are the in-tree producers W8 deletes: after Wave 3 the
  kernels and the builder pack come only from the signed image set.
  Four release blockers were fixed on the way and none was image-related:
  #3678 (the release feature set did not compile), #3687
  (`mvm-gpu-endpoint` was not shipped), #3688 (a removed machine's instance
  state leaked into its successor), and #3689 (the documented-surface lane
  did not tolerate the destructive-lab skip).
- **Rollback drill.** W7.3 above: both directions green, no CLI rebuilt.

`image-set/v0.2.0` in `mvm-images` is a burned tag: its publish step refused,
fail-closed, because the pinned `mvm` could not parse the new initramfs role,
and nothing was published under it. The next image set is `image-set/v0.2.1`.

The `legacy` lock-entry retirement date, 2026-12-31, was confirmed by the
maintainer on 2026-09-25; it had been recorded as a proposal. Pin proposals
from `update-image-pin.yml` still need the repository setting that lets
GitHub Actions open pull requests; the maintainer is enabling it, and until
then a proposal branch is opened by hand, as #3677 was.

## W8 — cut over, remove duplication, shrink the suite

Goal: delete image construction and canonical image hosting from `mvm`,
keep the contract/resolver/boot-test surface, and re-measure the release.

Hard gates before any W8 PR:

- [x] W7 window evidence collected and appended to this file (W7.2 signals
      plus the W7.3 drill record). *Done:* "W7 window close" above.
- [ ] A fresh deletion inventory re-scanned from `main` at W8 start; the
      wave assignments below revalidated ref by ref. The inventory below is
      a 2026-09-24 snapshot (44 crate files, 7 workflows), not a contract.

### Deletion inventory (2026-09-24 snapshot)

Reference classes: **D** = delete with the wave, **K** = keep
(contract/resolver/verify/tests), **E** = edit (docs/comments/fixtures that
mention in-tree paths without depending on the flakes).

Wave assignment is the plan; the W8 kickoff task reclassifies each
reference before its wave lands.

**Workflows (7):** `cache-warm.yml` (D), `ci-full.yml` (E — strip image
build legs), `ci.yml` (E), `kernel-cve-watch.yml` (E), `release.yml` (D —
retire image asset publication and signing; keep the CLI release),
`release-boot-image.yml` (D — whole file), `security.yml` (E).

**Crates (44 files):** every reference in `mvm-build` (18 files: the build
bins, `builder_vm_image.rs`, `builder_vm_runtime.rs`, `libkrun_builder.rs`,
`initramfs.rs`, `stage0*.rs`, `runtime_overlay.rs`, `image_source*` — the
last two keep the resolver and lose the in-tree arm), `mvm-cli` (16 files:
`commands/build/*`, `commands/env/builder_vm/*`, `doctor/image_source.rs`,
`update.rs`, `vm/exec.rs`, `tests/agent_workload_example.rs`), `libkrun-sys`
(`sys.rs`, E), `mvm-agentd` (`guest_mount.rs`, E), `mvm-backends`
(`driver/qemu.rs`, E), `mvm-conformance` (`lib.rs`, E), `mvm-contract`
(policy files, E), `mvm-core` (`config.rs`, `image_set/tests.rs` — the
contract itself is keep; fixture paths may need edit), `mvm-fs`
(`initramfs.rs`, E), `mvm-runtime` (`template/lifecycle/artifacts.rs`, E),
`mvm-vmm` (`host/runtime_meta.rs`, E).

**Keep-list (never deleted in W8):** `crates/mvm-core/src/image_set*`
(contract, validation, typed selector), `crates/mvm-core/images.lock`,
the acquisition boundary in `mvm-build` (`artifact_verify`, manifest
verify, cache install), `update-image-pin.yml`, the boot witnesses
(`runtime_boot_bench`, guest-image-boot lane, boot-latency lane), and the
sibling-checkout selector minus its in-tree arm.

### Waves

- [ ] **Wave 0 — classification and trackers.** Re-scan from `main`,
      produce the per-ref D/K/E table as a checked-in inventory file under
      `specs/`, open the W8 tracking issue updates. No code changes.
- [ ] **Wave 1 — `mvm-build`.** Remove the in-tree image-build arms
      (`InTree` selector variant and its flake invocations, builder-vm and
      default-microvm image builders, the `build image-set`-style verbs that
      build from `nix/images`), keeping pair builds (they build from the
      sibling checkout, not `nix/images`). The tool-builder path exempted
      from pair routing in W5f is re-pointed at published/fetch acquisition,
      not at `nix/images`.
- [ ] **Wave 2 — `mvm-cli`.** Remove the build verbs and bootstrap arms
      that construct images in-tree; keep install/verify/doctor surfaces.
- [ ] **Wave 3 — workflows.** Land the workflow D/E set: retire
      `release-boot-image.yml`, strip image publication/signing from
      `release.yml`, drop image-build legs from `cache-warm.yml` and the CI
      lanes, keeping every lane that consumes the published path.
      *Prerequisite found 2026-09-24:* CLIs built from `main` still download
      the runtime overlay, SDK sidecar and initramfs from their own
      `tinylabscom/mvm` `v{version}` release (`download_runtime_overlay`,
      `download_sdk_sidecar`, `download_initramfs`), under the CLI identity.
      Stripping the W7.1 mirror from `release.yml` before those three read
      the image set would make every new CLI 404. The overlay and sidecars
      are already signed-root members; the initramfs is published by
      `mvm-images` but is not a root member, and `release.yml` still builds
      it from `nix/images/initramfs`. Those moves are a Wave 3 precondition,
      not a follow-up.
      *Second coupling (2026-09-24):* the overlay, sidecar and initramfs
      resolvers refuse a `VERSION` that differs from the running CLI's
      semver, and `nix/images/version.nix` is what `_release-prep` bumps. An
      image set therefore serves exactly one CLI version: the W7.1 mirror for
      `v0.18.0` needs a set built at `0.18.0`. Moving these artifacts to the
      image set means replacing that equality with the set's declared
      `compatibility` range, or every CLI release still needs an image
      release.
- [ ] **Wave 4 — tree and stragglers.** Delete `nix/images/`, the E-class
      reference edits across remaining crates, and live-doc updates
      (`CLAUDE.md`, `AGENTS.md`, contributor docs) to state that image
      construction is `mvm-images`-only. Historical specs, ADRs, and
      delivery notes stay as history.
- [ ] **Re-measure.** Record release duration, release storage, download
      volume, and failure rate against the pre-W8 baseline; the release
      gate must be at least 25 minutes faster per the parent plan, and
      rollback must remain a lock-file change to a verified existing
      release. Normal host-only changes must not rebuild an image, and an
      image-only change must not require a CLI release.
- [ ] **Suite sharding (separate PR).** If the 313-scenario
      documented-surface suite's live phase remains the release critical
      path after the image legs are gone, shard it per the parent plan —
      this is intentionally not bundled with any wave above.

Non-goals: deleting GitHub release assets or historical releases; changing
the `Released`-arm trust semantics; touching `mvm-images` (its own repo
owns the producer side); W9 history compaction (separate decision, separate
window, per #3373).

## Test expectations

- Every deleted arm's refusal test stays: after W8, attempting an in-tree
  image build must fail with a clear "image construction lives in
  `mvm-images`" error, not a missing-flake mystery. This is a new test in
  Wave 1 and gates Waves 2–4.
- W7.1's digest gate gets positive, negative (tampered member), and
  missing-member tests.
- The keep-list surfaces keep their existing tests green untouched; a
  final full workspace run plus `just check-gated` and the repository
  gates (`check-declared-backing`, `check-nextest-groups`,
  `check-workflow-paths`, `check-builder-shell-job-sites`, and the rest of
  the check-all set that references `nix/images`) gate the last wave.

## Rollout

W7.1 → W7.4 land as small sequential PRs (W7.2's signal collection is
elapsed time and needs no PR beyond the criteria edit). W8 waves land in
order, each green on the full matrix before the next opens. The parent
plan's workstream checkboxes tick as waves land; this file's boxes are the
execution detail.
