# Image cutover window and in-tree image deletion (W7 + W8)

Backing: preview
Validation: each wave lands with the tests and measured evidence named in
its boxes; unchecked waves remain in progress.

**Status:** PROPOSED — planning complete, awaiting W7 window evidence
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

- [ ] Extend the `mvm` release workflow with a mirror job that downloads the
      locked image-set members (both architectures, plus the default-image
      trio the legacy release used to carry) from the `mvm-images` release
      and attaches them to the `mvm` release under the historical asset
      names. The job reads every URL and digest from `images.lock` — never
      from a mutable latest release.
- [ ] Gate the mirror on a digest comparison: every mirrored asset's
      SHA-256 must equal the corresponding member digest in the signed root
      (and the legacy default-image trio's recorded digests). A mismatch
      fails the release, loudly, before publication.
- [ ] Tests: the digest-comparison helper accepts equal digests, refuses
      missing members, refuses size mismatches, and refuses a root whose
      member list does not cover the legacy trio.

### W7.2 Define and collect the health signals

- [ ] Record the window's exit criteria before it opens, in this file:
      `guest-image-boot` and boot-latency lanes green on every merge during
      the window; at least one `update-image-pin.yml` dry-run verification
      green; download counts on the `mvm-images` release observed via the
      GitHub API at window open and close; zero reported 404s against
      legacy asset URLs (GitHub release asset traffic plus issue tracker).
- [ ] Window length: one full CLI release train plus the observations
      above; extend once if any signal is unavailable, not silently.

### W7.3 Rollback drill

- [ ] On a branch, point `images.lock` at the previous selection (the
      explicit `legacy` entry) and run the acquisition/boot lanes
      (guest-image-boot, boot-latency, image check) against it in CI.
      Restore the pin afterwards. The drill must not require rebuilding a
      CLI and must not touch the merge queue's protected state.
- [ ] Record the drill result in `specs/sprint/delivery/`.

### W7.4 Migration and support-window documentation

- [ ] Publish the support window in the docs site and the `mvm` release
      notes: which CLI versions consume which URLs, the legacy-URL
      retirement date, and the pin-update cadence (`update-image-pin.yml`).
- [ ] The docs must state plainly that image construction is no longer
      possible from the `mvm` tree after W8 — contributors land image
      changes in `mvm-images`.

Acceptance (carried from the parent plan): no supported CLI version
receives a 404 or accepts differently signed bytes during the transition.

## W8 — cut over, remove duplication, shrink the suite

Goal: delete image construction and canonical image hosting from `mvm`,
keep the contract/resolver/boot-test surface, and re-measure the release.

Hard gates before any W8 PR:

- [ ] W7 window evidence collected and appended to this file (W7.2 signals
      plus the W7.3 drill record).
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
