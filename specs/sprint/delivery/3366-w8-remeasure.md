# W8 re-measure — the v0.18.1 release without in-tree images

Backing: shipped-source
Validation: the measured numbers below, taken from the v0.18.1 release run
(36375167752) and the GitHub releases API.

Issue #3366, plans `specs/plans/2026-09-24-image-cutover-and-deletion.md`
(W8) and `specs/plans/2026-09-16-image-repository-extraction.md` (parent).

## What was measured

The re-measure release is `v0.18.2` — the first CLI release cut after
Waves 3+4 removed image construction, mirroring and re-signing from the
`mvm` release **and** the first to ship with a green release gate. Its
predecessor `v0.18.1` (tag `72a797a677`, pushed 2026-09-28T03:48:42Z) was
cut from the same tree but its release could not go green: both
documented-surface lanes failed the two in-process SDK scenarios
deterministically (twice), root-caused to #3785 — the transient
`LocalBackend` launch booted runtime-lean OCI images without the
universal initramfs and panicked at `/init`. #3785 was fixed (#3792) and
`v0.18.2` supersedes `v0.18.1`, which never published. The phase timings
below are from the v0.18.2 attempt (identical trees modulo the two release-blocking
fixes; the v0.18.3 lanes confirm them)

- **Duration (tag push → published).** 3h17m for v0.18.3 (tag pushed
  15:52:47Z, run 36446916391; promoted 19:10:15Z), the Linux e2e lane
  ~2h33m of it on the critical path. rc.2 for comparison: its Linux e2e
  lane alone was 2h16m on the critical path (run 36134611204). v0.18.1
  and v0.18.2 never published — both were cut before release-blocking
  defects found only by this suite were fixed: #3785's two halves, fixed
  by #3792/#3795.
- **Linux documented-surface lane.** 147.5 min end to end, all 340
  runnable scenarios green (v0.18.3 run 36446916391): build 11.7 min,
  builder image 8.7 min (a verified fetch of the pinned set's member — at
  baseline this was inside the 37-min source-prep), SDK sidecar 22.1 min
  (source pair build), dev default image 39.4 min (source pair build),
  suite 65.4 min (313 → 340 scenarios). Against the 2026-09-15 baseline
  (build 10, image prep 37, scenarios 67; 114 min job) and rc.2 (2h16m
  Linux e2e on the critical path).
- **What remains on the lane's critical path.** The two
  source pair builds the lane still pays: the SDK sidecar (~24 min) and the
  dev default-tenant image (~42 min). The dev image has no published member
  and the sidecar's published fingerprint is not recorded yet, so the lane
  cannot fetch either; that is the follow-up plan
  `specs/plans/2026-09-27-release-e2e-under-image-target.md`.
- **Release storage.** v0.18.3: 10 assets, ~55 MiB — CLI archives and
  manifests only. rc.2: 78 assets, ~1.66 GiB, including the 38 mirrored
  image assets the CLI release no longer builds, mirrors, re-signs or
  attaches.
- **Download volume.** v0.18.3: 16 downloads in its first minutes (10
  assets). The image bytes moved to the image train: `image-set/v0.2.1`
  stood at 1,138 downloads across its 148 assets at publish time (805 at
  the morning of the re-measure), consumed by the boot lanes, the
  release lanes and contributors — the same fetch volume the CLI release
  used to carry as mirrored assets. Method: releases API `downloadCount`
  summed over assets, as in the W7 window.
- **Failure rate.** Three release attempts were needed, and the reasons are
  the measurement's most useful finding: the release suite caught two
  real, release-blocking defects that no PR-level lane could see — the
  in-process SDK boot without the universal initramfs (#3785, fixed by
  #3792) and the SDK run reply's build_mode conflating host accessibility
  with the declared profile (#3795) — plus one transient external failure
  (two egress scenarios saw example.com return 404 for a few minutes;
  green on re-run). The suite is the only lane that exercises the
  in-process SDK path end to end.
- **first-run smoke.** Green on both platforms inside the release
  (macOS HVF 77s, Linux Firecracker 27s). The three-boot smoke
  (tinylabscom/mvm#3782) exercises the download-mode path the release
  decoupling (#3787) serves — a second boot re-downloading the overlay or
  initramfs, or refusing the published sidecar, fails it — and it passed
  on the first release shipping that path.

## Acceptance status, recorded honestly

- Host-only change rebuilds no image: holds — every in-tree build arm is
  gone (Waves 1+2) and the released CLI acquires its overlay, sidecar and
  initramfs as members of the pinned set (#3787 keys them by the pinned
  root, so the 0.18.0-rc.2 member `VERSION` no longer matters).
- Image-only change needs no CLI release: holds — the `image-set/v0.1.1`
  pin advance landed as #3677 with no CLI release.
- Rollback is a lock-file change to a verified existing release: holds —
  drilled both directions during W7.3 (#3677 forward, dispatch run
  36093777305 back, both boot lanes green each way).
- Release gate at least 25 minutes faster: **missed, and left open.** The
  image-prep saving landed (no mirror, no in-tree prep), but the lane's two
  remaining pair builds keep it at ~148 minutes, above the baseline's
  114 minutes. The parent plan's gate box stays unticked; the plan Status
  stays IN PROGRESS; the follow-up plan above carries the work to bring the
  e2e under target (publish the dev default-tenant member and the sidecar
  fingerprint, fetch both when unchanged).

## Boot witnesses (parent W6's open box)

`image-set/v0.2.1`'s default-tenant pack booted through every Linux-direct
backend the fleet has, clean caches, reported on tinylabscom/mvm-images#8:

| Host | Arch | Backends | Result |
|---|---|---|---|
| witness Mac (macOS 26) | aarch64 | HVF, libkrun | PASS (2026-09-26) |
| rpi1.local (Pi 4, KVM) | aarch64 | Firecracker, QEMU | PASS (2026-09-28) |
| Hetzner KVM box | x86_64 | Firecracker, QEMU | PASS (2026-09-28) |

Bundles under `~/.cache/mvm-witness/` (`v0.2.1-hvf-libkrun-2026-09-26`,
`v0.2.1-rpi1-aarch64-2026-09-28`, `v0.2.1-hetzner-x86_64-2026-09-28`).
Found on the way and filed as tinylabscom/mvm#3789 (contributor-checkout
second-boot refusal; fixed by #3791; release binaries were unaffected).
