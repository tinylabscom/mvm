# WS1 — boot the staged image before publishing it

Every gate in `release.yml`'s `default-microvm` job was a checksum, a signature,
or a byte-level read. None of them can answer the only question anyone asks of a
boot image: does it boot. v0.17.0 shipped an image whose guest panicked with
ENOEXEC before userspace and stayed published for five weeks, with every
checksum verifying clean the entire time — a faithful copy of a broken image is
still faithful.

The job now boots the artifact in `staging/` between the build and the upload,
so a rootfs that cannot reach userspace never becomes a release asset.

## Scope was smaller than the plan

The plan proposed two halves: an x86_64 boot and an aarch64 static `/init`
header check. The header check **already landed** in the release-verification
work that followed the ENOEXEC incident — and landed better than proposed, as
`assert-init-shebang.sh` running on *both* arches, on the staged image before
upload and again on the published image after download, with a red-first fixture
case in `verify-release-assets.test.sh`. Only the boot was missing. Duplicating
the header check would have been a second copy of a gate that already had one.

## What the boot gate is, and is not

It boots the staged bytes on the x86_64 leg only. The aarch64 leg runs on
`ubuntu-24.04-arm`, which has no nested KVM and cannot boot a guest at all; its
coverage stays the static `/init` read. That is a stated compromise, not a claim
of equivalence — an aarch64-only regression that is not a shebang defect still
gets past.

It is **not** a latency assertion. `MVM_RUNTIME_BOOT_BUDGET_MS` is 60s against an
observed median near 2s, and `RUNS`/`CONCURRENT` are both 1. The question is
"does it reach userspace". Latency belongs to the separate `boot-latency` lane,
which has its own threshold and its own argument, and which one budget cannot
serve: loose enough to survive shared-runner noise is too loose to catch drift.

Prerequisites (Firecracker at the pinned `FC_VERSION_DEFAULT`, `/dev/kvm` made
accessible, `mvm-meta.json` placed under the name the admission gate reads) are
copied from the existing `boot-latency` lane rather than reinvented.

## The ordering is the whole value

These are steps in one job, so a failed boot aborts before the upload — but only
while it stays above it. Reorder the two and the gate silently becomes a
post-mortem on an artifact the world already has. So
`the_staged_microvm_image_is_booted_before_it_is_uploaded` pins three things:
the step exists, it precedes the upload, and it boots `staging/` rather than a
published URL. Mutation-tested — deleting the step, moving it below the upload,
and repointing it at a downloaded artifact each fail it.

## Not done

The `boot-latency` lane is still `workflow_dispatch`-only and pinned to
`v0.17.0`. #2542 would put it back on every PR but cannot go green: it repins to
`v0.18.0`, which does not exist, and v0.17.0's own image is the broken one. That
lane is unblocked by cutting a release, not by editing CI, and is unrelated to
this gate — which is the point of booting the *staged* image instead.
