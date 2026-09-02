# Retire `VmVolumeKind::DirShare`

Backing: shipped-source
Validation: check-sprint-append

**Status: NOT STARTED — this is the design, not the change.** The last open box
of `specs/plans/2026-08-31-remove-virtio-fs.md` Stage A. It is separated because
it is not cleanup: it moves a fact the security model matches against.

## What `DirShare` is now

Not a transport. Since Stage A, every granted directory is materialized into an
ext4 image by `materialize_mount_volumes` and attached as virtio-blk; the volume
keeps `kind: DirShare` and carries the image in `materialized_image`. The
enum variant survives as a **record of what was granted**, and the removal plan
says so:

> `DirShare` is what records a *directory* grant in the plan, which claim 1
> matches against, so removing it means moving that fact somewhere else first.

## Why that fact cannot just be deleted

`mvm_hostd::plan_admission::enforce_admitted_shares` is the claim 1 / claim 8
trust-boundary hook. It derives the kind it demands straight from the runtime
enum:

```rust
let want_kind = match v.kind {
    VmVolumeKind::DirShare => ShareKind::DirShare,
    VmVolumeKind::Disk     => ShareKind::Disk,
};
let admitted = plan.shares.iter().any(|g| /* … */ g.kind == want_kind /* … */);
```

Delete the variant and every volume resolves to `ShareKind::Disk`, which no
longer matches a signed plan that recorded `ShareKind::DirShare`. Two bad
outcomes, and the second is worse:

- **Refuse to boot** anything whose plan recorded a directory grant, or
- **Stop recording that a directory was granted at all** — at which point an
  auditor reading the chain sees "given a disk image under `~/.mvm`" instead of
  "given host directory `/x`". That is the fact the grant exists to carry, and
  losing it is a weakening of claim 1 dressed up as a refactor.

## The shape the fix should take

Keep `ShareKind::DirShare` in the **signed plan** — the audited artifact, where
the grant belongs — and stop deriving it from a runtime enum variant. The
volume already carries the discriminator:

```rust
let want_kind = if v.materialized_image.is_some() {
    ShareKind::DirShare   // a granted directory, delivered as an image
} else {
    ShareKind::Disk
};
```

`materialized_image` means exactly "the ext4 image the granted directory was
materialized into"; its doc already explains that `host` stays the directory
that was granted "because that is the fact an admission record has to carry".
The information is present. Only the derivation reads the wrong field.

## What blocks it today

**Unmaterialized `DirShare` is still producible.** `LocalVolume::as_vm_volume`
maps `LocalVolumeKind::Directory` to `VmVolumeKind::DirShare` with
`materialized_image: None`, and that kind is reachable: `register_attachment`
constructs it for `VolumeSourceKind::ManagedDirectory` /
`AdHocHostDirectory`. Under the derivation above those volumes would resolve to
`ShareKind::Disk` and stop matching their own plans.

So the first question is not about `VmVolumeKind` at all:

- [ ] **Decide what a managed *directory* volume is.** Either it materializes
      like `--mount` does (and `LocalVolumeKind::Directory` collapses into
      `BlockImage`), or it stays a genuinely different thing and needs its own
      discriminator. `attaches_as_block()` already returns `false` for it, so
      today it reaches no backend as a device — worth establishing whether that
      path boots at all before designing around it.

## Ordered work

- [ ] Establish whether an unmaterialized `DirShare` can reach a live boot, and
      what happens if it does. This is the load-bearing unknown; everything
      below is contingent on it.
- [ ] Move the `want_kind` derivation off `VmVolumeKind` and onto
      `materialized_image`, with a test that a plan recording `ShareKind::DirShare`
      still admits a materialized mount, and that a `Disk` plan does not admit
      one.
- [ ] Only then delete `VmVolumeKind::DirShare` and `LocalVolumeKind::Directory`.
- [ ] Live-validate `mvmctl machine run --mount` end to end. The claim-1 check
      is the boot path; a unit test that constructs both sides agrees with
      itself by construction, which is the failure mode this repo has hit
      repeatedly.

## Found while scoping, not part of this work

`validate_firecracker_start_config` (`mvm-runtime/src/backend.rs:185`) refuses
**any** volume whose kind is `DirShare`, with:

> Firecracker has no virtio-fs, so directory share '…' isn't supported; use a
> disk-image volume instead (host:/guest:SIZE).

That message describes the world before Stage A. A materialized `--mount` *is* a
disk-image volume and Firecracker can serve it, but the check matches on `kind`
alone and would refuse it.

It is **not a live bug**: its only callers are `FirecrackerConfig::from_start_config`
and `…_with_slot`, and `FirecrackerConfig` has no consumer outside its own
module beyond a `pub use` in `lib.rs`. The wrapper's own doc calls it legacy.
Recorded because it is a landmine for whoever revives it, and because it is
evidence for this plan: a `DirShare` that is really a block device already
misleads one reader in the tree.
