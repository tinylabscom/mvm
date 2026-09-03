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
      discriminator.

### What live testing established

Run on macOS 26 / arm64, after fixing the encryption probe that was refusing
every registration (see below):

    mvmctl machine volume mount dirvol-test --volume probevol \
        --host /tmp/mvm-dirvol2 --guest /data/probe     # registers, ok
    mvmctl machine run --name dirvol-test --image alpine -- ls /data/probe
    → ls: /data/probe: No such file or directory        # VM booted fine

So an unmaterialized `DirShare` **does not fail the boot**. It also does not
reach the guest. `mvmctl machine volume ls dirvol-test` still lists the
attachment afterwards, so the registration persisted and the transient `run`
path simply never consumed it.

This **contradicts the code-path reading** that preceded it. `mount_volumes`
propagates a failed mount with `?`, and a workload has no virtio-fs device, so
the prediction was a failed boot. The volume never got that far: it is dropped
before `VolumeConfig` is built, not attached-and-ignored. Recorded because the
inference was confident and wrong, and only the live run separated the two.

- [x] **Find the launch path that *does* consume the registry.** It is
      `start_machine` → `start_persistent_oci_machine` →
      `merge_registered_volumes_for_launch`, i.e. `mvmctl machine start`. That
      is the only production caller; transient `machine run --name` never
      reaches it.

      So the split is by *lifecycle*, not by volume kind: registrations belong
      to a persistent named machine you start and stop, and a transient run is
      a job. Nothing said so, which is what made it look like a bug rather than
      a boundary.

- [x] **Exercise the persistent path with a directory-kind registration.** It
      does consume the registry and preserves the directory discriminator as
      an unmaterialized `VmVolumeKind::DirShare`. The shared workload-runner
      guard then refuses before assembling the backend spec because no
      directory-share device can express the grant. The live BDD regression
      pins that refusal instead of accepting either dangerous alternative:
      silently dropping a registered volume or booting without its data.

      This settles reachability, not the product decision above. Managed
      directories still need either materialization or a durable discriminator
      before the runtime enum can be removed.
- [x] **Decide whether silently ignoring a registered volume is acceptable.**
      Decided: no, but a warning rather than a refusal, landed in
      `fix(mount): say what a transient run will and will not attach`.

      Not a refusal because attaching would take the exclusive attachment lease
      that `machine stop` releases, and a transient run has no stop to pair with
      it; and refusing outright would break a run whose registrations are simply
      irrelevant to it. Best-effort, too — a registry that cannot be read must
      not fail a boot that never depended on it.

## Ordered work
- [ ] Move the `want_kind` derivation off `VmVolumeKind` and onto
      `materialized_image`, with a test that a plan recording `ShareKind::DirShare`
      still admits a materialized mount, and that a `Disk` plan does not admit
      one.
- [ ] Only then delete `VmVolumeKind::DirShare` and `LocalVolumeKind::Directory`.
- [ ] Live-validate `mvmctl machine run --mount` end to end. The claim-1 check
      is the boot path; a unit test that constructs both sides agrees with
      itself by construction, which is the failure mode this repo has hit
      repeatedly.

## Fixed while scoping: the encryption probe could never succeed

`detect_host_path_encryption_status` ran `diskutil info <path>` on the host
directory being shared. `diskutil info` takes a device or a volume, **not an
arbitrary directory** — `diskutil info /Users/auser` exits 1 with "Could not
find disk", while `diskutil info /` exits 0. Every caller passes a directory,
so the macOS arm could never succeed, and `require_encrypted` refused every
`mvmctl machine volume mount` on every macOS host.

The message made it look environmental: both "could not spawn diskutil" and
"diskutil ran and rejected the argument" collapsed into *"diskutil
unavailable"*. It read as a missing tool on this machine rather than a bug in
how it was called.

Fixed in this change: resolve the path to its containing volume's device with
`statfs`'s `f_mntfromname` before asking `diskutil`, and report the two failure
modes separately. Registration now succeeds, which is what made the live test
above possible at all.

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
