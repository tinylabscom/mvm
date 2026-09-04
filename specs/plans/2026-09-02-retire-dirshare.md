# Retire `VmVolumeKind::DirShare`

Backing: shipped-source
Validation: check-sprint-append

**Status: COMPLETE.** The registration-time snapshot prerequisite and runtime
variant retirement are implemented. This was separated from mechanical cleanup
because it moves a fact the security model matches against.

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

## Resolved prerequisite

The apparent blocker was an unmaterialized `DirShare` from the local-volume
registry. Live measurement established that it never reached a guest, and
#3151 removed the last producer: `machine volume mount --host` snapshots the
directory into an ext4 image and registers `LocalVolumeKind::BlockImage`.
Persistent machine-spec directory entries remain an explicit refusal before a
runtime volume is built.

So the first question is not about `VmVolumeKind` at all:

- [x] **Decide what a managed *directory* volume is.** Answered by measurement,
      and the answer makes the retirement smaller than this plan assumed: **an
      unmaterialized `DirShare` is unreachable on every path.** There is no
      live configuration in which one serves a guest, so
      `LocalVolumeKind::Directory` needs neither materialization nor a new
      discriminator — it needs deleting.

      The two paths reach that end differently, which is why one measurement
      did not answer for both:

      | path | behaviour |
      | --- | --- |
      | transient `machine run --name` | registration silently ignored; boot succeeds; mount absent |
      | persistent `machine start` | **refused before boot**, naming the volume and two ways forward |

      The persistent refusal comes from the workload runner, not the guest:
      *"the WorkloadRunner has no virtio-fs device yet, so a live
      host-directory share can't be expressed. Use a disk-image volume instead
      (host:/guest:SIZE)"*. It never reaches guest init, so the predicted
      virtiofs `ENODEV` never happens — worth recording, because the code path
      (`resolve_mount_entry` ends `LocalVolumeKind::Directory => {}`, no
      conversion) correctly predicted *that it fails* and wrongly predicted
      *where*.

      Measured on macOS 26 / HVF via `machine start`, which needs no LUKS
      fixture because the FileVault probe admits the registration. `#3146` pins
      the same refusal on Firecracker, so it holds on both backends.

- [x] **Make `--host <directory>` registration useful and consistent.** The
      shared `machine volume mount` boundary now snapshots the directory into
      a namespaced ext4 image and registers that image as a disk attachment.
      Persistent launch consumes the same block-volume shape as every other
      image attachment instead of reaching the workload runner as an
      unmaterialized directory share. The source and snapshot destination must
      both have encrypted backing, and the snapshot is created with private
      filesystem permissions before source bytes are written.

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

- [x] **Exercise the persistent registration path.** The BDD regression now
      proves that a real host directory registers as an ext4 snapshot, while
      focused service tests prove the image validates, acquires a launch lease,
      and resolves as `VmVolumeKind::Disk`. Malformed images are refused.

      Managed directories still need either materialization or a durable
      discriminator before the runtime enum can be removed.
- [x] **Decide whether silently ignoring a registered volume is acceptable.**
      Decided: no, but a warning rather than a refusal, landed in
      `fix(mount): say what a transient run will and will not attach`.

      Not a refusal because attaching would take the exclusive attachment lease
      that `machine stop` releases, and a transient run has no stop to pair with
      it; and refusing outright would break a run whose registrations are simply
      irrelevant to it. Best-effort, too — a registry that cannot be read must
      not fail a boot that never depended on it.

## Ordered work
- [x] Materialize ad-hoc `--host <directory>` registrations into private,
      encrypted-destination ext4 snapshots and resolve them as block volumes.
- [x] Move the `want_kind` derivation off `VmVolumeKind` and onto
      `materialized_image`, with a test that a plan recording `ShareKind::DirShare`
      still admits a materialized mount, and that a `Disk` plan does not admit
      one.
- [x] Only then delete `VmVolumeKind::DirShare` and `LocalVolumeKind::Directory`.
- [x] Live-validate `mvmctl machine run --mount` end to end. The claim-1 check
      is the boot path; a unit test that constructs both sides agrees with
      itself by construction, which is the failure mode this repo has hit
      repeatedly.

## Verification

- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `just check-gated` (x86_64 Linux all-target and BDD compilation)
- `just bdd` (65 features, 249 scenarios: 248 passed and one capability skip)
- Live Firecracker `mvmctl machine run --mount` against immutable Alpine
  `sha256:e7a1a92a5bfeee40966aea60f0796b0e7917cc35591542701834f03a68fa3d18`.
  The signed plan admitted the directory grant, the assembled cmdline carried
  `mvm.uvols=uvol0:2f776f726b:ro:blk`, the guest read the materialized mount at
  `/work`, and printed `dirshare-retirement-live-ok`. The project builder VM
  cannot expose nested KVM, so the owner-approved Lima KVM test provider was
  used strictly for this live Firecracker witness and stopped afterwards.

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

## Found while scoping and removed here

`validate_firecracker_start_config` (`mvm-runtime/src/backend.rs:185`) refuses
**any** volume whose kind is `DirShare`, with:

> Firecracker has no virtio-fs, so directory share '…' isn't supported; use a
> disk-image volume instead (host:/guest:SIZE).

That message describes the world before Stage A. A materialized `--mount` *is* a
disk-image volume and Firecracker can serve it, but the check matches on `kind`
alone and would refuse it.

It was **not a live bug**: its only callers were
`FirecrackerConfig::from_start_config` and `…_with_slot`, and
`FirecrackerConfig` has no consumer outside its own module beyond a `pub use`
in `lib.rs`. Retiring the runtime variant also removes this obsolete validator,
so the legacy wrapper now carries materialized directory images as block
volumes if it is inspected.
