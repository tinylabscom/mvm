# `--mount` is a block image, not a virtio-fs share

**Status: COMPLETE** — Stage A of `specs/plans/2026-08-31-remove-virtio-fs.md`.

## What changed

A granted host directory is materialized into an ext4 image and attached as
virtio-blk. No workload asks for a virtio-fs device any more.

virtio-fs put a FUSE server on the host — parsing requests the guest composed,
pointed at a host directory. It was the one mechanism by which a guest addressed
host filesystem *structure* rather than opaque blocks. An image has no protocol
for a guest to drive.

The immediate prompt was `virtiofsd --sandbox none`, spawned with its own
namespace/seccomp confinement disabled, no comment, no ADR. That flag is on the
QEMU path and is *not* fixed here — see "Not done".

## Why this was small

Almost all of it already existed, and most of what was left was deletion.

- The converged workload runner **already had no virtio-fs device**:
  `ensure_no_dir_share_volumes` says a directory share "can't be expressed on
  this path".
- Firecracker **already refused** virtio-fs, with a test.
- The volume model already had both halves, and already called one of them
  legacy: `LocalVolumeKind::{Directory, BlockImage}` → `VmVolumeKind::{DirShare,
  Disk}`. Managed volumes were already block images; **nothing about `mvmctl
  volume` changes.**
- The builder had already made this exact move for its own reasons —
  `pack_stage0_work_disk` packs a tree into a labelled ext4 image because
  virtio-fs-over-FUSE exhausted libkrun's handle pool under `nix build`.
- `materialize_ext4_pure` — pure Rust, no `mkfs`, no subprocess — already writes
  every rootfs.

## The audit decision

`plan_admission` maps `VmVolumeKind::DirShare` → `ShareKind::DirShare`, and the
chain records the host path under claim 1. Had `--mount` simply become a `Disk`,
the chain would record an ext4 image under `~/.mvm` and lose the fact that a
host *directory* was granted.

So `VmVolume.host` stays the granted directory and a new
`VmVolume.materialized_image` carries what is actually attached. The grant and
its transport are different facts and only the first belongs in an admission
record.

## One predicate, three callers

The block list, the slot arithmetic and the guest device mapping all have to
agree on which volumes are attached and in what order. They previously each
matched on `kind`. They now all call `VmVolume::attaches_as_block`, because
drift between them means a guest mounts a real device holding someone else's
data and nothing errors.

`a_materialized_grant_resolves_to_the_block_node_the_vmm_created` is the test
for exactly that.

## Verified live

macOS/HVF, `--mount /tmp/mvm-mount-test:/work -- sh -c "cat /work/marker.txt"`:

```
hello from the host
```

The guest read a host file from a materialized image over virtio-blk, with no
virtio-fs device in the launch.

## Semantic change

A mount is a snapshot taken at boot; host edits during the run are not visible.
`--mount` was already read-only — the CLI refuses `rw` with "transient live
shares are read-only" — so mid-run visibility is the only property lost.

**This is not yet documented in `--mount --help` or the README.** It must be
before this ships.

## Removed

`refuse_unsupported_dir_shares` and both its call sites. It existed to refuse
`--mount` on backends without virtio-fs; every backend can serve a mount now,
so the refusal could only produce a false one.

## Not done

- **Backends still advertise `directory_shares`** and the virtio-fs plumbing is
  still present, now unreachable from `--mount`. Deleting it is the next commit,
  kept separate so this one is a behaviour change and that one is a deletion.
- **`virtiofsd --sandbox none` is untouched.** It is on the QEMU path, which does
  not run on the macOS dev host, and landing a blind change to a sandbox flag is
  how it got there.
- **Stage B (virtiofs-root) and Stage C (builder VM) are not started.** Stage C
  is still blocked on the `out` share: the guest writes artifacts the host reads
  back, and replacing it needs either a host-side ext4 reader (`mvm-fs` has only
  a writer) or vsock streaming.
- **No `xtask check-no-virtio-fs` gate yet** — Stage D. Until it exists, nothing
  stops virtio-fs coming back.
- **Materialization cost is unmeasured on a large tree.** The test mount was
  tiny. A `--mount $PWD` on this repo will pay real time, and no cache exists
  yet: the `mount_fingerprint` / `mount_cache_lookup` / `mount_materialize`
  spans are still unproduced. Measure before deciding a cache is needed.
