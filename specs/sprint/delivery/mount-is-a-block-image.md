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

`plan_admission` now maps `materialized_image: Some(_)` →
`ShareKind::DirShare`, and the chain records the host path under claim 1. Had
`--mount` simply become an undifferentiated disk, the chain would record an
ext4 image under `~/.mvm` and lose the fact that a host *directory* was granted.

So `VmVolume.host` stays the granted directory and a new
`VmVolume.materialized_image` carries what is actually attached. The grant and
its transport are different facts and only the first belongs in an admission
record.

## One predicate, three callers

The block list, the slot arithmetic and the guest device mapping all have to
agree on which volumes are attached and in what order. All runtime volumes are
now block images; the shared mapping derives each guest node from that one
ordered list. Drift between them would mean a guest mounts a real device
holding someone else's data and nothing errors.

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

The snapshot semantics are documented in the CLI help and persistent-workspace
guide.

## Removed

`refuse_unsupported_dir_shares` and both its call sites. It existed to refuse
`--mount` on backends without virtio-fs; every backend can serve a mount now,
so the refusal could only produce a false one.

## Deleted after the behaviour change

Once every mount materializes, a pile of machinery had nothing left to decide:

- `VmmDriver::supports_directory_shares` — every driver answered the same.
- HVF's override and its advertised `directory_shares` capability.
- `VmCapabilities::directory_shares`.
- `ensure_dir_share_support`, whose two arms collapsed into the refusal.
- `workload_shares`' volume arm: the only virtio-fs share a workload spec can
  carry now is the dev-tier root.

85 lines out, 10 in.

Two tests asserted the deleted behaviour. They were **inverted rather than
removed** — `a_user_volume_never_becomes_a_virtiofs_share` and
`no_directory_volume_produces_a_share_whatever_its_mode` — because "this maps
to virtio-fs" becoming "this never maps to virtio-fs" is the regression guard
worth having, and deleting them would have left the new property untested.

## Measured

macOS/HVF, 30MB tree:

| | admit | `mount_materialize` | dispatch window | total |
|---|---|---|---|---|
| no mount | 25–56 ms | — | 73–90 ms | 271–322 ms |
| mount 30 MB | 133–149 ms | 105–127 ms | 70–77 ms | 370–384 ms |

No-mount launches are unchanged, and the dispatch window — the number
`PREPARED_COLD_HARD_MAX_MS` budgets — is unchanged, so the 200ms ceiling is
untouched. `admit_plan` is identical either way: admission itself did not get
slower.

A mounted launch originally paid the materialization **every launch**. The
2026-09-03 follow-up relocated immutable images into a shared,
content-addressed cache and now records the existing fingerprint, cache-lookup,
and miss-only materialization spans.

The cache does not impose a source-size ceiling or retain the tree in memory.
It streams each regular file to capture its digest, then streams it into the
staged image and verifies the emitted bytes against that digest. A short, long,
unreadable, or changed file refuses publication. The cache root is private and
must itself live on encrypted backing storage before any snapshot bytes are
written.

## Not done

- **Subsequently completed:** `VmVolumeKind::DirShare` was retired after claim
  1's derivation moved to `materialized_image`. `ShareKind::DirShare` remains in
  the signed plan and still records the directory grant.
- **`virtiofsd --sandbox none` is untouched.** It is on the QEMU path, which does
  not run on the macOS dev host, and landing a blind change to a sandbox flag is
  how it got there.
- **Stage B (virtiofs-root) and Stage C (builder VM) are not started.** Stage C
  is still blocked on the `out` share: the guest writes artifacts the host reads
  back, and replacing it needs either a host-side ext4 reader (`mvm-fs` has only
  a writer) or vsock streaming.
- **No `xtask check-no-virtio-fs` gate yet** — Stage D. Until it exists, nothing
  stops virtio-fs coming back.
- **Materialization cost remains unmeasured on a large tree.** The original
  test mount was tiny. Cache hits now avoid rebuilding the ext4 image, but a
  content-correct hit still pays the source tree walk and hash.

## 2026-09-03 follow-up

Persistent `machine volume mount --host` and transient `--mount` now share one
verified content-addressed image cache. The cache key covers source bytes and
guest-visible metadata, the ext4 materializer format version, and the volume
label. A cache miss hashes the exact collected node set and verifies each file
again while streaming it into the staged image, closing the mutable-tree race
between identity and image creation without buffering the tree. Read-only
mounts attach the immutable cache image; writable persistent mounts receive a
private reflink/copy. Registered host sources are fingerprinted again before
each start, changed sources refresh, and missing sources refuse instead of
serving the last snapshot. Source and cache destinations must both have
encrypted backing.
