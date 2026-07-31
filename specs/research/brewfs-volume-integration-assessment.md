# BrewFS volume integration assessment

**Date:** 2026-07-31

**Decision:** do not use BrewFS as the backing engine for mvm's existing
single-attach block volumes. Keep it as a candidate for an experimental,
object-backed shared POSIX filesystem when a real RWX requirement appears.

## Executive assessment

BrewFS is a distributed filesystem, not a virtual block-volume manager. It
provides a POSIX-like FUSE mount whose metadata lives in Redis, TiKV, etcd,
PostgreSQL, or SQLite and whose data lives in local storage or an S3-compatible
object store. That makes it a plausible answer to "several microVMs need the
same writable filesystem," but not a drop-in replacement for mvm's ext4
disk-image, virtio-blk, encryption, snapshot, and clone lifecycle.

| Requirement | BrewFS fit | Assessment |
| --- | --- | --- |
| Per-VM persistent ext4/virtio-blk volume | Poor | BrewFS exports a FUSE filesystem, not a block device. |
| Encrypted volume with mvm key wrapping | Poor | Backend transport/storage security would not replace mvm's per-volume encryption contract. |
| Atomic volume snapshots and clones | Poor | BrewFS does not map to mvm's block snapshot and warm-restore lifecycle. |
| Shared RWX/POSIX data across microVMs | Promising | This is BrewFS's natural use case, subject to consistency and credential constraints. |
| Object-backed datasets and model artifacts | Promising | Chunking, local caches, and S3-compatible storage match this workload shape. |

## Architectural mismatch with mvm

mvm currently has two related storage abstractions:

- `VolumeBackend` is a scoped file/object data-plane contract with
  `put/get/list/delete/stat/rename`. A backend is directly guest-mountable only
  when it exposes a real local path for virtio-fs
  (`crates/mvm-runtime/src/storage/volume/backend.rs:11-55`).
- `MountProvider` resolves a declared source into an attachable host path or
  guest tmpfs. Its comments reserve future `BlockDev` and `Fuse` variants, and
  external providers already route by a string discriminator
  (`crates/mvm-runtime/src/storage/volume/mount_provider.rs:1-27`).

BrewFS belongs, if anywhere, behind `MountProvider` as an external filesystem
provider. Treating it as `VolumeBackend` would either duplicate BrewFS's own VFS
semantics or reduce it to an already-mounted local directory.

The production workload runner is currently block-oriented. It maps `Disk`
volumes to persistent virtio-blk devices and refuses `DirShare` volumes because
`VmmSpec` has no generic virtio-fs share representation
(`crates/mvm-runtime/src/workload_runner/spec_map.rs:16-85,111-133`). The older
`mvmctl volume mount` path likewise records the intended mount but states that
host virtiofsd and Firecracker attachment remain follow-up work
(`crates/mvm-cli/src/commands/vm/volume.rs:727-778`).

This is also an upstream Firecracker boundary. Firecracker's documented device
model includes virtio block, network, balloon, vsock, and related minimal
devices, but not virtio-fs. A host-side BrewFS mount therefore cannot be
exported directly into a Firecracker guest without adding a different transport
or changing VMM.

## Integration options

### 1. Host BrewFS mount exported over virtio-fs

This is the cleanest security shape. BrewFS, metadata credentials, S3
credentials, and cache state remain host-side; the guest receives only the
mounted directory. It could become viable for libkrun/HVF after mvm adds a
generic `VmmSpec` directory-share device.

It is not a Firecracker solution because upstream Firecracker has no virtio-fs
device. It would also introduce two userspace filesystem layers, BrewFS FUSE
followed by virtio-fs, which must be measured for latency and cache behavior.

### 2. Guest-native BrewFS mount

This is the only direct BrewFS design compatible with Firecracker. The workload
kernel already enables `FUSE_FS` because virtio-fs depends on it
(`nix/images/kernel/workload.nix:10-31`). A trusted guest service could access
`/dev/fuse`, mount BrewFS at an admitted path, and then expose the mount to the
unprivileged workload.

The security cost is substantial:

- BrewFS requires mount privilege, `/dev/fuse`, and network access to both its
  metadata and object-storage backends.
- S3 and metadata authentication normally require credentials in the BrewFS
  process. mvm's standing invariant is that secret values stay out of the guest
  (`specs/adrs/031-serialization-crypto-storage-selection.md:24-29`).
- The BrewFS process would become trusted guest infrastructure and need its own
  capability drop, seccomp profile, lifecycle supervision, audit events, and
  resource limits.
- BrewFS's documented default cache budgets are far larger than a tiny microVM:
  4 GiB read memory, 384 MiB write memory, a 1.25 GiB VFS memory budget, and
  20 GiB each of read and write SSD cache. Every value would need an explicit
  microVM profile.

A production version would require host-side, per-volume credential proxies.
The guest could use non-secret placeholder identities while a plan-bound host
service authenticates S3 requests and metadata connections, restricts them to
one tenant bucket/prefix and namespace, and keeps the real credentials out of
the VM. This is a new storage data plane, not a small package integration.

### 3. Ext4 image stored as a file on BrewFS

Firecracker could theoretically use a file inside a host BrewFS mount as a
virtio-blk backing file. Do not adopt this design. It creates
ext4-over-BrewFS-over-object-storage, turns a distributed namespace into one
large random-write object graph, prevents safe multi-attach, and makes guest
flush, host FUSE fsync, BrewFS commit, and object durability one long and
poorly-proven chain. It also loses the shared-filesystem benefit that would
justify BrewFS.

## Correctness, operations, and maturity

The latest reviewed release is v0.1.2 from 2026-07-18. BrewFS has meaningful
correctness work: its repository includes Rust tests, pjdfstest, xfstests, LTP,
stress-ng, fuzzing, and fio profiles. Its published test matrix nevertheless
documents exclusions and unresolved buffered-write/page-cache, locking,
O_DIRECT, and sparse-file cases.

The project's own gap analysis says that it is beyond a demo but still trails
JuiceFS in cross-client consistency, complete POSIX lifecycle behavior,
production operations, encryption/format governance, long-running validation,
and fault injection. Its architecture describes current multi-client
close-to-open consistency as best effort.

Durability mode also matters:

- `upload_before_commit` uploads data before publishing metadata and is the
  only acceptable initial mode for mvm.
- `commit_before_upload` publishes metadata first. BrewFS documents that cache
  loss or process failure can then lose published-but-not-uploaded objects or
  make other clients temporarily observe missing data. It must remain disabled
  for an mvm integration.

BrewFS does not eliminate mvm's existing responsibilities for tenant scoping,
signed admission, credential non-disclosure, encryption at rest, snapshot
lineage, audit events, quotas, cleanup, and crash recovery.

## Recommended proof of concept

Only start this work when there is a concrete shared-RWX requirement that
native virtio-blk volumes cannot satisfy. Keep the first implementation in a
development/test tier that production admission refuses.

1. Model BrewFS as `MountSource::External { provider: "brewfs", ... }`, not as
   a new `VolumeBackend` or `VmVolumeKind`.
2. Pin and Nix-build an exact BrewFS source revision for Linux x86_64 and
   aarch64. Publish it through mvm's normal signed artifact path; do not execute
   BrewFS's curl-to-shell installer.
3. For Firecracker, use a guest-native mount with anonymous, local-only test
   Redis/S3 services. Do not put production credentials in the guest.
4. Configure `upload_before_commit`, full cache checksum verification, zero or
   short metadata TTL during correctness testing, and a small independent
   cache root for every client.
5. Exercise single-client and concurrent-client reads, writes, rename, locks,
   fsync, process kill, VM kill, cache loss, metadata outage, object-store
   outage, remount, and warm snapshot restore.
6. Treat snapshots, clones, encrypted-at-rest tenant storage, quota enforcement,
   and credential brokering as unsupported until each has an explicit contract
   and negative-path tests.

If the actual requirement is ordinary single-attach persistent storage, finish
mvm's encrypted virtio-blk volume path instead. BrewFS adds a distributed
filesystem control plane without solving that problem.

## Primary sources

- BrewFS repository and overview: <https://github.com/brewfs/brewfs>
- BrewFS architecture: <https://github.com/brewfs/brewfs/blob/main/doc/architecture/arch.md>
- BrewFS configuration and durability modes: <https://github.com/brewfs/brewfs/blob/main/doc/operations/configuration.md>
- BrewFS deployment requirements: <https://github.com/brewfs/brewfs/blob/main/doc/operations/binary-deployment.md>
- BrewFS self-assessed gaps: <https://github.com/brewfs/brewfs/blob/main/doc/gap/README.md>
- BrewFS filesystem test matrix: <https://github.com/brewfs/brewfs/blob/main/doc/testing/fs-test-suite-matrix.md>
- BrewFS v0.1.2 release: <https://github.com/brewfs/brewfs/releases/tag/v0.1.2>
- Firecracker device model: <https://github.com/firecracker-microvm/firecracker/blob/main/FAQ.md>
