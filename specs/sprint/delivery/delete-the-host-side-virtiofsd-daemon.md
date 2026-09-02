# Delete the host-side virtiofsd daemon

Plan: `specs/plans/2026-08-31-remove-virtio-fs.md`, Stage C.

## What this closes

`crates/mvm-vmm/src/host/virtiofsd.rs` — 382 lines that spawned and supervised a
`virtiofsd` process per share — is gone, along with its only consumer: the QEMU
workload driver's share arm.

**This is the line the plan opened on.** The finding that started the whole
removal was `virtiofsd.rs:253`, `.args(["--sandbox", "none"])` — virtiofsd's own
namespace/seccomp confinement disabled with no comment, no ADR, and no mention
in the commit that introduced it. That flag no longer exists anywhere in the
tree, because the process it configured no longer exists.

## Why it was safe now and not before

The deletion was gated on "both builders on the disk transport". Both landed:
the QEMU builder first, then the persistent HVF builder. That left the QEMU
*workload* driver as virtiofsd's last consumer.

Unreachability was **proven, not assumed**. Every `VmmSpec.shares` assignment in
the tree — across `spec_map`, both builder specs, all five drivers, the mock and
every test fixture — is empty. No construction anywhere produces a share, so the
`if !spec.shares.is_empty()` arm could never run.

## What went

- The `virtiofsd` spawn loop, the `memory-backend-memfd` + `-numa` object, the
  `vhost-user-fs-pci` device loop, `qemu_virtiofs_socket_path`, and the
  `VirtiofsdGuard` field on the running-VM handle plus its teardown.
- `mvm-vmm`'s `which` dependency, which existed only to locate the virtiofsd
  binary.
- `mvm_build`'s `pub use mvm_vmm::host::virtiofsd` re-export.

`mem_arg` went too: it sized the memfd backend and nothing else. Worth noting
because `-m` is pushed separately and a test pins it, so QEMU still gets its
memory — the orphaned local was the *only* casualty.

## The test was replaced, not dropped

`argv_maps_virtio_fs_shares` asserted the mapping that no longer exists.
Deleting it outright would have left nothing pinning the absence, so it became
`argv_emits_no_virtio_fs_arguments_even_for_a_spec_that_carries_shares`: it
builds a spec **with** a share and asserts the argv still carries no virtiofs
wiring. That pins the arm as *deleted* rather than merely unreached, so
re-introducing the mapping fails the suite instead of silently restoring a
guest-driven FUSE server on the host.

## The gate

`check-no-virtio-fs` drops from 46 sites across 14 files to **41 across 13**,
with the `virtiofsd.rs` row deleted outright.

It has **not** reached FFI-only rows, which the plan names as the end state.
Still pinned: the libkrun builder's Stage 0 `RootDir` path (which boots a
virtio-fs root and predates the disk transport), the libkrun C FFI, and the
now-dead HVF device model — `HvfVirtioFsShare`, the `hvf.rs` mapper,
`virtio.rs`'s VirtioFs MMIO device and `kernel_boot.rs`'s attach. Those map and
attach nothing today and are the next deletion.

## Verification

`RUSTFLAGS="-D warnings" just check-gated` (the CI flags, not the recipe's
default — a warning is an error there), `cargo nextest run --workspace` (12,949
passed), `cargo run -p xtask -- check-all` (66/66), `cargo fmt --all --check`.

No live run was needed: this is a deletion of an unreachable path, and the
absence is pinned by a test and the ratchet rather than by a boot.
