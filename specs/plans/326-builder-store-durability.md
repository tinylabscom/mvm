# Plan 326: the builder nix store must survive any abrupt failure

## Status

IN PROGRESS — WS-A and WS-B complete; WS-D next, then WS-C.

## The problem

A builder VM that dies abruptly can leave `~/.mvm/cache/builder-vm/nix-store-<arch>.img`
ext4-corrupt. Observed 2026-08-11:

```
EXT4-fs (vdb): warning: mounting fs with errors, running e2fsck is recommended
EXT4-fs (vdb): recovery complete
EXT4-fs error (device vdb): ext4_lookup:1821: inode #3932165: comm chown:
    deleted inode referenced: 3981611
```

Journal replay ran and the filesystem was *still* inconsistent, so ordering
guarantees had already been violated. The surfaced error was
`mvm-host-vm-init: setup_nix_store failed: /bin/chown -R 902:902 /nix/var/nix
exited 1` — which names neither the disk nor corruption, and the only
documented recovery (`mvmctl cache repair`) clears all 147 GB when one 63 GB
image was bad.

## What the code actually does today

Three findings in `crates/mvm-vmm/src/vmm/virtio.rs`:

1. The device advertises only `VIRTIO_F_VERSION_1` and, when read-only,
   `VIRTIO_BLK_F_RO`. **`VIRTIO_BLK_F_FLUSH` is never offered.**
2. `VIRTIO_BLK_T_FLUSH` is not handled. The status line is
   `matches!(req_type, VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT)`, so a flush would
   be answered `VIRTIO_BLK_S_IOERR`.
3. **The backing file is never synced.** There is no `sync_all`, `sync_data`,
   or `F_FULLFSYNC` anywhere in `mvm-vmm` or the HVF backend. Writes are
   `pwrite` into the host page cache and stay there.

So no mechanism exists, at any layer, by which the guest or the host can make
the store durable.

## What that does and does not explain

It **does** explain host-crash corruption. On panic or power loss the page
cache is gone, an arbitrary subset of writes survives in arbitrary order, and
ext4 cannot recover. That is unconditional and is a real hole regardless of
anything below.

It does **not** explain `kill -9` of the supervisor. Those writes are already
in the host page cache, which the kernel owns and which outlives the process.
On that analysis a killed builder VM should not corrupt the store — yet one
did. **The mechanism behind the observed failure is not yet established.**
WS-D exists to settle that rather than assume it.

Do not describe WS-A as fixing the observed corruption until WS-D says so.

## Workstreams

### WS-A — make durability expressible

- [x] Advertise `VIRTIO_BLK_F_FLUSH` on writable disks.
- [x] Handle `VIRTIO_BLK_T_FLUSH`: fsync the backing file, report
      `VIRTIO_BLK_S_OK` on success and `VIRTIO_BLK_S_IOERR` on failure.
- [x] A read-only or RAM-backed disk answers flush `OK` without work.
- [x] Device-level tests: flush is accepted; a flush reaches the file; an
      unknown request type is still refused.

Closes the host-crash hole. With `F_FLUSH` negotiated, guest ext4 issues real
barriers and jbd2's commit ordering becomes enforceable instead of assumed.

### WS-B — fail fast, and recover narrowly

- [x] Guest init reads the ext4 superblock's `s_state` error bit on the store
      device before mounting and refuses with a message naming the disk, the
      cause, and the recovery — rather than letting a downstream `chown` fail
      with `exited 1`. Reading `s_state` beats parsing kernel output: the bit
      survives remount, so it is still set on the next boot.
- [x] `clear_builder_store_image` removes only the store image, keeping the
      Stage 0 seed and the builder images.
- [x] `mvmctl cache repair --store-only` exposes it; the blanket clear stays
      available but stops being the only option.

This is the piece that converts an hour of misdirected debugging into one
actionable line.

### WS-C — a build cannot damage the base store

- [ ] Each build attaches a CoW overlay over the base store image rather than
      mutating it in place.
- [ ] The overlay is committed to the base only on a clean, synced exit.
- [ ] An abrupt death discards the overlay; the base is untouched by
      construction, so no failure mode can corrupt it.

WS-A makes corruption unlikely; WS-C makes it structurally impossible for the
base image. This is the workstream that actually delivers "never".

### WS-D — establish the mechanism, then keep it fixed

- [ ] Reproduce: kill a builder VM mid-write and check whether the store
      mounts clean afterwards.
- [ ] If `kill -9` alone does not corrupt, find what did — a second writer, an
      I/O error path, or a host-level event — and record it here.
- [ ] Regression coverage for whatever WS-D establishes.

## Sequencing

WS-A is independent and lands first. WS-B is independent of WS-A and can land
in parallel. WS-C depends on neither but is the largest change and should
follow WS-D's findings, so the design answers the real failure mode rather
than the assumed one.
