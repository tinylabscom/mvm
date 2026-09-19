# 3360 — virtio-blk discard, and the trim that uses it

The builder's Nix store disk is a sparse image that only ever grew. The guest
filesystem freed blocks and nothing told the host, so the host file stayed at
its high-water mark for the life of the checkout — a contributor home measured
53 GB of store against a 12 GB clean closure.

Three things had to be true to reclaim it: the store has to be collected, the
guest has to say which blocks it stopped using, and the device has to hand them
back. This is the second and third. The Stage 0 collection and its trim are
`fix/3360-stage0-store-reclaim`.

## The device

`VIRTIO_BLK_F_DISCARD` is offered on every writable backing, alongside
`VIRTIO_BLK_F_FLUSH`. A read-only backing offers neither: it takes no writes,
so it has nothing to release, and a guest that asks anyway is refused at the
device rather than trusted not to ask.

The three discard limits are served from block config space at the offsets
`struct virtio_blk_config` gives them — `max_discard_sectors` at +0x24,
`max_discard_seg` at +0x28, `discard_sector_alignment` at +0x2c, checked against
`virtio-bindings`' generated offset assertions. The alignment is 8 sectors, so
the guest names 4 KiB-aligned ranges, which is what a host filesystem can
release whole.

`crates/mvm-vmm/src/vmm/blk_discard.rs` owns the parse and the release.

## What the parse refuses

Everything in a discard payload is guest-controlled, and this device model is
shared with the workload tier, so the range list is validated whole before any
byte is released:

- A payload that is empty, not a whole number of 16-byte segments, or longer
  than the advertised `max_discard_seg` allows.
- A segment with any flag set. The only defined flag, unmap, belongs to
  write-zeroes, which this device does not implement — reported as
  `VIRTIO_BLK_S_UNSUPP`, which is what the spec asks for, not as an I/O error.
- A range longer than `max_discard_sectors`.
- A range whose start plus length overflows, or ends past the disk's capacity.
  Refused, never clamped: trimming it to fit would release bytes the guest never
  named.
- A zero-sector range. No driver emits one, and it is the case where nothing
  constrains the start sector, so accepting it would admit a start past the end
  of the disk.

One bad range refuses the whole request; nothing is released unless every range
is valid. `parse_discard_ranges` is registered in `xtask/dormant-controls.toml`
— it is the only bound on a guest-named range, and its unit tests pass whether
or not the device calls it.

## The release

macOS punches with `fcntl(F_PUNCHHOLE)`, which requires a range aligned to the
filesystem's block size (read from `fstatfs`), so only the whole blocks inside
the range are released and the partial blocks at either edge keep their bytes —
which discard permits. Linux uses
`fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`, which zeroes partial
blocks itself. Neither changes the file's length.

A host filesystem with no hole support reports success rather than an error: a
guest told its trim failed can do nothing but log it. Every other failure
surfaces as `VIRTIO_BLK_S_IOERR`.

## The trim

`render_flake_cmd_sh` now runs `fstrim /nix-store` immediately after the
cap-triggered `nix-collect-garbage`, inside the same branch — the trim is what
turns collected store paths into host blocks, and running it when nothing was
collected would walk the store for nothing. `/nix-store` is the ext4 store disk;
`/nix` is an overlay over it and has no FITRIM of its own. Best-effort: a device
that does not offer discard reports the operation unsupported and the build
carries on.

## Where this takes effect, and where it does not

The in-house VMM device model is what HVF boots, so the macOS builder and the
macOS workload tier get this today.

It does **not** reach Linux yet, and the issue should not claim it does.
Firecracker serves the Linux builder and Stage 0 disks with its own
virtio-block, which gained opt-in discard only in **1.17.0** (writable drives,
Sync IO engine); `FC_VERSION_DEFAULT` pins **v1.14.1**. Until that pin moves and
the drive opts in, `fstrim` on a Firecracker-backed store returns
`EOPNOTSUPP`, whatever this device model does. That is a version bump plus a
drive-config change, and it is worth its own issue rather than being folded in
here. libkrun's block device was not surveyed.

Firecracker and libkrun block devices are otherwise out of scope: they are not
this device model.

## Tests

`crates/mvm-vmm/src/vmm/blk_discard.rs` covers the parse — every refusal above,
the accepted boundary case (a range ending exactly at capacity), segment order,
and the hole punch itself (blocks released, length unchanged, bytes outside the
range untouched, with an escape for a filesystem that has no holes).

`crates/mvm-vmm/src/vmm/virtio.rs` drives real requests through the virtqueue:
the released range and its untouched neighbours, a range past the end releasing
nothing, a batch where one bad range releases none of them, the unmap flag
reporting unsupported, a malformed payload, a read-only backing refusing and
keeping every byte, and a file-backed discard that does not resize the image.
The feature-word tests now assert `FLUSH | DISCARD` on a writable backing and no
discard bit on a read-only one; the config-space test pins the three limits.

`render_flake_cmd_sh_embeds_gc_tail_with_default_cap` pins the trim after the GC
and inside the cap branch.
