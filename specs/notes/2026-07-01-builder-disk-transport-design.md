# Disk-only builder transport for the in-house VMM (Plan 214 S6.3)

Status: design + in progress. Path B (disk-only) was chosen over virtio-fs
parity — see the fork decision (virtio-fs is not needed for microVMs; sealed/RO
surfaces are virtio-blk images, virtio-fs only buys live mutable host-dir
bind-mounts the posture discourages).

## The constraint that shapes everything

The libkrun/vz builder moves job + artifacts over **virtio-fs shares**
(`/work`, `/out`, `/job`, `/mvm-bins` = host directories). The in-house VMM has
no virtio-fs, so those move over disks. But the **host is macOS** and cannot
format or read ext4 — so the transport must never require host-side
guest-filesystem access. That rules out "host mkfs.ext4 an input image" and
"host reads the guest's ext4 output."

## Transport: symmetric tar-over-raw-disk

Both sides already have `tar` (a workspace dep; `stage0.rs` uses
`tar::Builder`/`tar::Archive`; the guest rootfs ships it). Use it, no filesystem
on the transport disks:

- **Input disk (RO):** host `tar c {job, work, mvm-bins}` → raw bytes written to
  a pre-sized disk image. Guest reads `/dev/vdX` raw, `tar x` into a tmpfs at
  `/input`, binds `/job`,`/work`,`/mvm-bins`. tar's two-zero-block EOF stops
  extraction before the trailing zeros of the padded disk.
- **Output disk (RW):** guest `tar c {rootfs.ext4, result.json, vmlinux?}` → raw
  bytes to `/dev/vdY`. Host reads the raw disk file, `tar x` into the per-build
  artifact dir. Symmetric; host only runs `tar`, never touches ext4.
- **nix-store disk (RW, persistent):** stays a real ext4 the guest formats +
  mounts (already live-proven: guest formatted `/dev/vdb`, ext4 superblock
  persisted to the host file). Survives across builds.

Disk slots (within `MAX_DISKS = 4`): `vda` = builder rootfs (RO, file-served),
`vdb` = nix-store (RW persist), `vdc` = input tar (RO), `vdd` = output tar (RW).

## Pieces

1. **Host transport codec** (mvm-build): `pack_input_disk(job_dir, work_src,
   mvm_bins, out_image)` and `read_output_disk(disk_image, dest_dir)` — pure,
   round-trip-testable, no VM. (First slice.)
2. **Guest init** (`mvm-host-vm-init`): when the virtio-fs mounts are absent,
   fall back to the disk transport — extract the input disk, mount the nix-store
   disk, run the job, tar the artifacts to the output disk. Keep the virtio-fs
   path for the libkrun/vz builder (detect + fall back).
3. **BuilderRunner<D: VmmDriver>** (mvm-backend): sibling to `WorkloadRunner`.
   Stage the job (reuse `stage_job_dir`), pack the input disk, create the output
   + nix-store disks, compose a `VmmSpec` (disks + builder cmdline
   `init=/sbin/mvm-host-vm-init`), boot via the driver, wait, read the output
   disk, finalize (reuse `finalize_flake_job`). Wire into
   `builder_backend_select` so `--builder inhouse` (and eventually the macOS
   auto-default) uses it. Removes vz from the builder path.
4. **Builder egress on HVF:** the builder is trusted (no claim-10 gate); it needs
   a path out for substituters. Separate wiring slice.
