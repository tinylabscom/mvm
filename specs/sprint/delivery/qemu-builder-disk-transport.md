# QEMU builder on the disk transport

Stage C of `specs/plans/2026-08-31-remove-virtio-fs.md`, QEMU half. Both
one-shot QEMU builder sites (`run_shell_script_qemu`, `run_build_qemu`) now move
their job in and their artifacts out over the raw-tar-on-a-disk transport the
libkrun and HVF one-shot builders already use, instead of four
vhost-user/virtiofsd shares.

## Why this one first

QEMU is the Linux auto-detect default builder, so this is not the "opt-in
dev/test backend we can delete the feature from" the plan originally filed it
as — deleting its shares without a replacement breaks every Linux build. It is
also the half that is separately validatable, on the Linux/KVM box, which the
persistent HVF builder is not.

## What moved

- `prepare_builder_transport_disks` / `extract_builder_transport_output` are
  `pub(crate)`, and the former takes a real `closure_nar: Option<&Path>` rather
  than a hardcoded `None`.
- `qemu_runtime_overlay_attachment` delegates to
  `builder_runtime_overlay_attachment` instead of the `virtiofs` flavour.
- Both sites pack `[job, work, mvm-bins]` plus the seeded closure NAR onto the
  input disk and extract the output disk after QEMU exits.
- Drives are attached vda rootfs / vdb nix-store / vdc input / vdd output /
  vde overlay, extra disks, identity last.
- Deleted: two `virtiofsd` spawn loops, two `memory-backend-memfd` + `-numa`
  objects, two `vhost-user-fs-pci` device loops,
  `qemu_shares_with_closure_seed`, `qemu_virtiofs_socket_path`.

No guest change and no builder-image rebuild: `mvm-host-vm-init`'s
disk-transport mode is what libkrun's one-shot builder already boots, so QEMU
inherits it. That is also the first thing to confirm on a live run.

## Four things worth keeping

**The closure seed maps across with a step removed.** `stage_closure_seed_dir`
copies one file into `<vm_state_dir>/closure-seed/<CLOSURE_FILE>` and returns
the wrapper directory; the wrapper exists only because virtio-fs shares
directories and not files. The source is already a file, and
`pack_input_disk`'s `closure_nar` archives it at the same fixed name. The plan's
stated reason for the open question — "libkrun passes `None` there, so the
helper has no closure path to copy" — was wrong: libkrun has a closure and left
it on virtio-fs. That makes the plan's `[x]` on "closure seed — done for the
one-shot builder" false, and it is now corrected to an open box.

**The overlay device and the transport tokens are one decision.**
`builder_runtime_overlay_cmdline` wraps `builder_disk_transport_cmdline`, so
swapping the delegate emits `mvm.runtime_data=/dev/vde` *and*
`mvm.builder_transport=disk` + the input/output device tokens together. Treating
them as two edits is how you end up with a guest mounting the input tar as its
runtime overlay.

**`work` needed filtered staging that the recipe did not mention.** QEMU shared
`job.work_dir` / `mounts.flake_src` directly, which on a source checkout is the
repo root. A share tolerates that; a tar does not — `stage_filtered_work_input`
exists because `target/` + `.git/` + `.worktrees/` overflow the guest's
RAM-capped extraction tmpfs.

**The ratchet gate could not see any of this.** `check-no-virtio-fs`'s pattern
matched the libkrun C symbol `krun_add_virtiofs` but not the safe wrapper
`add_virtio_fs` — underscore — missing 21 Rust call sites. And the QEMU builder
attached shares through neither, spawning `virtiofsd` and passing a
`vhost-user-fs-pci` device, so `qemu_builder.rs` was never in the pinned table
and this deletion lowered no count. The device name is a string literal, which
the checker blanks before matching, so the spawn side is now caught by
`VirtiofsdGuard` / `locate_virtiofsd`. The gate went from 23 sites across 11
files to 54 across 15.

## Also in this change

`--mount`'s user-facing text was wrong in four places since Stage A: `exec.rs`,
`README.md`, and two rows plus an example in the CLI reference all said it needs
a virtio-fs backend and serves a *live* share. Neither is true — the directory
is materialized into an ext4 image and attached as a block device, which every
backend serves, and the image is a snapshot taken at boot. The README went
further and told users Firecracker "refuses before boot", which stopped being
true when materialization landed.

`--volume` stays. It reads as a redundant alias of `--mount`, but the flag takes
two shapes through `parse_volume_spec` — `host:/guest[:ro]` for a directory and
`host:/guest:SIZE[:ro][:enc]` for a disk — and `--volume` is the natural
spelling for the second. Removing it would leave `--mount …:4G` as the only way
to say it.

## Validation

Gates green on macOS: `just check-gated`, the workspace suite, doctests,
`clippy --workspace --all-targets -D warnings`, `xtask check-all`.

The behaviour itself is not CI-testable — no hosted runner boots a guest — so it
was validated with a live `mvmctl machine build --builder qemu` on the
Linux/KVM box, from a cold `MVM_HOME` so Stage 0 built the builder image too.
It completed:

    [mvm] Step 2/2: Build complete
    [mvm]   Slot:     032e844447f7d53080ec7f9f8c32fe9184498db09ba2a61ddb0564cce891242a

A green build is not on its own proof that the new path ran, so four things were
checked directly rather than inferred:

- The guest booted with all four tokens — `mvm.builder_transport=disk`,
  `mvm.builder_input=/dev/vdc`, `mvm.builder_output=/dev/vdd` and
  `mvm.runtime_data=/dev/vde` — confirming the delegate swap emits the vde move
  and the transport tokens together.
- The guest enumerated the devices in the intended order: `vdc` 613 MB (the
  input tar), `vdd` 8.00 GiB (the output disk), `vde` 10.7 MiB mounted `ro`
  (the runtime overlay). Had the order been wrong, `vde` would have carried the
  input tar rather than an ext4 the guest could mount.
- `virtiofsd`, `vhost-user-fs` and `memory-backend-memfd` appear **zero** times
  in the run log.
- The input disk is 613 MB, not tens of GB, so `stage_filtered_work_input`
  pruned `target/`, `.git/` and `.worktrees/` as intended — the failure mode
  this migration was most exposed to.

Reproducing it needs two things that are easy to lose an hour to. The bootstrap
helper must be pinned with `MVM_BUILDER_VM_BOOTSTRAP_BIN` at a binary built
`--features embed-host-bins`, because the helper mvmctl builds for itself
carries no embedded host binaries and cannot bootstrap (issue #3067). And the
process needs `/usr/sbin` on `PATH`, or Stage 0 reports `mkfs.ext4` missing when
it is installed.
