# Remove virtio-fs

Backing: shipped-source
Validation: check-sprint-append

**Status: IN PROGRESS — Stages A and B landed. Stage C (builder VM) is
unstarted and gated on the `out` decision; Stage D (the gate) follows it.**

No guest gets a virtio-fs device. Not a workload, not the builder VM, not the
dev-tier root. The host filesystem reaches a guest as a block image or it does
not reach it at all.

## Why, beyond the flag that started this

The immediate finding was `crates/mvm-vmm/src/host/virtiofsd.rs:253`:

```rust
.args(["--sandbox", "none"])
```

— virtiofsd's own namespace/seccomp confinement, disabled, with no comment, no
ADR, and no mention in the commit that introduced it (`e54fd9769e`). The C
flavour passes no `-o sandbox=` at all.

But the flag is a symptom. virtio-fs puts a FUSE server on the host — in a
daemon for QEMU, in the VMM's address space for libkrun and HVF — and points it
at a host directory. Every request it parses comes from the guest. That is a
large, guest-driven parser sitting on the wrong side of the boundary, and it is
the one mechanism by which a guest addresses host filesystem *structure* rather
than opaque blocks. A block device is a byte array with no protocol for a guest
to attack.

This also removes the awkwardness in claim 1. "No host-fs access from a guest
beyond explicit shares" currently rests on virtio-fs behaving; afterwards the
shares are images, and the claim rests on the guest having no channel to the
host filesystem at all.

## What already points this way

- **Firecracker refuses virtio-fs outright** and has a test for it
  (`fc.rs::boot_rejects_virtio_fs_shares`). The Linux production workload path
  is already clean. This plan makes every backend match the one that is right.
- **The builder already migrated its largest share to a disk.**
  `pack_stage0_work_disk` copies the workspace tree, materializes an ext4 image
  with a volume label, and attaches it as virtio-blk — because "`nix build`
  reading a large workspace tree through virtio-fs-over-FUSE exhausts libkrun's
  virtio-fs handle pool". Different motive, same destination, and the machinery
  is written.
- **`--mount` is already read-only.** `exec.rs` refuses rw:
  "`--mount '{spec}'` requests rw, but transient live shares are read-only". So
  the only property a materialized image loses is *host edits becoming visible
  mid-run*, which a read-only mount consumed at boot barely has.
- **The timing surface already has slots for the replacement.**
  `mount_fingerprint`, `mount_cache_lookup` and `mount_materialize` are declared
  in `SubPhase`, rendered by the report, and have **no producer**. The comment
  says they exist because "a content-addressed mount image is what records
  them". Someone designed this and did not build it.

## Stages

Ordered by security value per unit of work. Each stage leaves the tree shippable.

### Stage A — workloads

The whole security argument lives here: an untrusted guest driving a FUSE
server. Everything below this is our own code.

**This stage is a deletion, not a feature.** Both halves of the fork already
exist and both are wired end to end:

```rust
pub enum LocalVolumeKind {
    /// Legacy host directory exposed only by backends with directory sharing.
    #[default]
    Directory,
    /// Portable ext4 image attached as a virtio block device.
    BlockImage { size_mib: u32 },
}
```

`as_vm_volume` maps those to `VmVolumeKind::DirShare` and `VmVolumeKind::Disk`.
The code already calls one legacy and the other portable. The work is removing
the legacy arm, not building the portable one.

- [x] `--mount <host>:<guest>` is materialized into an ext4 image by
      `mvm_build::rootfs::materialize_ext4_pure` and attached as virtio-blk.
      The volume stays `DirShare` so admission still records a *directory*
      grant; the new `VmVolume.materialized_image` carries what is attached.
      Landed as `feat(mount): deliver a granted directory as a block image`.
- [ ] The guest mounts by volume label rather than by the device node
      `workload_volume_devices` resolves. The image **is** labelled, but the
      guest is still handed a node, so this is not done — it is the difference
      between "works" and "cannot silently mount the wrong device".
- [x] `refuse_unsupported_dir_shares` and both its call sites deleted: every
      backend can serve a mount now, so it could only produce a false refusal.
- [x] Deleted: the `supports_directory_shares` trait method (every driver
      answered the same thing once mounts materialize), HVF's override and its
      advertised `directory_shares` capability, the `directory_shares` field on
      `VmCapabilities`, the two-arm `ensure_dir_share_support`, and
      `workload_shares`' volume arm. 85 lines out, 10 in.
- [ ] `VmVolumeKind::DirShare` and `LocalVolumeKind::Directory` stay for now:
      `DirShare` is what records a *directory* grant in the plan, which claim 1
      matches against, so removing it means moving that fact somewhere else
      first. `VirtioFsShare` also stays — its only remaining producers are the
      dev-tier root (Stage B) and the builder VM (Stage C).

**Custom volumes are unaffected.** A managed volume is already a
`BlockImage`/`Disk` today. Nothing about `mvmctl volume` changes.

**Deliberately not in this stage:** content-addressing and caching of the
materialized image. The `mount_fingerprint` / `mount_cache_lookup` /
`mount_materialize` spans exist for it and have never fired, so the slot is
there — but adding a cache is the "heavy new feature" this work is supposed to
avoid. Land the deletion, measure a cold `--mount`, and only then decide
whether a cache is worth its own plan.

**Semantic change to document, not hide:** a mount becomes a snapshot taken at
boot. Host edits during the run are not visible. Say so in `--mount --help` and
the README. The gap is small because `--mount` is already read-only — `exec.rs`
refuses rw with "transient live shares are read-only" — so the only lost
property is mid-run visibility.

### Stage B — the dev-tier root

**Evidence it costs nothing in practice:** across this host's entire recorded
history — 1,278 launches — the audited `root_strategy` is `block-ext4` **1,278
times and virtiofs-root zero times.** The dev-tier root was reachable in
principle and taken never.

- [x] Virtiofs-root is unreachable. `resolve_virtiofs_root` — the single
      authority, gating on backend capability x prod x sealed — is deleted, and
      the strategy is `BlockExt4` unconditionally. The security-posture ADR
      already called this a weaker contract that does not witness claim 3; it
      was the one boot mode that could not be dm-verity sealed.
- [x] `ImageSource::Prebuilt`'s virtiofs candidate became
      `unpacked_oci_root: Option<String>`. The field was doing double duty:
      besides feeding the gate, it was the only thing distinguishing an
      OCI-derived prebuilt from the cached dev image, and the two take
      different initrds. Deleting it outright would have quietly given every
      prebuilt the OCI initrd, and no test would have caught that —
      `only_an_oci_derived_prebuilt_resolves_the_oci_initrd` covers it now.
- [x] Deleted the machinery below the gate, in five units so a mistake is one
      `git revert`: the driver bootargs arm and `VIRTIOFS_ROOT_TAG`; the
      `VmStartConfig` field and `workload_shares`; the `VmCapabilities` flag
      with `select_root_strategy` and `RootStrategy::VirtiofsRoot`; and the HVF
      device model's root channel — its MMIO slot, the `mvmroot` tag the driver
      lifted out of the share list, the restore path's inheritance of it, and
      `MVM_HVF_VIRTIOFS_ROOT`, an env hook in `mvm-hvf-supervisor` that booted
      a virtio-fs root without going through the run-path gate at all.
- [x] `RuntimeSourceRootStrategy::VirtiofsRoot` **stays**, deliberately. It is
      not a boot mode — it is a value recorded on a warm-pool parent's on-disk
      spec. A parent warmed before this change still declares what it was
      warmed under, and the compat check has to be able to read that and refuse
      it. Deleting the variant would turn a clean refusal into a deserialization
      failure. Nothing produces it.

### Stage C — the builder VM

Largest, least security value: the builder runs our own Nix builds, and my
memory note already separates dev-builder from prod tiers. It is in scope
because the goal is *nowhere*, not *nowhere that matters*.

Remaining shares are `work`, `out`, `job`, `mvm-bins` and the closure seed.

- [ ] `work`, `job`, `mvm-bins`, closure seed — inbound and read-only. Same
      treatment as Stage A; `work` is already done on Stage 0.
- [ ] `out` is the hard one and needs a decision: the guest **writes** artifacts
      the host must read back. Options: a writable virtio-blk image the host
      mounts read-only after poweroff (needs a host-side ext4 *reader*, which
      `mvm-fs` does not have — it has a writer); or stream artifacts out over
      the existing vsock channel. Neither is free. Do not start Stage C until
      this is chosen.
- [ ] Delete `crates/mvm-vmm/src/host/virtiofsd.rs`, both QEMU call sites, and
      the `virtiofsd` host dependency from the Linux install docs.

### Stage D — the gate

- [ ] `xtask check-no-virtio-fs`, modelled on `check-single-network-path`:
      fails on `virtio_fs` / `VirtioFs` / `virtiofsd` / `add_virtio_fs`
      anywhere in the workspace outside the libkrun FFI bindings, which declare
      the C API whether or not we call it.
- [ ] Add it to the CI gate list. A removal without a gate grows back.

## What this costs

- **Every `--mount` pays a materialization**, proportional to the tree, until
  something caches it. The `$PWD:/work` in this project's own README is a large
  tree. This cost is **unmeasured** — measure a cold `--mount` before deciding
  whether a cache is needed, rather than building one on the assumption.
- **It does not touch the launch budget.** `PREPARED_COLD_HARD_MAX_MS` is 200ms
  on the *dispatch window* (`backend_start + vsock_wait`), and the mount spans
  are parented to `drives`, which is outside it. A launch with no `--mount` is
  unchanged, and a custom volume is already a block image.
- **Stage C is weeks**, most of it in `out`, for a guest that runs our code.
- **The QEMU workload driver may simply lose directory shares** rather than gain
  images — it is opt-in dev/test and `auto_select` never picks it, so it is the
  one place where deleting the feature outright is defensible.

## Stopgap

Restoring virtiofsd's sandbox is a one-line change and Stages A–C are not
one-line changes.

- [ ] `--sandbox namespace` for the Rust flavour, explicit `-o sandbox=namespace`
      for the C one. DAX needs `cache=always`, which is orthogonal to the
      sandbox, so the reason it was disabled is probably not the reason it looks
      like.
- [ ] **Needs Linux validation before it lands.** The QEMU path does not run on
      the macOS dev host, so this cannot be tested where it was written. Do not
      land it blind on the strength of the argument above.
