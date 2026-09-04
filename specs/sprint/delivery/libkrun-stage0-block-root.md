# libkrun Stage 0 boots a block root

The last guest-visible virtio-fs path is gone. libkrun Stage 0 still accepts a
`BuilderVmImage::RootDir` as its verified source representation, but
`run_stage0_impl` materializes that tree with the pure ext4 writer and boots
the resulting `root.ext4` as vda. The libkrun context carries
`root_dir: null`, never reaches `krun_set_root`, and declares no virtio-fs
mounts.

Stage 0 now uses the same raw-tar block transport as the one-shot and
persistent builders: store on vdb, input on vdc, output on vdd, and the
identity disk after them. The minimal seed has no usable `tar` applet, so
`stage0-init` extracts and emits the archive through
`builder_disk_transport`'s Rust implementation. Output emission preserves the
attached disk's capacity and is round-trip tested.

The tight seed root now includes its PID-1 mount points and a runtime-space
reserve, mounts procfs before reading the kernel command line, places Nix's
disposable fetcher cache on `/run` tmpfs, and reuses the guest mount helper for
the `/dev/fd` family that Nix's `patch-shebangs` requires. Each invariant came
from a forced cold Stage 0 boot and is represented by focused tests or the
Linux-gated compilation witness described below.

The same change closes the adjacent libkrun seams:

- persistent sessions pack fixed-capacity input/output disks and expose those
  paths to every dispatch;
- install dispatches write to `/out` under disk transport and return their
  sidecars instead of being refused;
- materialized directory grants attach only their block image, while an
  unmaterialized directory or any low-level libkrun share is refused before
  launch;
- the stale conformance witness for libkrun share mapping now points at that
  refusal test.

## Live witness

On macOS 26.5.2 arm64, `mvmctl` was rebuilt with
`--features embed-host-bins` and its exact path was pinned with
`MVM_BUILDER_VM_BOOTSTRAP_BIN`; the process environment carried a full `PATH`
including `/usr/sbin`.

A forced source Stage 0 bootstrap completed. Its supervisor config at
`.mvm-test/cache/builder-vm/vms/mvm-stage0-1788469239974-62380/` records
`root_dir: null`, `rootfs_path: .../root.ext4`, store/input/output/identity
block disks, and `virtio_fs_mounts: []`.

The public command then exited 0:

    mvmctl machine build --builder libkrun --no-persistent-builder --force examples/sleeper

Its config at
`.mvm-test/cache/builder-vm/vms/mvm-builder-vm-1788469548334-38310/` records
the cached ext4 root, store/input/output/runtime/identity disks, and the same
empty mount list. It produced
`.mvm-test/dev/builds/1788469548334-38310/rootfs.ext4`.

## Ratchet and verification

`check-no-virtio-fs` now requires exactly **19 sites across 6 files**. The
survivors are the 16 libkrun C-API declaration sites, the low-level
`VirtioFsShare` type, and the QEMU/Firecracker tests that prove shares are
refused. Removing a survivor without lowering the pin or adding any attach
site both fail the gate.

Validation completed on the host:

- 13,001 workspace tests passed under nextest (22 skipped);
- workspace all-targets Clippy passed with warnings denied;
- `cargo check --workspace`, `just check-gated`, formatting, focused libkrun,
  persistent-builder, and disk-transport suites passed;
- the conformance meta-gates and generated `CONFORMANCE.md` are current.

An additional native-Linux run was attempted inside the same libkrun builder
VM. The first cold-Cargo run reached its 7,200-second job deadline; a retry
with compiler output routed to the VM console identified the wait as Cargo's
`Updating crates.io index`, with no compilation error. The retry was stopped
and the supervisor reaped. Accordingly, Linux/BDD targets are compile-witnessed
by `just check-gated`, but this delivery does not claim a native-Linux Clippy
or Stage 0 test execution; those remain CI evidence. This limitation is in the
ad-hoc validation harness, not the successful forced Stage 0 or public builder
flows above, both of which ran entirely through the live libkrun path.
