# The builder boots mvm's binaries from a payload, not from its image

Backing: shipped-source
Validation: the_builder_boot_contract_composes_onto_every_shipped_driver

Workstreams W1–W6 and W11 of
`specs/plans/2026-09-24-builder-image-without-host-bins.md`, plus the `mvm`
side of the `builder_boot_abi` image-set field.

## What changed

- **The payload.** `mvm_build::builder_boot::payload` assembles a newc
  initramfs: `mvm-host-vm-init` as `/init`, and `mvm-host-vm-init`,
  `mvm-builderd` and a `MANIFEST` (`<name> <sha256>`, sorted) under
  `/mvm/host-bins`. Entries are fixed-order with mtime and ownership zeroed,
  so the bytes are a function of the member bytes. The payload digest is the
  SHA-256 of `MANIFEST`, which the guest can recompute from unpacked files.
  `mvmctl` holds each member to the digest compiled into it as it reads it.
- **Stage 1.** `mvm-host-vm-init` run as PID 1 from a payload verifies it
  against `mvm.boot_payload=` on the kernel command line, copies it to
  `/run/mvm/host-bins`, mounts the image read-only, refuses an image outside
  the payload's boot ABI range (or one with no `/run`), pivots, and
  re-executes itself from the tmpfs copy. Any refusal is one
  `mvm-host-vm-init: stage1 refused:` console line, then power-off.
- **One command line.** `builder_boot_cmdline` is the only producer of the
  builder kernel command line; HVF, Firecracker, libkrun and QEMU all go
  through it, and `stage_builder_boot` / `stage_image_boot` decide each boot.
  libkrun and QEMU now attach the builder root read-only at the VMM.
- **Every boot carries it.** `mvmctl` registers its embedded payload as the
  source at startup. Legacy images (ABI 0) boot with it too; their baked
  copies never run. A host without a source boots only an ABI-0 image and
  refuses a higher one by name.
- **Persistent builders** record the payload digest they booted with and are
  stopped, not reused, by an `mvmctl` with different builder binaries.
- **The HVF patcher is gone.** HVF and Firecracker resolve their image through
  `ensure_builder_vm_image`, the freshness decision libkrun and QEMU already
  took; before, they checked only that two files existed. `cache prune`
  removes `builder-vm/hvf/`.
- **The payload manifest moved** to `crates/mvm-build/src/host_payload_manifest.rs`,
  so `mvm-build` reads the one list; `BUILDER_HOST_BINARIES` is gone.
- **Image sets** carry `builder_boot_abi`. A set without it means ABI 0, local
  or release, until mvm-images#31 makes the emitter write it; W8a then refuses
  a local set that omits it.
- **ADR-004** records the builder boot contract; ADR-030 and ADR-018 point at it.

## What did not change, and why

- **Fingerprint layer 2 stays.** The in-tree builder flake still bakes the
  builder binaries (ABI 0), so a Rust edit to them still moves the builder
  image key and a source checkout still rebuilds the image through Stage 0.
  The payload makes that rebuild unnecessary for correctness — the baked
  copies never run — but removing the term is W8, after `mvm-images` ships
  ABI-1 images (W7).
- **Job-side `/mvm-bins` packing stays.** Builder jobs that build the builder
  flake read `MVM_HOST_BIN_DIR=/mvm-bins`; that goes with W8 too.

## Live boot (HVF, macOS 26 Apple Silicon, 2026-09-25)

One isolated run: `HOME`, `MVM_HOME` and `MVM_EMBED_CACHE_DIR` under a
throwaway directory, a debug `mvmctl` built with
`dev,embed-host-bins,release-artifact-bootstrap` and a fresh host-binary
cross-compile, and `MVM_BOOT_IMAGE=fetch`, so the builder image was the
published one (`image-set/v0.1.1`): boot ABI 0, no marker, and its own older
`/sbin/mvm-host-vm-init` (713 464 bytes) and `/sbin/mvm-builderd` baked in.
`mvmctl __builder-shell-job` ran a script that recorded what the guest saw:

- PID 1: `/run/mvm/host-bins/mvm-host-vm-init` (the payload copy, 798 456
  bytes), with `mvm-builderd` and `MANIFEST` beside it, all read-only.
- Kernel command line: `… root=/dev/vda ro rootfstype=ext4 rootwait
  mvm.boot_payload=7a48…c628 mvm.builder_transport=disk …` — no `init=`.
- Console: `stage1 payload 7a48…c628 verified; builder image /dev/vda is boot
  ABI 0`, then `pid 1 starting (CarriedByStage1)`; the job succeeded.

Then a one-line edit to `mvm-host-vm-init`'s stage-1 log message, a rebuild of
`mvmctl`, and the same job again: the builder image was not fetched or
rebuilt (its files kept their timestamps), the payload digest moved to
`7d1f…89ea`, and the guest printed the edited line. The second job took
22.4 s end to end.

What this does not show: in a source checkout **without**
`MVM_BOOT_IMAGE=fetch`, the same edit still moves fingerprint layer 2 and
rebuilds the image through Stage 0, because the in-tree flake still bakes the
binaries. That is W8's to remove.

Boot overhead, from the guest's console: the kernel unpacked the 2.2 MB
payload in about 1 ms (`Unpacking initramfs` 0.6445 s, `Freeing initrd
memory` 0.6455 s), ran `/init` at 0.6668 s, and had verified and copied the
payload and mounted the image by 0.6709 s — about 5 ms of stage 1 in all.
Host-side assembly was not timed separately. Firecracker, libkrun and QEMU
were not booted live here.

## Found while doing it

- HVF and Firecracker resolved their builder image by checking that two
  files existed, so a cache with another contract or a stale source
  fingerprint booted on them while libkrun and QEMU refused it. They now go
  through `ensure_builder_vm_image`.
- That then exposed that `MVM_BOOT_IMAGE=fetch` in a source checkout fetched
  and verified the published image and refused to boot it for want of a
  source fingerprint; libkrun and QEMU had the same rule. An explicit fetch
  now stands the fingerprint rule down.
- Seeding an isolated builder image cache from the shared one copied each
  artifact into place with `std::fs::copy`, which truncates and refills an
  existing file's inode. A second seeder racing the first shrank a
  `rootfs.ext4` another process was already reading, and the host-side ABI
  read failed with `ImageUnreadable` ("failed to fill whole buffer"). It
  showed up as a flaky `libkrun_builder` test in two of three runs with a
  fresh `MVM_HOME` and a real image in `$HOME`; the seed now stages and
  renames, and the same runs passed four of four. `ext4_view` itself reads
  a Nix-built image fine; a committed fixture with that image's exact
  `dumpe2fs` feature set now pins it. The three `run_build` tests that
  reached the seed without isolating `HOME` are hermetic, and
  `check-test-home-isolation` now flags that shape.
