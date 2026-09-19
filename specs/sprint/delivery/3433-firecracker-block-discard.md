# Firecracker 1.17 and block discard for the builder stores

Issue #3433, the Linux half of #3360's reclaim.

Firecracker served the Linux builder and Stage 0 stores from a pinned v1.14.1,
whose virtio-block offers no discard. A guest trim returned `EOPNOTSUPP`, so the
sparse store images kept their high-water mark however much Nix collected.

## What changed

- **Pin.** `FC_VERSION_DEFAULT`, the CI install steps (`ci.yml`, `ci-full.yml`,
  `bdd.yml`, `e2e-docs.yml`, `release-boot-image.yml`) and the Hetzner
  cloud-init move to v1.17.0. The `ci-full.yml` lane that installs Firecracker
  inside the builder-VM rootfs keeps its own v1.10.1 pin; it is not the host
  driver.
- **Discard, gated on the running binary.** Every writable drive asks for
  `discard` when the Firecracker serving the API socket reports 1.17 or later
  (`GET /version`, read right after the socket is adopted). `install` keeps an
  existing Firecracker, and Firecracker before 1.17 rejects unknown drive
  fields, so the pin cannot decide this: an older or unreadable version gets
  the byte-identical drive body it accepts today. Read-only drives never carry
  the field. `drive_body` became `FcDrive`, which enforces both.
- **Fleet CI assets.** The `firecracker-ci/<version>/` prefix that
  `download_assets` and the fleet builder read kernel and rootfs from is pinned
  apart at v1.15, the last prefix the public bucket publishes. Deriving it from
  the binary version would have pointed both at an empty listing.
- **Doctor.** A `fc block discard` line reports whether the installed
  Firecracker returns trimmed blocks, and names the version to install when it
  does not.

## Live evidence

Hetzner KVM box, x86_64, cold `MVM_HOME`, `MVM_BUILDER_STORE_GC_GIB=1`, debug
build with `MVM_EMBED_NO_CACHE=1` and the collection code confirmed in the
embedded init. Firecracker 1.17.0 ran from a private `PATH` entry so the box's
shared 1.14.1 stayed in place for other sessions.

- **Firecracker 1.14.1, cold:** `mvmctl bootstrap` exit 0; both Stage 0 builds
  collected (`9307380 -> 2157948 KiB`, `4200660 -> 1352460 KiB`) and reported
  `the store disk does not support discard`. The gate sent no field the old
  binary would refuse. Store image afterwards: **11,509,456 KiB allocated**.
- **Firecracker 1.17.0:** exit 0; built to `9307456 KiB` used, collected to
  `2157972 KiB`, then `trimmed 66172858368 bytes of freed store blocks`. Store
  image afterwards: **2,538,376 KiB allocated** (apparent size unchanged at
  64 GiB).

Both runs started from a freshly formatted store and made the same cold build,
peaking at ~9.3 GB used. Without discard the file kept that high-water mark
plus the kernel build's (11.5 GB); with it, the blocks freed after the peak went
back to the host. (The second run started fresh because the test script
removed the store's host-side `.stage0-seed` marker along with the builder
image, which makes the host reformat the store; that was the script, not the
collection.)

Two warm bootstraps on 1.17 then kept the store and its marker and removed
only the built outputs. The image Stage 0 built nothing and collected
`2621520 -> 2053612 KiB`; the workload-kernel Stage 0 built its 4 derivations
and collected to `1352484 KiB`; a second image Stage 0 straight after that was
still warm (no derivations). Every run trimmed, and the store image stayed at
1.7–2.4 GB allocated. So one Stage 0 flavour's collection does not unroot what
the other needs.

## Not done

- A snapshot taken by Firecracker 1.14.1 will not restore on 1.17: the snapshot
  format moves from 8.0.0 to 12.0.0, and Firecracker treats a major bump as
  incompatible. Our snapshots are not keyed by Firecracker version, so
  upgrading a host's Firecracker leaves its warm snapshots unusable. How
  cleanly the restore path refuses one was not exercised.
- libkrun's block device is still unsurveyed for discard.

## Validation

`cargo fmt --all -- --check`; `RUSTFLAGS="-D warnings" just check-gated`;
`cargo nextest run -p mvm-core -p mvm-vmm -p mvm-backends -p mvm-runtime -p
mvm-build -p mvm-cli -p mvmctl` (7909/7915; the six failures were broker and
network-endpoint spawn tests timing out at load average ~190, and all 64 in
those modules pass on rerun); `cargo test --workspace --doc`; `xtask check-all`
(69 gates); the `test-support` library lane (4734 passed).
