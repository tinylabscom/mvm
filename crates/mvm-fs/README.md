# mvm-fs

`mvm-fs` owns filesystem and image materialization for mvm. It fetches and
verifies OCI content, builds deterministic ext4 images, seals root filesystems,
clones runtime state efficiently, and stores content-addressed snapshots.

## Who uses it

`mvm-build` uses it to turn source and OCI content into bootable artifacts.
`mvm-runtime` and `mvm-vmm` use its rootfs, clone, overlay, and snapshot
operations during launch and restore. `mvm-hostd`, `mvm-client`, `mvm-cli`, and
`xtask` consume storage, verification, or fixture helpers.

## How it works

The OCI path resolves a reference, selects a platform manifest, verifies every
declared digest while downloading, and unpacks only allow-listed filesystem
entries into a staging tree. `rootfs` walks that tree once and feeds the
pure-Rust `ext4` writer. `oci_to_rootfs` then produces the ext4 image and its
dm-verity metadata as a single materialization pipeline.

At runtime, `overlay` selects a versioned, architecture-specific sealed overlay.
`clone` uses platform copy-on-write primitives when available and safe
fallbacks otherwise. `snapshot_store` hashes snapshot inputs and verifies them
on read, so warm-pool state is addressed by content rather than mutable names.

## Main modules

| Module | Responsibility |
|---|---|
| `oci` | Registry resolution, fetch, verification, and safe unpack |
| `ext4` | Deterministic in-process ext4 writer |
| `rootfs` / `oci_to_rootfs` | Directory-to-image and OCI-to-image pipelines |
| `initramfs` | Initramfs construction and inspection |
| `overlay` | Runtime overlay selection and integrity checks |
| `clone` | Reflink/copy-on-write cloning |
| `hash` / `snapshot_store` | Content identity and durable snapshots |
| `extension_image` / `sdk_sidecar` | Auxiliary guest image assembly |
| `trusted_snapshot` | Platform-backed trusted snapshot support |

## Security boundaries

Registry and archive input is untrusted. Paths are normalized before writes,
digests are checked before content is trusted, allocations are capped, and
special files or traversal attempts are rejected. The crate denies unsafe code
except for small reviewed platform calls in the cloning implementation.

## Developing

Run `cargo test -p mvm-fs`. Changes to archive, image, or snapshot parsers need
positive, malformed, traversal, and tamper tests. The OCI and ext4 fuzz targets
live outside the main workspace and should be exercised for parser changes.
