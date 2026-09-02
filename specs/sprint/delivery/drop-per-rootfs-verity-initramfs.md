# Drop the per-rootfs verity initramfs

Every sealed rootfs used to get its own `rootfs.initrd` assembled beside it: a
gzip cpio carrying `mvm-verity-init` as PID 1, which read the roothash off
`/proc/cmdline`, built the dm-verity device-mapper target by raw ioctl, mounted
it, and `switch_root`ed to the real `/init`. The universal initramfs replaced
that: its agent is PID 1, it receives the roothash and device paths over vsock
via `ActivateEnvironment`, and `guest_mount::mount_rootfs` sets the dm-verity
target up itself. The per-rootfs artifact had no remaining job.

**dm-verity sealing is unchanged.** Claim 3 rests on the sealed rootfs and its
`rootfs.verity` / `rootfs.roothash` sidecars, all of which still land exactly as
before. What goes is the *initramfs that used to set the target up*, not the
seal, and not the verification.

## What that let go

- `crates/mvm-agentd/src/bin/mvm-verity-init.rs` and its `[[bin]]`.
- `crates/mvm-build/src/verity_initrd.rs`, whole module.
- `seal_and_assemble_verity` collapses to `seal_rootfs_for_run` — a plain seal.
  The write-initrd-first/roll-back-on-seal-failure ordering existed only to keep
  two artifacts in step, and with one artifact there is nothing to keep in step.
- `qemu_verity_initrd_path` / `libkrun_verity_initrd_path`, and the
  `.or_else(...)` in each driver's `effective_initrd` that fell back to a
  sibling `rootfs.initrd`. The explicit universal-initramfs path is the only
  source now.
- `rootfs.initrd` leaves the checkpoint sidecar carry-list and the CoW clone
  list.
- The guest binary set drops from five to four across `MvmRuntimeBinaries`,
  `GuestAgentLayout`, `RuntimeOverlayGuestLayout`, `GuestRuntimeBinaryPaths`,
  `OCI_GUEST_RUNTIME_BINARY_NAMES`, the `cargo zigbuild --bin` list, and
  `OVERLAY_ARCHIVE_MEMBERS`.
- nix: the `--bin mvm-verity-init` flag, the overlay flake's copy of it, and the
  `verityInitBinary` passthru in `mk-guest.nix` — whose only consumer was the
  initramfs builder this change deletes.
- `.github/workflows/release-boot-image.yml`: three guest-runtime binary lists.

## Tests kept rather than deleted

`seal_and_assemble_verity_emits_all_artifacts_together` was the load-bearing
`--prod` invariant, and it is a real Linux + `veritysetup` test. It survives as
`sealing_emits_both_verity_sidecars`, asserting the same two sidecars land with
a 64-hex roothash, plus a new assertion that **no** `rootfs.initrd` is produced.
The initrd-assembly tests around it are gone because what they exercised is.

`a_missing_artifact_is_an_error_not_a_stale_identity` made an artifact vanish by
deleting `bins.verity_init`; it now deletes `bins.egress_client`, so it still
tests what it says.

## Gates

`fmt --all`, `clippy --workspace --all-targets` (zero warnings),
`nextest --workspace` (12,183 pass), `cargo test -p mvmctl`,
`xtask check-all` (61 gates), and `just check-gated`.

`check-gated` earned its keep here: after macOS `nextest` was fully green, the
Linux cross-compile still failed on a `cfg(target_os = "linux")` test that a
macOS host never compiles — the `veritysetup` seal test above, which a
Rust-suite-only sweep would have shipped broken.
