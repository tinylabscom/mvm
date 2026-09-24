# An interrupted Stage 0 run no longer poisons its store

A Stage 0 VM that died without shutting down (the user interrupted `mvmctl
machine run`, or the VM was killed) left its persistent Nix store
(`nix-store-stage0-<arch>.img`) mounted. The next bootstrap reused it as-is: the
guest kernel warned `mounting unchecked fs`, reported `freeing already freed
block`, and `nix build` failed on a zero-filled `flake.nix`. Every later
bootstrap failed the same way until the store was pruned by hand.

## Cause

The host reused the store when its seed marker matched and the superblock had no
recorded-error bit. A clear `EXT4_VALID_FS` bit, which is what an unfinished
mount leaves, was accepted as recoverable on the grounds that ext4 would replay
its journal. The store the host formats when it has no `mkfs.ext4`, which is
every macOS host, comes from the pure-Rust ext4 writer, and that filesystem has
no journal. Nothing was replayed.

## What changed

- **Reuse needs a clean unmount.** `prepopulate_stage0_nix_store_image` reuses
  the store only when its superblock records a clean unmount with no errors;
  anything else is reformatted from the seed under the store lock, with one
  `[mvm]` line naming the store and why. A journaled store is unaffected: ext4
  clears the valid bit at mount only when there is no journal.
- **A build failure keeps the store.** The guest unmounts the store on the
  failure path as well, so a failed build leaves a clean superblock and the warm
  store survives.
- **Guest-reported faults reach the host.** `stage0-init` reported a store's
  ext4 errors only when the build had succeeded; a failed build hid them. It now
  reports both. The host's reaction to that report ran only in the libkrun
  builder; the generic Stage 0 runner that HVF, Firecracker and QEMU use now runs
  it too.
- **QEMU unmounts its store.** `stage0-init` skipped finalization and store GC
  on QEMU, a leftover from when QEMU Stage 0 had no persistent store. Without
  this change the stricter reuse check would have reformatted a QEMU store on
  every bootstrap.

The steady-state builder store (`nix-store-<arch>.img`) does not have the same
exposure: the guest formats it with e2fsprogs `mkfs.ext4`, which gives it a
journal, and `mvm-host-vm-init` already refuses a store with recorded errors.

## Not done

- Interrupting `mvmctl` still kills the Stage 0 VM without a clean shutdown.
  The Stage 0 guest has no control channel through which to request a poweroff,
  so the store is discarded and rebuilt on the next bootstrap rather than
  corrupting it. Asking the guest to shut down on SIGINT would keep it warm.
- No live boot. The QEMU finalization change is covered by the Linux
  cross-check only.

## Validation

`cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D
warnings`; `RUSTFLAGS="-D warnings" just check-gated`; `cargo nextest run -p
mvm-build -p mvm-runtime -p mvm-cli`; `cargo nextest run --workspace`; `cargo
test --workspace --doc`; `xtask check-all`.
