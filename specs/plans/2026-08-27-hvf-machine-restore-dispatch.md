# HVF machine restore dispatch

Backing: shipped-source
Validation: check-sprint-append

**Issue:** #2961  
**Status:** COMPLETE

## Problem

The backend-neutral `vm checkpoint fork` surface classifies a full-machine
checkpoint by its recorded machine-state blob, but all three `machine`
fork/restore surfaces called the Firecracker arm directly. An HVF checkpoint
therefore hit Firecracker's live-parent refusal even though the HVF restore arm
already existed and the checkpoint manifest classified correctly.

## Implementation

- [x] Make the shared vm_full dispatcher callable from the sibling `machine`
      command module.
- [x] Carry the caller's Firecracker experimental opt-in through that
      dispatcher; ignore it for non-Firecracker origins.
- [x] Replace the direct Firecracker call in `fork_vm_full_machine` with the
      shared dispatcher.
- [x] Add an HVF-origin regression and a retired-origin fail-closed regression
      through the user-facing machine helper.
- [x] Run a live two-vCPU HVF parent capture and child restore, proving both
      restored vCPUs resume. Driven on macOS 26.5.2 arm64: a live 2-vCPU HVF
      parent was forked, and the child's own post-restore guest RAM carries 217
      probe samples generated after the capture point, every one reporting
      `nproc=2`, `grep -c ^processor /proc/cpuinfo = 2`, and
      `/sys/devices/system/cpu/online = 0-1`, with no RCU stall or lockup
      warning on the child console.
- [x] Stop asking a resumed child to rename itself. A restore skips the boot
      where `mvm.hostname=` is applied by PID 1, and the unprivileged agent
      that survives into the child cannot call `sethostname`, so the request
      failed every HVF fork. Both the fork and warm-claim paths now build their
      signal from `VsockPostRestoreSignal::for_resumed_child`.
- [x] Run a live restore with a deliberately mismatched target CPU count and
      prove it refuses before resuming the guest. A two-vCPU checkpoint offered
      to a one-vCPU target is rejected before restore-target construction with
      `snapshot vCPU count does not match this machine`.

## Validation and delivery

- [x] Focused `mvm-cli` machine checkpoint unit tests pass.
- [x] `cargo nextest run --workspace` passes (one pre-existing, host-dependent
      failure unrelated to this branch: `dev_vm_connects_via_libkrun_per_port_socket`
      asserts no socket-path shortening and so fails under macOS's long default
      `TMPDIR`; it passes with `TMPDIR=/tmp`, and this branch does not touch
      `crates/mvm-vmm/src/host/`).
- [x] `cargo clippy --workspace -- -D warnings` passes.
- [x] `just check-gated` passes.
- [ ] Plan, sprint, refactor rollup, and delivery note agree.
- [ ] Pull request checks pass and the PR merges through the merge queue.
