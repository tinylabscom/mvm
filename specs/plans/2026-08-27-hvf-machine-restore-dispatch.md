# HVF machine restore dispatch

**Issue:** #2961  
**Status:** IN PROGRESS

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
- [ ] Run a live two-vCPU HVF parent capture and child restore, proving both
      restored vCPUs resume.
- [ ] Run a live restore with a deliberately mismatched target CPU count and
      prove it refuses before resuming the guest.

## Validation and delivery

- [x] Focused `mvm-cli` machine checkpoint unit tests pass.
- [ ] `cargo test --workspace` passes.
- [ ] `cargo clippy --workspace -- -D warnings` passes.
- [ ] `just check-gated` passes.
- [ ] Plan, sprint, refactor rollup, and delivery note agree.
- [ ] Pull request checks pass and the PR merges through the merge queue.
