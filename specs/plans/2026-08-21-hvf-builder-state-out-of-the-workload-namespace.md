# HVF builder state out of the workload VM namespace

Backing: shipped-source
Validation: none

**Status:** OPEN
**Date:** 2026-08-21
**Owner:** mvm

## Why

The libkrun builder stages its VM state under `~/.mvm/cache/builder-vm/vms/`.
The HVF builder family stages its state under `~/.mvm/vms/` — the workload
machine namespace — because `BuilderRunner::build`
(`crates/mvm-runtime/src/builder_runner/runner.rs:90`) and
`HvfPersistentBuilder` (`.../hvf_persistent.rs:138`) both call
`mvm_core::config::vm_state_dir`.

Two surfaces read that directory as "the user's machines" and got the builder
back:

- `machine ls` listed a running `nix build` as a transient machine the user
  owned, whose every spec-derived column was blank and whose name every
  spec-requiring verb then refused.
- The orphan reaper treats everything under the workload root as managed
  restartable state, so a finished build's dir was never pruned.

Both were fixed at the reading end, by name
(`mvm_core::naming::is_builder_owned_vm_name`). That is a correct filter and a
fragile boundary: it holds only as long as every builder VM name keeps a
recognisable prefix, and it does nothing about the namespace collision itself —
a machine and a builder job can still claim the same directory.

## What

Give the HVF builder its own state root, so the two namespaces stop
overlapping and the name filter becomes belt-and-braces rather than the
mechanism.

- [ ] Thread a state root through `BuilderRunner`/`BuilderBuild` instead of
      reaching for `vm_state_dir` directly; default it to
      `builder_vm_cache_dir().join("vms")`, matching libkrun.
- [ ] Move `HvfPersistentBuilder`'s `vm_state_dir` call to the same root.
- [ ] Follow the vsock socket paths: `vm_hvf_vsock_port_socket_at` and
      `vm_vsock_port_socket_at` are resolved from the state dir, so anything
      that reconnects to a builder by name has to move with it.
- [ ] Migration: an existing `~/.mvm/vms/mvm-*builder*` dir must not strand a
      warm Nix store. Either move it on first use or accept the one-time
      rebuild and prune it.
- [ ] Once the roots are disjoint, `mvmctl doctor`'s builder line and
      `cache prune` can drop their workload-root special cases.

## Not doing

Renaming the on-disk name prefixes. `mvm-persistent-builder-vm-*` /
`mvm-persistent-builder-hvf-*` are documented in CLAUDE.md and are load-bearing
for existing state dirs; `mvm_core::naming::BuilderVmSlot` pins them.
