# Builder VMs are not user machines

Delivered 2026-08-21.

## What was wrong

`mvmctl machine ls` listed a running `nix build` as a machine:

```
NAME                                             KIND       STATUS   HEALTH  BACKEND  PORTS  SOURCE  AGE
mvm-hvf-builder-shell-92326-1787337475138993000  transient  running  -       hvf      -      -       -
```

and then every spec-requiring verb refused the name it had just printed:

```
$ mvmctl machine shell mvm-hvf-builder-shell-92326-1787337475138993000
Error: machine "mvm-hvf-builder-shell-…" does not exist.
```

PID 92326 was an `mvmctl __builder-shell-job` running in a different worktree
against a shared `MVM_HOME`.

Two independent defects met there.

**The builder is in the workload namespace.** libkrun's builder stages VM state
under `~/.mvm/cache/builder-vm/vms/`; the HVF builder family stages it under
`~/.mvm/vms/`, because `BuilderRunner::build` and `HvfPersistentBuilder` both
call `mvm_core::config::vm_state_dir`. The inventory join
(`mvm_client::inventory::join_inventory`) is specs × live-backend-scan, and
anything live the spec registry does not claim becomes a transient record — so
the builder job arrived as a machine with every spec-derived column blank.

**`shell`/`exec` gated on the wrong thing.** Both did `let _ =
load_machine_spec(&args.name)?;` and discarded the result: a bare existence
check against the *spec* store. But they reach the guest over the per-VM vsock
socket under `~/.mvm/vms/<name>/` and never read a spec. A transient VM from
`machine run` has that socket and no spec, so the console was refused for a
machine `machine ls` was correctly listing as running. The builder job hit the
same gate, which is why it produced a misleading error rather than the right
one.

## What changed

`mvm_core::naming` now owns builder VM names — both the minting
(`persistent_builder_vm_name`, `builder_shell_vm_name`, and the
`BuilderVmSlot` enum pinning the documented `-vm-` / `-hvf-` on-disk tokens)
and the predicates that recognise them. The three `format!` sites in
`hvf_builder`, `hvf_persistent` and `libkrun_builder` call it, so the format
and the predicate cannot drift apart — a test asserts the predicate against
what the minting functions return, not against a literal.

- `join_inventory` drops builder-owned VMs from the spec-less remainder. A
  *spec* with a builder-shaped name is still listed: that one the user created.
- `machine shell` / `machine exec` gate on `require_console_target`: a
  persisted spec **or** a runtime state dir admits, so transients work; a
  builder-owned name is refused by name with the reason (headless, no agent,
  no PTY) rather than "does not exist".
- The orphan reaper now treats a per-job builder dir as ephemeral wherever it
  sits, and the workload root is swept under the same `remove_builder_dirs`
  authority the builder root already had. Without this, hiding builder VMs
  from `machine ls` would have converted a visible leak into an invisible one:
  everything under the workload root was `all_dirs_managed`, so a finished
  build's dir was never pruned. The kill-only startup sweep passes `false` and
  still removes nothing.

## Not fixed

The namespace collision itself. The filter is by name, which holds only while
builder VM names keep a recognisable prefix. Moving HVF builder state out of
`~/.mvm/vms/` is
`specs/plans/2026-08-21-hvf-builder-state-out-of-the-workload-namespace.md`.
