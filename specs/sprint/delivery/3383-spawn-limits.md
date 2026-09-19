# #3383 — memory and task ceilings on every VMM spawn

**Delivered:** 2026-09-17
**Plan:** `specs/plans/2026-09-16-sandbox-review-upgrades.md` W6

## What changed

`mvm_core::cpu_scope` is now `mvm_core::spawn_scope`, because it no longer
bounds only CPU. On a Linux host with a systemd user session, every VMM spawn
is born inside a transient scope carrying `MemoryMax=` (guest RAM plus
`VMM_MEMORY_OVERHEAD_MIB`, 256), `MemorySwapMax=0`, `TasksMax=1024` and
`OOMPolicy=stop`. `CPUQuota=` is added only when a share was granted. The
Firecracker cold boot, every Firecracker snapshot load, QEMU, and the libkrun
and HVF supervisors (cold and restored) all go through it.

`bind_spawn` returns a `BoundCommand` rather than a `Command`, so the spawn
cannot skip the creation watch. The watch polls the launcher's
`/proc/<pid>/comm` until it stops being `systemd-run`. `systemd-run` execs the
payload only once the scope exists. Past `SCOPE_CREATION_TIMEOUT` (10 s) the
launcher is killed and the launch fails. The Firecracker shell path records
`$!` and uses the same watch. The read-back queries are bounded as well.

`EnforcedGrants` gains `memory` and `tasks`, as `EnforcedCeiling` values that
carry the tier and the value read back from `memory.max` and `pids.max`. They
are audited in `plan.grants_enforced` and in the supervisor's `plan.running`
entry. The waited exit report reads the scope unit's `Result`. If it is
`oom-kill`, the report writes `plan.memory_limit_exceeded`.

## Measurements behind the constants

These were measured on an x86_64 Ubuntu 24.04 KVM host (kernel 6.8,
systemd 255) with a 512 MiB, 2-vCPU guest, as the scope's `memory.current`
minus the guest mapping's resident size:

- Firecracker: about 2 MiB beyond the guest, 5 tasks.
- QEMU with `-mem-prealloc`: 34 MiB, 38 MiB at peak, 5 tasks.

The libkrun supervisor was not measured. The 256 MiB margin is deliberately
several times the largest figure.

A user manager stopped with SIGSTOP held `systemd-run` for 90 s before the
launcher failed. That wait is what the timeout exists for.

## Live evidence (same host, unprivileged user in a real SSH session)

- `a_granted_cpu_share_binds_a_real_spawn_to_its_quota`: measured 1.4939 cores
  against a 1.5-core target.
- `a_spawn_past_its_memory_ceiling_is_killed_and_the_kill_is_recorded`:
  `memory.max` read back 335544320 (64 + 256 MiB) and `pids.max` read back
  1024. The payload was killed, and the unit reported `oom-kill` at that
  ceiling.
- `a_stopped_service_manager_fails_the_launch_at_the_deadline`: the launch
  failed after 10.02 s with the scope-creation error.
- `a_scoped_vmm_reads_back_guest_ram_plus_the_overhead` (QEMU, 512 MiB): read
  back 805306368 and 1024. The `plan.grants_enforced` entry carried both
  values and the chain verified.
- `a_vmm_pushed_past_its_memory_ceiling_is_killed_and_audited`: the same QEMU,
  bounded as a 64 MiB guest, was SIGKILLed after 81 ms. The unit reported
  `oom-kill` at 335544320. The `plan.memory_limit_exceeded` entry verified on
  the chain.
- A Firecracker v1.12.1 launch in the launch script's shape, 512 MiB: the
  launcher pid became `firecracker`, and the scope read `memory.max`
  805306368, `memory.swap.max` 0 and `pids.max` 1024.

## Not done

- The exit-report call site was not exercised through a full `mvmctl` launch.
  The live runs drove the probe and the emitter directly.
- A missing mechanism is not a `--prod` refusal. The ceilings are host
  protection that no plan requests.
- The admission budget does not count the overhead margin.
