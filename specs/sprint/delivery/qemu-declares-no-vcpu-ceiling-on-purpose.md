# The QEMU backend declares no vCPU ceiling, and that is the answer

After the Firecracker (32) and libkrun (64) ceilings were corrected, QEMU was
the one backend left declaring nothing: `capabilities().max_vcpus` is `None`,
so the reporting clamp above the backends never fires and `--cpus 9999` boots
silently. That was recorded as unmeasured and deliberately left open.

It is now measured, and the outcome is that QEMU is **working as intended**.
No probe, no constant. The deliverable is the reasoning, pinned by a test so it
cannot be quietly "finished" by someone declaring a plausible number.

## Why this was not a matter of picking a number

Measured on the Hetzner x86_64 KVM box, QEMU 8.2.2
(`1:8.2.2+ds-0ubuntu1.17`). Nothing below is inferred.

| probe | result |
| --- | --- |
| `mvmctl machine run --hypervisor qemu --cpus 100`, guest `nproc` | **64**, exit 0 |
| `mvmctl machine run --hypervisor qemu --cpus 300`, guest `nproc` | **64**, exit 0 |
| guest dmesg | `CPU topo: Allowing 64 present CPUs plus 0 hotplug CPUs` |
| guest `/sys/devices/system/cpu/kernel_max` | `63` |
| `qemu-system-x86_64 -smp 9999`, no `-machine` | refuses; max for `pc-i440fx-noble-v2` is 255 |
| `qemu-system-x86_64 -machine help` | default machine is `pc-i440fx-noble-v2` |
| QMP `query-machines` | `pc-i440fx-*` → `cpu-max` 255; `pc-q35-5.2`+ → 288; `pc-q35-2.7`/`-xenial` → 255 |
| `qemu-system-x86_64 -M q35 -smp 256` | **fails**: `apic initialization failed. APIC ID 255 is invalid` |
| `qemu-system-aarch64 -M virt -smp 513` | refuses; max for `virt-8.2` is 512 (512 accepted) |

**A constant is wrong.** One host, one binary, three answers, chosen by machine
type and version. This driver names no machine on x86_64
(`mvm_vmm::qemu_arch::machine_for_arch` returns `None` there), so that 255 is a
fact about the distribution's packaging, not about mvm — it changes without mvm
changing. That it coincides with `u8::MAX` is luck. Writing it down would
reproduce the defect `xtask check-vcpu-ceilings` exists to refuse, in a form the
gate cannot see because the literal would no longer name a type.

**A query is wrong, which is the finding that decides it.** The obvious
objection to a probe was cost: `capabilities()` is called on every launch and by
`mvmctl doctor`, so an honest answer would need a cached subprocess. The real
problem is worse. QMP `query-machines` reports `cpu-max: 288` for
`pc-q35-noble`, and that machine will not start at `-smp 256`. A probe would
spend the subprocess to obtain a count 33 above the one the machine boots —
handing the clamp a granted-but-unbootable number, which is precisely the #3051
failure, bought at a higher price. The only oracle that tells the truth is the
boot attempt, and the contract forbids letting an over-large `--cpus` be fatal.

**And no host-side number is the one the caller observes.** `--cpus 100` clears
QEMU's check and still yields a 64-CPU guest. The binding limit is
`CONFIG_NR_CPUS` in the guest kernel, which `nix/images/kernel/` does not set —
so it is nixpkgs' arch-dependent default, inherited and unpinned. A clamp
warning is only truthful when the declared ceiling is the binding one. On
Firecracker (32) and libkrun (64) it is, which is why those warnings are honest.
On QEMU it never is: every candidate ceiling sits above 64, so any warning would
name a count four times the machine the caller actually got. Silence is the
accurate answer here, not the unfinished one.

## What landed

- `crates/mvm-backends/src/driver/qemu.rs` — the `-smp` bound is documented as
  a **floor** that keeps an absurd request non-fatal (raw QEMU refuses
  `-smp 9999`), explicitly not a claim about how many vCPUs QEMU starts, with
  the measurements above recorded where the next reader will look.
- `no_vcpu_ceiling_is_declared_and_an_oversized_request_still_boots` — asserts
  `max_vcpus` is `None` and that 9999/300/100/0 reach `-smp` as 255/255/100/1,
  so the contract (granted, never refused) stays pinned to the mechanism that
  actually holds it.
- `.agent-memory/notes/qemu-has-no-vcpu-ceiling-worth-declaring.md` — the
  measurements, so this costs one read rather than four guest boots.

No behaviour change: `--cpus 9999` booted before and boots now.

## Deliberately not done

`--cpus 100` silently delivering 64 is a *granted ≠ delivered* gap that exists
on every backend and is merely hidden on the others by their lower declared
ceilings. Closing it means reporting the guest's real CPU count after boot,
which is a different mechanism from a host-side clamp and a different decision.
Not in scope here.
