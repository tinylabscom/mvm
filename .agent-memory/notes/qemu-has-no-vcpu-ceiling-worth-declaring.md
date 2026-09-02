---
title: QEMU has no vCPU ceiling worth declaring, and the guest kernel caps at 64 regardless
date: 2026-09-01
tags: [qemu, vcpu, capabilities, backends, falsification]
---

The QEMU driver declares no `VmCapabilities::max_vcpus`, so the reporting clamp
never fires and `--cpus 9999` boots with no warning. That was left open after
the Firecracker (32) and libkrun (64) ceilings were fixed. It is now closed as
working as intended, and the reason is not "QEMU is a dev backend" — it is that
**every candidate ceiling is either wrong or invisible**.

Measured on the Hetzner x86_64 KVM box, QEMU 8.2.2 (Debian
`1:8.2.2+ds-0ubuntu1.17`), against `mvmctl machine run --hypervisor qemu`:

| probe | result |
| --- | --- |
| `--cpus 100`, guest `nproc` | **64**, exit 0 |
| `--cpus 300`, guest `nproc` | **64**, exit 0 |
| guest dmesg | `CPU topo: Allowing 64 present CPUs plus 0 hotplug CPUs` |
| guest `/sys/devices/system/cpu/kernel_max` | `63` |
| `qemu-system-x86_64 -smp 9999` (no `-machine`) | refuses; max for `pc-i440fx-noble-v2` is **255** |
| `qemu-system-x86_64 -machine help` | default machine is `pc-i440fx-noble-v2` |
| QMP `query-machines` | `pc-i440fx-*` → `cpu-max` **255**; `pc-q35-5.2`+ → **288**; `pc-q35-2.7`/`-xenial` → 255 |
| `qemu-system-x86_64 -M q35 -smp 256` | **fails**: `apic initialization failed. APIC ID 255 is invalid` |
| `qemu-system-aarch64 -M virt -smp 513` | refuses; max for `virt-8.2` is **512** (512 accepted) |

Three findings, in increasing order of how much they settle the question.

**A constant would be right by coincidence.** One host and one binary give
three different answers depending on machine type and version. `mvm` passes
`-machine virt` on aarch64 and *no* `-machine` at all on x86_64
(`mvm_vmm::qemu_arch::machine_for_arch`), so the x86_64 number is a property of
whichever machine the distribution shipped as its default. It moves without mvm
moving. That 255 happens to equal `u8::MAX` is luck, not derivation.

**Querying returns the wrong number — this is the part that was not known.**
QMP `query-machines` reports `cpu-max: 288` for `pc-q35-noble`, and that machine
refuses to start at `-smp 256`. So a cached subprocess in `capabilities()`
would not merely cost a spawn on a path every launch and `mvmctl doctor` walk —
it would hand the clamp a count 33 above what the machine boots, recreating the
exact #3051 defect (a granted count that will not run) with a more expensive
mechanism. The only oracle that tells the truth is the boot attempt, and the
contract forbids making an over-large `--cpus` fatal.

**No host-side ceiling is the number the caller observes.** `--cpus 100`
passes QEMU's check (100 < 255), boots, and yields 64. The binding limit is
`CONFIG_NR_CPUS` in the guest kernel, which `nix/images/kernel/` does not set —
it is nixpkgs' arch-dependent default, inherited and unpinned. A clamp warning
is only truthful when the *declared* ceiling is the *binding* one. On
Firecracker (32) and libkrun (64) it is, so those warnings are honest. On QEMU
it never is: every candidate sits above 64, so any warning would name a count
four times the machine the caller got. **Today's silence is more accurate than
the warning would be.**

Do not re-derive this, and in particular do not "finish" it by declaring
`Some(255)`. The `-smp` floor in `qemu_boot_argv_for_arch` stays — it is what
keeps an absurd request non-fatal, since raw QEMU refuses `-smp 9999` — but it
is a floor, not a ceiling claim, and `check-vcpu-ceilings` correctly does not
see it as a declaration.

Loose end, not a defect in this backend: `--cpus 100` silently delivering 64 is
a *granted ≠ delivered* gap that exists on every backend and is only hidden on
the others by their lower declared ceilings. Closing it means reporting the
guest's real count after boot, which is a different mechanism from a host-side
clamp. Not built here.

Related: [[a-citation-can-resolve-to-its-own-test-fixture]].
