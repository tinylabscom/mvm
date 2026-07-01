# ADR-099 — Multi-backend hypervisor abstraction (the `HypervisorVm`/`HypervisorVcpu` seam)

**Status:** Accepted (2026-06-29)
**Relates to:** [Plan 214](../plans/214-clean-replacement-architecture.md) ("no VMM lock-in"),
[ADR-098](098-macos-raw-hvf-performance-backend.md) (raw HVF macOS backend),
the no-VMM-lock-in principle in [ADR-066](066-target-architecture.md).

## Context

The clean-replacement work built a **portable, hypervisor-agnostic device model**
(`mvm_backend::vmm`: guest memory, device tree, arm64 kernel-image loading, the
PL011 console, and virtio-mmio block + vsock) with zero hypervisor FFI, plus a
**raw HVF backend** (`mvm_backend::hvf`) that boots real arm64 Linux to userspace
on macOS / Apple silicon, live-proven (PL011 console, in-kernel GICv3 + arch
timer, PSCI, virtio-blk, virtio-vsock).

To honour the no-VMM-lock-in principle we need the *same* device model and run
loop to run under other hypervisors — **KVM on Linux**, **WHP on Windows** — not
just HVF. The question this ADR answers: **what is the seam between the portable
VMM and a concrete hypervisor, so backends plug in without rewriting the run loop
or the device model?**

The source review (the reviewed reference implementation studied for this work —
not named here, per the architecture brief) solves exactly this with a single
high trait pair and static, compile-time backend selection. We adopt that shape.

## Decision

Introduce a portable hypervisor seam in `mvm_backend::vmm::hv`:

- **`HypervisorVm`** — owns guest physical memory + the interrupt controller and
  creates vCPUs: `create()`, `map_ram()`, `create_vcpu()`, `set_irq(intid, level)`.
- **`HypervisorVcpu`** — drives one vCPU: `step() -> VcpuExit`, `get/set_core`,
  `get/set_sys`, plus an `exit_token()` returning a `VcpuHandle` that another
  thread can use to force the vCPU out of `step()` (run watchdog / snapshot
  rendezvous).
- **`VcpuExit`** — a small `Copy` enum that **unifies the two ways a guest MMIO
  access surfaces**: the raw arm64 `Exception { syndrome, phys_addr }` (HVF — the
  run loop decodes the ESR) *and* the already-decoded `Mmio { … }` / `Io { … }`
  (KVM `KVM_EXIT_MMIO` / `KVM_EXIT_IO`). Both route to the same device handler,
  so **one run loop serves every backend and architecture**.
- **`CoreReg` / `SysReg`** — portable register names (`X(n)`, `Pc`, `Cpsr`,
  `MpidrEl1`); each backend maps them to its native id (HVF `hv_reg_t`; KVM
  `KVM_REG_ARM_CORE`).

The seam is drawn **high**: memory, registers, IRQ-raise, and run/exit live in
the contract; everything below (how a backend services doorbells or injects
interrupts) is the backend's own business, so each platform uses its fastest
native mechanism (userspace on HVF; irqfd / ioeventfd / in-kernel irqchip on
KVM) without the portable layer forcing a slower pattern.

Dispatch is **static**: the active backend is bound as a concrete type alias
`vmm::hv::ActiveVm` behind `#[cfg]`, so trait calls monomorphize to direct calls
— **no `dyn` on the vCPU hot path**.

```
macOS / aarch64   →  ActiveVm = hvf::HvfVm     (HVF)
linux / aarch64   →  ActiveVm = kvm::KvmVm     (KVM — to land)
linux / x86_64    →  ActiveVm = kvm::KvmVm     (KVM, x86 boot/16550/IOAPIC)
windows           →  ActiveVm = whp::WhpVm     (WHP — later)
```

`mvm_backend::vmm` (device model + the forthcoming generic run loop) is the layer
**below** the product `VmBackend` trait and **above** this seam:

```
VmBackend (product/CLI/mvmd) ─ AnyBackend dispatch
        └── vmm: device model + generic run loop  ── drives ──▶  HypervisorVm/Vcpu seam
                                                                   ├─ hvf  (macOS)
                                                                   ├─ kvm  (Linux)
                                                                   └─ whp  (Windows)
```

## Why this shape

- **One run loop, many backends.** The MMIO/virtqueue/console dispatch is written
  once against `VcpuExit`; adding a hypervisor is "implement two traits."
- **Cross-architecture for free in the exit enum.** Because `VcpuExit` carries
  both the raw-`Exception` and decoded-`Mmio`/`Io` forms, the same loop handles
  arm64 (HVF raw ESR; KVM decoded) and x86 (KVM decoded `Io`/`Mmio`).
- **Zero hot-path overhead.** Static `cfg` dispatch, no `dyn`, no vtable on
  `step()`.
- **No lock-in.** A backend is one module behind the seam; none leaks into the
  device model or the product `VmBackend`.

## Status of implementation

- ✅ `vmm::hv` — the trait contract (`HypervisorVm`, `HypervisorVcpu`,
  `VcpuExit`, `CoreReg`, `SysReg`, `VcpuHandle`, `prot`). Portable; compiles on
  macOS + cross-compiles to Linux.
- ✅ `hvf::{HvfVm, HvfVcpu, HvfHandle}` implement the seam (thin wrappers over the
  existing HVF FFI), validating the contract against a real, live-proven backend;
  `ActiveVm` binds on macOS.
- ✅ **Unified run loop** (`vmm::run`) — one body, generic over `HypervisorVcpu`:
  `step()` → dispatch decoded `Mmio`/`Io` to a `RunDevice` list (matched by guest
  address / port) → `complete_read` on a read → `set_irq` on a write that raises
  a line; `Halt`/`Canceled` end it; non-MMIO exceptions (arm64 PSCI/HVC) go to a
  caller hook. `RunDevice` is implemented for `Pl011`/`VirtioBlk`/`VirtioVsock`.
  Mock-tested with a scripted vCPU (7 tests: read-completion, write+offset, IRQ
  raise, PIO-by-port + RAZ, cancel, exception hook, vtimer); compiles on macOS +
  both Linux targets.
- ✅ **HVF `VmBackend` + selection.** `mvm-hvf-supervisor` (the detached per-VM
  host process, `mvm-vm-host`) self-signs the hypervisor entitlement, reads an
  `HvfSupervisorConfig` (in `mvm-build`, shared with the backend) on stdin, boots
  via `boot_kernel`→`vmm::run`, and captures `console.log` + a PID file.
  `HvfBackend` (always-compiled `crate::hvf_backend`) implements the lifecycle
  over it — `start` spawns + waits for the PID file, `stop`/`status`/`list`/`logs`
  track it — and is registered in the catalog + `AnyBackend` so
  `--hypervisor hvf` / `MVM_BACKEND=hvf` select it. Live-verified end to end on
  Apple silicon (start → status Running → guest to PID 1 + virtio-blk → logs →
  stop). `as_workload_backend` returns `None` until egress parity lands.
- ✅ **HVF boots a live arm64 Linux guest through the unified loop.**
  `hvf::kernel_boot` now wraps its raw vCPU in `HvfVcpu` and drives it via
  `vmm::run`: the inline `sys` decode/dispatch loop is gone; PL011/virtio-blk/
  virtio-vsock dispatch through `RunDevice` + `complete_read`, PSCI/HVC via the
  exception hook, and the watchdog via the seam's `force_exit`. Live-verified on
  Apple silicon: boots to **PID 1**, reads a virtio-blk disk, and round-trips a
  virtio-vsock message — same result as the pre-migration path. The KVM boot path
  gets the same loop once driven on the box (the spike already proves the guest).
- ✅ **x86_64 KVM boot live-proven to userspace** — a `kvm-ioctls` driver
  (`spikes/kvm-x86-boot/`) boots a stock distro `bzImage` on `/dev/kvm` straight
  to **PID 1** (`Run /init as init process` → the init's own marker → clean
  shutdown). KVM is *simpler* than HVF on the run loop: the kernel decodes MMIO
  (`VcpuExit::Mmio`/`Io`, no ESR to parse). The x86 host device path the spike
  pins down for the backend: 64-bit long-mode entry (page tables + GDT +
  `efer.LME`, kernel at 1 MiB, entry `+0x200`), **`KVM_SET_CPUID2`** with the
  host-supported CPUID (without it the kernel's early page-table math faults), a
  **two-entry e820** map (0–640 KiB, then 1 MiB–end; a single entry falls back to
  legacy e801 → no RAM → `alloc_low_pages` panic), the **in-kernel irqchip +
  `KVM_CREATE_PIT2`** (no PIT → the kernel hangs after APIC setup waiting for
  timer ticks), and a 16550 serial for the console.
- ✅ `kvm::KvmVm` / `KvmVcpu` (x86_64) — implement the seam over `kvm-ioctls`
  (`create`/`map_ram`/`create_vcpu`+CPUID/`set_irq`/`step`→`Io`/`Mmio`/`Halt`,
  `boot_x86` applying the entry regs, a `tgkill`-based `force_exit`). `ActiveVm`
  binds to `KvmVm` on linux/x86_64. The boot setup is the pure, **unit-tested**
  `kvm::x86_boot` (7 tests; compiles on every host); the ioctl glue compiles on
  linux/x86_64.
- ✅ **Read-completion closed in the seam.** `step()` now always yields a *decoded*
  `Mmio`/`Io` (HVF decodes its data-abort ESR into the same form KVM gets from the
  kernel), and `HypervisorVcpu::complete_read(value)` delivers a load result
  natively: KVM fills the `kvm_run` data buffer (kernel finishes on re-entry); HVF
  writes the destination register + advances PC. So the (forthcoming) unified run
  loop is one body — `step` → dispatch `Mmio`/`Io` to the `vmm` devices →
  `complete_read` on a read — across both backends. (HVF decode unit-tested;
  stores self-complete in `step`.) Remaining: write that unified run loop against
  the `vmm` devices + drive a live boot through the backend (vs. the spike).
- ⏳ `kvm::KvmVm` (arm64) — on an aarch64 KVM host the *whole* `vmm` device model
  reuses unchanged behind the seam.
- ⏳ `whp::WhpVm` — Windows, later.

### Cross-architecture note (KVM reuse)

KVM runs **same-architecture** guests only. The `vmm` device model is arm64
(arm64 `Image`, FDT, PL011, GICv3), so it reuses **unchanged** under KVM only on
an **aarch64 KVM host** — there the KVM backend is just the seam's ioctl glue
(create VM/vgic-v3/vcpu, `KVM_RUN` → `VcpuExit::Mmio` → the same devices,
`KVM_IRQ_LINE` for virtio). On x86_64 KVM the *virtqueue logic* still reuses, but
the boot (boot_params/long-mode), console (16550 PIO), and interrupt controller
(IOAPIC + PIT) are a separate x86 device path — now **live-proven to userspace**
on an x86_64 host (`spikes/kvm-x86-boot/` boots a stock `bzImage` to PID 1 on
`/dev/kvm`). The clean whole-`vmm` reuse (the arm64 device model unchanged behind
the seam) wants an aarch64 KVM box, but the x86 backend stands on its own proof.

## Alternatives considered

- **`dyn VmBackend` everywhere.** Rejected for the hot path (vtable on `step()`),
  and the existing product `VmBackend` trait is too high-level (it speaks VM
  lifecycle, not vCPU registers/exits). The seam is deliberately separate and
  lower.
- **A backend per (arch × hypervisor) with no shared device model.** Rejected —
  that is the lock-in the design exists to avoid; it duplicates virtio/console.

## Consequences

- New code to add a hypervisor = implement `HypervisorVm` + `HypervisorVcpu`
  (+ a `VcpuHandle`); the run loop and device model are untouched.
- The product `VmBackend` impls (`AnyBackend`) for HVF/KVM become thin shells
  over `vmm` + the seam.
- A single cross-backend snapshot pipeline is a natural extension (add
  capture/restore to the vCPU/VM traits) — deferred until the run loop migration.
