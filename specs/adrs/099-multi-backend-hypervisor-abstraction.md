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
- ⏳ Migrate the `hvf::kernel_boot` run loop onto the seam (drive `step()` →
  dispatch `VcpuExit` to the `vmm` devices) so it is backend-generic; the inline
  `sys` calls in `kernel_boot` collapse into `HvfVm`/`HvfVcpu`.
- ⏳ `kvm::KvmVm` — the Linux backend (`kvm-ioctls`/`kvm-bindings`). KVM is
  *simpler* than HVF: the kernel decodes MMIO (`VcpuExit::Mmio`, no ESR), and
  PSCI + the arch timer are in-kernel.
- ⏳ `whp::WhpVm` — Windows, later.

### Cross-architecture note (KVM reuse)

KVM runs **same-architecture** guests only. The `vmm` device model is arm64
(arm64 `Image`, FDT, PL011, GICv3), so it reuses **unchanged** under KVM only on
an **aarch64 KVM host** — there the KVM backend is just the seam's ioctl glue
(create VM/vgic-v3/vcpu, `KVM_RUN` → `VcpuExit::Mmio` → the same devices,
`KVM_IRQ_LINE` for virtio). On x86_64 KVM the *virtqueue logic* still reuses, but
the boot (boot_params/long-mode), console (16550 PIO), and interrupt controller
(IOAPIC) are a separate x86 device path. KVM itself is validated live on an
x86_64 host (a `kvm-ioctls` guest ran on `/dev/kvm` and the host captured its
serial output); the clean whole-`vmm` reuse proof wants an aarch64 KVM box.

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
