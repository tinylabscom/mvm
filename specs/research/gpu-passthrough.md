# GPU Passthrough for MicroVMs

Research date: 2026-02-27

## Summary

GPU passthrough is **not currently possible with Firecracker**. The most viable alternative for mvm would be adding Cloud Hypervisor as a second VMM backend for GPU workloads on Linux hosts.

## Firecracker (current mvm VMM)

Firecracker's minimal device model intentionally omits PCI/PCIe emulation, which is required for VFIO-based GPU passthrough.

- A proof-of-concept existed that attached up to 8 GPUs via VFIO to a single Firecracker VM
- The Firecracker team **paused all GPU/PCIe work** — insufficient resources to pursue it
- Fundamental tension: GPU passthrough requires **pinned memory**, which breaks Firecracker's memory overcommit model and increases boot time — both core design goals
- Tracking issues remain open but stalled:
  - [GPU Support #849](https://github.com/firecracker-microvm/firecracker/issues/849)
  - [Hardware-accelerated inference #1179](https://github.com/firecracker-microvm/firecracker/issues/1179)
  - [GPU/PCIe Discussion #4845](https://github.com/firecracker-microvm/firecracker/discussions/4845)

## The Lima Layer Problem

On macOS, mvm runs Firecracker inside a Lima VM. GPU passthrough would require:

1. The **host** to pass GPU to **Lima VM** (not supported on Apple Silicon — no IOMMU/VFIO)
2. Lima VM to pass GPU to **Firecracker microVM** (double passthrough)

On macOS/Apple Silicon, this is a dead end. On a **Linux host** (no Lima needed), only barrier #2 applies.

## Alternative VMMs

| VMM | GPU Support | Notes |
|-----|------------|-------|
| **Cloud Hypervisor** | VFIO passthrough (works) | Rust-based like Firecracker, ~200ms boot, supports PCI hotplug. Fly.io uses this for GPU Machines. |
| **QEMU/KVM** | VFIO passthrough + virtio-gpu | Most mature option. Larger attack surface. |
| **crosvm** | virtio-gpu (3D accel) | Google's Rust VMM for ChromeOS. Good virtio-gpu but less production use outside Google. |

### Cloud Hypervisor Details

- Written in Rust, shares the [rust-vmm](https://github.com/rust-vmm) crate ecosystem with Firecracker
- Supports VFIO device passthrough, CPU/memory hotplug, live migration
- ~50k lines of Rust vs QEMU's ~2M lines of C
- [Fly.io switched to Cloud Hypervisor for GPU Machines](https://fly.io/blog/wrong-about-gpu/)

## Possible Paths for mvm

1. **Linux-only GPU path** — On Linux hosts (no Lima), use Cloud Hypervisor as the VMM backend for GPU workloads. Shares rust-vmm crates with Firecracker, so architectural gap is smaller than QEMU.

2. **Hybrid approach** — Keep Firecracker for CPU-only microVMs (fast boot, overcommit), add Cloud Hypervisor as a second VMM backend for GPU workloads. This is what Fly.io does.

3. **Wait for Firecracker PCIe** — The PoC worked, but timeline is indefinite.

4. **vsock-based GPU API forwarding** — Expose a GPU API (CUDA/ROCm) over vsock from host to guest instead of hardware passthrough. No production-ready solution exists for Firecracker yet.

## References

- [Firecracker GPU/PCIe Discussion #4845](https://github.com/firecracker-microvm/firecracker/discussions/4845)
- [Firecracker GPU Issue #849](https://github.com/firecracker-microvm/firecracker/issues/849)
- [Firecracker Inference Issue #1179](https://github.com/firecracker-microvm/firecracker/issues/1179)
- [Fly.io: We Were Wrong About GPUs](https://fly.io/blog/wrong-about-gpu/)
- [Cloud Hypervisor GitHub](https://github.com/cloud-hypervisor/cloud-hypervisor)
- [Guide to Cloud Hypervisor in 2026](https://northflank.com/blog/guide-to-cloud-hypervisor)
- [Firecracker vs QEMU (Northflank)](https://northflank.com/blog/firecracker-vs-qemu)
- [Ubuntu GPU Virtualization with QEMU/KVM](https://documentation.ubuntu.com/server/how-to/graphics/gpu-virtualization-with-qemu-kvm/)
