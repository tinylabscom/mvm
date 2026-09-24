# Upstream bug report (draft, ready to file)

File at https://bugzilla.kernel.org — suggested product: Memory Management
(re-triage freely; the failing path is fork-family, likely dup_task_struct /
alloc_pid / dup_mm, observed as ENOMEM).

---

**Summary:** fork/clone/clone3 inside a freshly created PID namespace fails
ENOMEM/EINVAL after ~1-2 children under virtualization (TCG, HVF, KVM;
aarch64 and x86_64), kernels 6.1 through 6.18; bare metal unaffected

**Environment:**
- Host A: Apple Silicon (M4), macOS 26.5 — qemu 11.1.1 (accel tcg and hvf),
  libkrun on Hypervisor.framework
- Host B: GitHub `ubuntu-24.04-arm` runner (Linux 6.8 host) — qemu 8.2.2 (tcg)
- Host C: GitHub `ubuntu-latest` x86_64 runner — qemu 8.2.2 with KVM
  (-cpu host, /dev/kvm)
- Guests: `-machine virt` (aarch64) / `-machine pc` (x86_64), 1-2 vCPU tested,
  512 MiB - 4 GiB RAM, busybox init, virtio-blk root, ext4, no swap

**Affected kernels:** vanilla 6.12.103 / .108 / .110 (all configurations tested,
including full defconfig); Debian 6.1.180, 6.18.15 (unsigned image builds)
**Not affected:** bare metal (per the reporter's production evidence)

**Steps to reproduce:**
1. Boot any affected kernel:
   `qemu-system-aarch64 -machine virt,accel=tcg -cpu max -smp 2 -m 2048 \
     -kernel <Image> -drive file=rootfs.ext4,if=virtio \
     -append "console=ttyAMA0" -nographic`
   (rootfs: any busybox-based init that mounts proc; x86_64 equivalent with
   `-machine pc,accel=kvm -cpu host` also reproduces)
2. In the guest:
   `unshare -Urmp sh -c 'for i in 1 2 3 4 5 6 7 8; do (true) 2>/dev/null || echo -n F; done; echo; echo DONE'`
   → `sh: can't fork: Out of memory` (busybox) on approximately the 2nd fork.
3. Go probe (any Go binary, e.g. `k3s --version`):
   `unshare -Urmp /usr/local/bin/k3s --version`
   → `runtime: failed to create new OS thread (have 2 already; errno=22)`
   `fatal error: newosproc`

**Actual results:** fork(2)/clone(2)/clone3(2) for a task inside a freshly
created PID namespace fail ENOMEM (12) or EINVAL (22) after ~1-2 concurrent
children, with gigabytes of memory free.

**Expected results:** forks succeed.

**Forensics collected in the guest:**
- ENOMEM without reclaim: /proc/vmstat `allocstall_*` all zero, no direct
  reclaim, no OOM; min_free_kbytes=2836, overcommit_memory=0,
  user/admin_reserve_kbytes normal (15587/8192)
- Not memcg: failing processes sit in the v2 root cgroup (implicitly
  memory.max=max); also reproduced with no cgroup filesystem mounted at all
- Not memory-size dependent: the budget is fixed at ~1-2 concurrent children
  across 512 MiB, 2 GiB, and 4 GiB guests
- Not namespace-position dependent: both PID 1 in the new namespace and its
  children see the same ceiling; the parent namespace forks without limit
- No dmesg output, no page-allocation-failure traces
- Two independent userspaces (busybox fork; Go 1.25 clone3) hit the same
  ceiling; errno differs by syscall family (ENOMEM via fork, EINVAL via
  Go's clone3) but the budget is identical
- Kernel-configuration independent: reproduced with a full arm64 defconfig
  (no distro config changes)
- Toolchain independent: nixpkgs gcc 13 and 14, Debian gcc 14.2.0, and
  pristine upstream binutils 2.44 all produce failing kernels
- Cross-hypervisor: TCG (qemu 8.2.2 and 11.1.1, two independent hosts),
  HVF (macOS Hypervisor.framework, via libkrun and via qemu),
  KVM (x86_64, -cpu host) — all reproduce
- Kernel-version range: 6.1.180, 6.12.103, 6.12.108, 6.12.110, 6.18.15 all
  reproduce — long-standing, not a recent regression

**Notes:**
- The trigger shape (a process that is PID 1 in a freshly created PID
  namespace and then clones) is exactly what container runtimes do for every
  pod sandbox. Conventional VM workloads are reportedly unaffected, so there
  may be an additional environmental precondition (guest size/topology, host
  configuration, or something present in larger/general-purpose guests) that
  production VMs satisfy and this minimal guest does not. The minimal guest:
  2 vCPU, 2-4 GiB, busybox init, virtio-blk, ext4 root, no swap; also
  reproduced with cgroup v2 mounted and the workload subtree delegated.
- Reproducer harness (CI matrix, logs, kernels):
  https://github.com/tinylabscom/mvm-images/pull/24 (throwaway branch)
- Found while bringing up Kubernetes (k3s) inside a microVM: every pod
  sandbox is a new PID namespace, so any Go pod init dies at startup.
