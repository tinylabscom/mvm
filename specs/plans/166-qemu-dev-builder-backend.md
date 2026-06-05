# Plan 166 — QEMU dev/builder backend (portable dev substrate; Firecracker stays prod)

## Status: Phase 1 DONE + CLI-proven; Task 3.1 (firecracker arch bug) DONE (2026-06-05); Task 1.5 (`run_build`) IMPLEMENTED (host side, awaiting box E2E). Phase 2 (runtime) designed + DEFERRED — fully specified below, ready to implement next session.

**Deferred (with the concrete design captured here):**
- **Phase 2 (runtime)** — `AnyBackend::Qemu` + a `VmBackend` impl + retire the `"qemu"→MicrovmNix` alias. Design below; deferred (a whole new runtime backend needing a workload boot to validate).
- The box stays provisioned (QEMU + virtiofsd installed, repo at `/root/mvm`, `/dev/kvm`) so the next session can implement against it directly.

**Phase 1 complete on the x86_64 box:** `MVM_BUILDER_BACKEND=qemu mvmctl kernel build` drives the full codified path — `QemuBuilderVm::run_stage0` packs the seed + shares as ext4 disks (`mkfs.ext4 -d`, **no root**), boots the stock Debian kernel + initramfs with slirp networking, `stage0-init` (QEMU branch) configures the NIC + mounts + runs `nix build`, the **kernel compiles**, `debugfs rdump` extracts `vmlinux`, and it's **promoted to the cache** (`builder/vmlinux`, 9.7 MiB). Exit 0, no passt, no libkrun, no libkrunfw. Committed: guest side (`2262faf4`), host side + wiring (`5f238362`), + the seed-mountpoint/cleanup fixes.

> Implements **ADR-072**. Adds QEMU as the **Linux** dev/builder-tier backend (KVM-accelerated where present, TCG fallback where not). **macOS already has its built-in equivalent — Vz** (Virtualization.framework, no third-party install); QEMU is *not* for macOS. **Firecracker remains the sole production runtime**, `/dev/kvm`-gated and favored whenever KVM is available. QEMU never ships as a production runtime. Steps use `- [ ]` checkboxes.
>
> **Sibling task (macOS, separate):** the Vz *builder* VM is `network: None` today → cold nix builds fail to resolve hosts (same class of bug as the Linux path). Wire the Vz builder to **gvproxy** (the Vz dev/workload VM already uses it). That's the macOS half of "give the builder VM networking"; this plan is the Linux half (QEMU + slirp).

> **Phase 1 core PROVEN end-to-end on the x86_64 box (2026-06-05) — the validated recipe `qemu_builder.rs` must codify:**
> - **Boot:** `qemu-system-x86_64 -enable-kvm -m 8G -smp 6 -kernel /boot/vmlinuz-$(uname -r) -initrd /boot/initrd.img-$(uname -r) -append "console=ttyS0 root=/dev/vda rw init=/init mvm.backend=qemu panic=-1" -display none -serial file:console.log -monitor none -no-reboot`. The **stock Debian kernel + its initramfs** carry the modular virtio/ext4 drivers, mount the ext4 seed at `/dev/vda`, and exec `/init` (`stage0-init`). No libkrun, no libkrunfw, no custom kernel, no 9p/virtiofs.
> - **Disks (all ext4/virtio-blk, built into the initramfs):** `vda`=seed (nix store + `stage0-init` as `/init`, sized ~25G sparse so the build closure fits), `vdb`=`/work` (repo, target/.git excluded), `vdc`=`/out` (+ `stage0-build.conf`), `vdd`=`/mvm-bins`. `stage0-init` (QEMU branch) mounts vdb/vdc/vdd as ext4; `/nix` is the writable ext4 root directly — **no tmpfs copy, no EMFILE**.
> - **Networking = slirp (the passt-killer):** `-netdev user,id=n0 -device virtio-net-pci,netdev=n0`. slirp's addresses are fixed; `stage0-init` statically sets the (renamed `ensN`) interface to `10.0.2.15/24`, gw `10.0.2.2`, resolv `10.0.2.3` over ioctls. **No DHCP, no passt, no priv-drop, no DNS guessing.**
> - **Result:** `net default_route=true` → nix resolved DNS, downloaded from cache.nixos.org/github, **compiled the kernel (bzImage, 5m42s)**, installed it, and `stage0-init` copied **`vmlinux` (10 MB) to `/out`** + halted clean. This is the complete build the libkrun+passt path could not finish. The guest-side `stage0-init` QEMU branch (Task: shares + slirp net) is **done + committed**; Tasks 1.1/1.3 codify the host-side launcher.

## Why (short)

The dev/builder substrate is pinned to libkrun on Linux — KVM-only and not packaged (build-from-source + passt friction; Plan 164's x86_64 box took hours). QEMU is `apt install` everywhere, uses KVM or TCG, and needs no passt (user-mode net). See ADR-072 for the full rationale and the production-favors-Firecracker invariant.

## Guardrails (do not violate)

- **Production favors Firecracker.** `AnyBackend::auto_select` must keep Firecracker at Tier 1 whenever `platform::supports_native_runner()` is true. QEMU is selected only on no-KVM dev/test, or when explicitly requested.
- **`--prod` refuses QEMU.** The admission gate lives in **mvmd** ([[feedback_prod_gate_lives_in_mvmd]]) — coordinate there; do not add `--prod` policy to mvm. A `--prod` run on a no-KVM host fails closed ("Firecracker requires /dev/kvm"), never silently falls back.
- **QEMU adds no security claims.** Dev tier only; outside ADR-002. KVM→Tier 2, TCG→Tier 3 (loud banner, same as Docker fallback).
- **No VMM lock-in / front with a trait** ([[feedback_no_vmm_lockin_keep_backend_trait]], ADR-066 §1) — QEMU is an impl behind the existing `BuilderVm` / `VmBackend` seams, not a new dispatch pattern.

## Phase 1: QEMU builder VM backend (the clear win)

The builder VM runs `nix build` (and Stage 0). This phase unblocks no-KVM / easy-provision dev builds.

### Task 1.1: `QemuBuilderVm` (the `BuilderVm` impl)
- [ ] New `crates/mvm-build/src/qemu_builder.rs`, parallel to `libkrun_builder.rs`, implementing the `BuilderVm` trait (`run_build` + `run_stage0`, ADR-068). Drives a `qemu-system-<arch>` child process.
- [ ] **KVM detection**: probe `/dev/kvm` (reuse `platform::supports_native_runner()` / a `[ -c /dev/kvm ]` check). Present → `-enable-kvm -cpu host`; absent → TCG (`-cpu max`) **plus a loud `[mvm] QEMU running unaccelerated (TCG) — builds will be slow; no /dev/kvm` warning**.
- [ ] **Networking**: user-mode (`-netdev user,id=net0 -device virtio-net-pci,netdev=net0`). No passt, no gvproxy, no root priv-drop. DNS/DHCP come from slirp; the guest's `nix` reaches `cache.nixos.org` out of the box.
- [ ] **Shares**: `/work`, `/out`, `/mvm-bins` via virtio-9p (`-virtfs local,...,mount_tag=work,...`) or virtiofsd where available. (9p is in-tree QEMU, zero extra daemons — prefer it for the dev tier.)
- [ ] **Console**: serial (`-serial file:<console.log> -append "console=ttyS0 ..."`) so `stage0-init` / `mvm-host-vm-init` diagnostics land in the same `console.log` the libkrun path uses (the panic-watcher in `wait_with_panic_detector_until` reads it).

### Task 1.2: QEMU Stage 0 bootstrap kernel
Stage 0 is chicken-and-egg: it needs a kernel to boot the nix seed that *builds* the real kernel. libkrun gets this free from libkrunfw; QEMU does not.
- [ ] **Source the bootstrap kernel**: prefer the host distro kernel (`/boot/vmlinuz-$(uname -r)`) where readable; else a **hash-pinned minimal kernel download** (parallel to the `NIX_SEED_*` pin in `stage0.rs` — URL + SHA-256, fail-closed). Document the choice in ADR-072's follow-up note.
- [ ] Boot: `qemu-system-x86_64 -kernel <bootstrap-vmlinuz> -append "console=ttyS0 init=/init ..." -fsdev/-virtfs <seed-rootdir>` with `init` = the embedded `stage0-init` (already x86_64 from Plan 164). The seed root is the same `materialize_root_dir` output the libkrun path uses — **no Stage 0 code change**, only a new launcher.
- [ ] Post-Stage-0 `run_build` boots the **kernel Stage 0 just built** (`vmlinux` from `/out`) — no bootstrap-kernel question there.

### Task 1.3: builder-backend selection
- [ ] Add `Qemu` to `BuilderBackendChoice` (`crates/mvm-build/src/builder_backend_select.rs`) + the `--builder qemu` / `MVM_BUILDER_BACKEND=qemu` parse arms + the `into_builder_vm` match (`BuilderBackendChoice::Qemu => Box::new(QemuBuilderVm::new())`).
- [ ] Auto-detect: keep Vz on macOS 26, libkrun elsewhere **for now**; add QEMU as an explicit opt-in. **Default-flip decision** (QEMU as the Linux builder default, given provisioning ease) is a follow-up once it's proven E2E on both arches — call it out, don't silently flip.
- [ ] `mvmctl doctor`: report `builder backend` resolution + the QEMU KVM/TCG mode + an install hint (`apt install qemu-system-x86 qemu-utils`) when QEMU is selected but missing.

### Task 1.4: prove it
- [ ] **x86_64 + KVM** on the Plan 164 Hetzner box (`/dev/kvm` present): `MVM_BUILDER_BACKEND=qemu mvmctl kernel build --builder qemu` boots Stage 0 under QEMU+KVM, `nix build` succeeds, `/out/{vmlinux,rootfs.ext4}` produced. (This is the path that hit passt friction under libkrun — QEMU slirp avoids it.)
- [ ] **No-KVM (TCG)**: same on a host/container with `/dev/kvm` masked — confirm it boots (slowly) and the unaccelerated banner fires.
- [ ] aarch64 (the dev Mac is HVF, not QEMU-relevant; validate aarch64 QEMU+KVM on a Linux aarch64 host or defer with a note).

### Task 1.5: QEMU `run_build` (steady-state builds) — completes the builder

Phase 1 Tasks 1.1–1.4 implement `run_stage0` (the from-source bootstrap that
*produces* the builder VM image). `run_build` is the steady-state path: it
**boots the built builder VM** (the `vmlinux` + `rootfs.ext4` Stage 0 emitted)
and runs a user's `nix build` job. **Design is much simpler than Stage 0**
because the mvm builder kernel has virtio **built-in** (`base.nix`/`default.nix`:
`VIRTIO_BLK/NET/PCI/CONSOLE`, `VIRTIO_FS`, `FUSE_FS`, `EXT4_FS` all `=y`):

Implemented in `qemu_builder::run_build_qemu` (gated behind `builder-vm`,
like its `libkrun_builder` cache-helper deps). Host side complete + unit-tested;
the live build awaits a box E2E run (needs an image-mode QEMU Stage 0 first).

- [x] **Boot directly, no initramfs**: `qemu-system-<arch> -kernel <vmlinux>
  -append "<qemu cmdline> root=/dev/vda ro init=/sbin/mvm-host-vm-init
  mvm.backend=qemu" -drive file=<rootfs.ext4>,if=virtio` — virtio-blk + ext4
  built-in, so the kernel mounts the rootfs and runs PID 1 with no initramfs.
  **Deviation from the sketch: `ro`, not `rw`.** `ro` is libkrun's proven guest
  contract (`builderCmdline` in `nix/images/builder-vm/flake.nix` is `…ro…`) and
  keeps the *shared cached* `rootfs.ext4` pristine across builds; the guest
  writes only to the `/dev/vdb` overlay, the virtio-fs shares, and tmpfs.
- [x] **Shares over virtiofs** (`/usr/lib/qemu/virtiofsd` etc.): one
  `virtiofsd --socket-path=<sock> --shared-dir=<dir> --sandbox none` per share
  (`work`, `out`, `job`, `mvm-bins`) + `-object
  memory-backend-memfd,id=mem,size=<m>,share=on -numa node,memdev=mem -chardev
  socket,…,path=<sock> -device vhost-user-fs-pci,…,tag=<tag>`. The builder
  kernel has `VIRTIO_FS` built-in, so **`mvm-host-vm-init` is UNCHANGED** — it
  mounts the same tags + read-only policy it does under libkrun/Vz. A
  `VirtiofsdGuard` reaps the daemons + sockets on drop; QEMU launches only after
  each socket is ready.
- [x] **Networking = slirp** (`-netdev user`): slirp's built-in DHCP feeds
  `mvm-host-vm-init`'s existing `udhcpc -i eth0` — no static config, no gvproxy,
  no passt. The QEMU cmdline forces `net.ifnames=0` so the NIC comes up `eth0`.
- [x] **Job protocol = the shared one**: reuse `stage_job_dir` (stage `cmd.sh`
  into `/job`) + `finalize_flake_job` / `finalize_install_job` (`/job/result`,
  `/out/result.json`) — identical to `LibkrunBuilderVm`/`VzBuilderVm`, so
  `BuilderArtifacts` is byte-identical regardless of VMM. Mirrors their
  `run_build` shape (validate mounts/job, resolve cached builder image +
  `NixStoreImageLock`, stage the job dir, boot, finalize).
- [ ] **Prove it** (box): an image-mode QEMU Stage 0 first (to get
  `rootfs.ext4`), then `MVM_BUILDER_BACKEND=qemu mvmctl build --flake <example>`
  runs the user build in the QEMU builder VM and produces the workload artifacts.

## Phase 2: QEMU dev/test workload runtime

Lets a workload *run* for dev/test on a no-KVM host. Dev tier only.

### Task 2.1: real `Qemu(QemuBackend)` in `AnyBackend`
- [ ] Add `Qemu(QemuBackend)` to `AnyBackend` (`crates/mvm-backend/src/backend.rs`) with a `qemu.rs` impl. **Retire the vestigial `from_hypervisor("qemu") → MicrovmNix` alias** — `"qemu"` now routes to the real backend.
- [ ] `security_profile` / `tier()`: KVM → `Tier2`, TCG → `Tier3`. Keep the `BackendSecurityProfile.tier` ↔ `AnyBackend::tier()` sync test green.
- [ ] `auto_select`: **Firecracker still wins on `/dev/kvm`**. QEMU is reached only when no native runner *and* a dev/test context (never the silent production default — that stays Firecracker, whose `start()` then surfaces the "Firecracker requires /dev/kvm" error).

### Task 2.2: production gating
- [ ] Firecracker `start()` on Linux: explicit fail-closed `/dev/kvm` probe with the ADR-072 hint (KVM host for prod, or `--hypervisor qemu` for local dev). (image.rs already emits a `[ -c /dev/kvm ]` guard — make the Rust-side selection match.)
- [ ] **mvmd**: extend the `--prod` admission gate to refuse a QEMU-tier backend (Tier 2/3) — production requires an admitted Firecracker launch. Draft in `../mvmd/specs/plans/` + a coordinating note here; do not add `--prod` logic to mvm.
- [ ] `mvmctl up` / `doctor`: Tier-3 (TCG) banner reuses the existing Docker-fallback banner path; Tier-2 (KVM-QEMU) notes "unaudited vs ADR-002".

## Phase 3: provisioning, docs, and the firecracker arch bug

### Task 3.1: firecracker bootstrap arch-download bug (found in Plan 164) — [x] DONE
- [x] On the x86_64 box, `mvmctl dev up` downloaded **`firecracker-v1.14.1-aarch64.tgz`** → `Exec format error`. Root cause: `mvm_core::config::ARCH` was **hardcoded `"aarch64"`** (`config.rs:7`), feeding `firecracker::install()`'s download URL + the firecracker-ci artifact paths. Fixed → `pub const ARCH: &str = std::env::consts::ARCH;` (the arch mvmctl is compiled for == the host it runs on). Verified on the box: the URL is now `firecracker-v1.14.1-x86_64.tgz`. aarch64 hosts unchanged. (The dead Lima-legacy `debootstrap --arch="${ARCH}"` fallback in `download_builder_artifacts.sh.tera` wants Debian names anyway — already broken with "aarch64", no regression.)

### Task 3.2: docs + doctor
- [ ] `mvmctl doctor`: QEMU availability probe + version + KVM/TCG + install hint, alongside the existing per-OS gateway/builder probes.
- [ ] Contributor docs (`public/.../contributing/development.md`): "dev on a no-KVM host" via QEMU; the KVM-vs-TCG speed note; firecracker stays prod-only.
- [ ] `CLAUDE.md` architecture block: add QEMU as the portable dev/builder backend; keep the "Firecracker-only on the runtime path" statement (it's about prod, unchanged).

## Verification
- [ ] x86_64 QEMU+KVM Stage 0 + builder build E2E (Hetzner box) — no passt, no libkrun-from-source.
- [ ] No-KVM TCG build completes (slow) with the unaccelerated banner.
- [ ] `auto_select` unit tests: Firecracker on `/dev/kvm`; QEMU only on no-KVM dev; never QEMU under `--prod`.
- [ ] `from_hypervisor("qemu")` routes to the real `QemuBackend` (not `MicrovmNix`); tier-sync test green; `cargo nextest` + clippy + nightly fmt + `check-spec-numbers`.

## Non-goals
- **QEMU as a production runtime.** Never. Firecracker is the only admitted-workload runtime (ADR-001/072).
- **microvm.nix replacement.** The `MicrovmNix` backend stays for its own use; this plan only retires the misleading `"qemu"` *alias* to it.
- **Dropping libkrun.** libkrun remains a supported Linux/macOS builder backend; QEMU is added, and a default-flip is a separate, evidence-gated decision (Task 1.3).

## Deferred follow-ups
- [ ] passt/`-netdev socket` parity for the QEMU dev backend (closer-to-prod networking for dev that wants it; default stays slirp).
- [ ] virtiofsd (vs 9p) for the QEMU shares where throughput matters.
- [ ] QEMU cross-arch (emulate aarch64 on x86_64 and vice-versa) for one-box multi-arch dev/test — ties to Plan 164.
