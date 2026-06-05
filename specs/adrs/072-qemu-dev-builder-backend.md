# ADR 072 - QEMU as the dev/builder backend; Firecracker stays the production runtime

**Status**: Proposed
**Date**: 2026-06-05
**Cross-refs**: ADR-001 (Firecracker-only *execution* — the production runtime path), ADR-002 (security posture / per-backend tier matrix), ADR-055 (passt/gvproxy virtio-net), ADR-066 §1 (name by role, front with a trait, hide impls), ADR-068 (Stage 0 dispatches through the `BuilderVm` trait), Plan 98 (`98-vz-builder-vm.md` — builder-backend selection libkrun/vz). Planning input: Plan 164 (multi-arch embed — surfaced the Linux provisioning pain that motivated this) + Plan 166 (this ADR's implementation).

## Context

On Linux, two distinct VM roles are both pinned to KVM-only VMMs:

- **The dev/builder substrate** — the builder VM that runs `nix build` (and the `mvmctl dev` shell). Today this is **libkrun** (the Plan 98 default on Linux), which on Linux uses `/dev/kvm`.
- **The workload runtime** — where tenant code actually runs. This is **Firecracker** (ADR-001), which requires `/dev/kvm` by design (the microVM is the security boundary).

Three problems fall out of pinning the *dev/builder* role to a KVM-only, hard-to-provision VMM:

1. **No-KVM hosts can't dev at all.** CI runners without nested virt, nested VMs, and restricted containers have no `/dev/kvm`, so neither libkrun nor Firecracker runs — the whole build/dev loop is unavailable, not just the (correctly KVM-gated) production runtime.
2. **libkrun is painful to provision on Linux.** It is not packaged on Debian/Ubuntu; bringing it up means building `libkrun` + `libkrunfw` from source (the latter compiles a kernel), installing `lld`/`clang`, and chasing `lib64` linker paths. Bringing up the Plan 164 x86_64 box took hours for exactly this.
3. **passt friction.** The Linux libkrun path needs passt (ADR-055), which self-sandboxes and stumbles on root priv-drop (`getpwnam: Permission denied`) — more setup surface for what is only a *dev* substrate.

Meanwhile the `VmBackend`/`AnyBackend` dispatch already supports many VMMs behind a trait (Firecracker, libkrun, Vz, Cloud Hypervisor, Apple Container, Docker, a microvm.nix runner, mock), `AnyBackend::auto_select` already favors Firecracker whenever `/dev/kvm` is present, and the builder side has its own `BuilderBackendChoice{Libkrun, Vz}` (Plan 98) fronting the `BuilderVm` trait (ADR-068). Adding a VMM is an impl, not a new pattern.

QEMU is the obvious fit for the *dev/builder* role: it is packaged everywhere (`apt`/`dnf`/`brew`), uses KVM when `/dev/kvm` is present (fast) and falls back to TCG software emulation when it is not (slow, but it *works anywhere*), needs no passt (user-mode `-netdev user`/slirp is zero-config), and can even emulate the other arch for cross-arch dev/test.

## Decision

**Add QEMU as a dev/builder-tier backend. Firecracker remains the sole production workload runtime — `/dev/kvm`-gated, and favored whenever KVM is present. QEMU never ships as a production runtime.**

**Platform scope: QEMU is the *Linux* dev/builder backend.** On macOS the built-in equivalent already exists — **Vz** (Apple Virtualization.framework ships with the OS, runs on Hypervisor.framework with no `/dev/kvm`, and is the macOS-26+ builder default with no third-party install; CLAUDE.md "Builder backend selection"). So the apt-vs-build-from-source portability win that motivates QEMU is a Linux concern; macOS uses Vz. The per-OS story:

- **macOS** → Vz (built-in) for dev/builder.
- **Linux** → QEMU (apt-installable) for dev/builder; Firecracker (KVM) for the production runtime.
- libkrun becomes optional/legacy on both (from-source pain on Linux; Vz supersedes it on macOS).

**Sibling gap — the builder VM needs networking on *both* VMMs.** The Vz *builder* VM is configured `network: None` today, so a cold `nix build` on it fails with the same "Could not resolve github.com" the Linux libkrun+passt path hit (masked only by libkrun-fallback in auto-detect; the Vz dev/workload VM already uses gvproxy). So the symmetric work is: **Linux = QEMU + slirp** (this ADR), **macOS = wire the Vz builder to gvproxy** (a separate, parallel task — *not* QEMU on macOS).

Two insertion points, mirroring the two roles:

1. **Builder VM** — add `Qemu` to `BuilderBackendChoice` (alongside `Libkrun`, `Vz`) implementing the `BuilderVm` trait (`run_build` + `run_stage0`, ADR-068). QEMU becomes the portable, trivially-provisioned Linux builder: KVM-accelerated where available, TCG where not.
2. **Dev/test workload runtime** — add a real `Qemu(QemuBackend)` variant to `AnyBackend` (replacing the vestigial `from_hypervisor("qemu") → MicrovmNix` alias) so a workload can be *run for dev/test* on a no-KVM host. This is a **dev tier only** — it is outside the ADR-002 security claims and is never selected for production.

### Production favors Firecracker — non-negotiable

- `AnyBackend::auto_select` keeps **Firecracker at Tier 1** whenever `platform::supports_native_runner()` (native Linux `/dev/kvm`) is true. QEMU is selected only when (a) there is no `/dev/kvm` *and* the caller is in a dev/test context, or (b) it is explicitly requested (`--hypervisor qemu` / `--builder qemu`).
- The **`--prod` admission gate (in mvmd, not mvm)** refuses QEMU outright: production requires an admitted Firecracker launch on real KVM. A `--prod` run on a no-KVM host fails closed with "Firecracker requires /dev/kvm" — it does **not** silently fall back to QEMU.
- Firecracker's `/dev/kvm` requirement becomes an explicit, fail-closed probe with a clear hint (use a KVM host for production, or the QEMU dev backend for local iteration) rather than an opaque spawn error.

### Networking

The QEMU dev backend defaults to **user-mode networking** (`-netdev user`, slirp) — zero-config, no passt/gvproxy, no root priv-drop. passt/`-netdev` socket parity with the Firecracker path (ADR-055) is an optional follow-on for dev that wants closer-to-prod network behavior, not the default.

### Security framing

QEMU is a **dev tier**, classified like the builder VM (ADR-002 out-of-scope for the hardened workload claims):

- **KVM-backed QEMU → Tier 2** (`tier2-fast-local`): real hardware virtualization, but unaudited against ADR-002.
- **TCG QEMU → Tier 3** (`tier3-fallback`): software emulation, no isolation guarantees; `mvmctl up`/`doctor` emit the loud Tier-3 banner already used for the Docker fallback.

Neither tier is ever promoted to production. The security claims (1–14) remain Firecracker/libkrun-specific; QEMU adds no claims and removes none.

## Consequences

- **Dev works everywhere.** A laptop, CI runner, or nested VM with no `/dev/kvm` can run the full build loop (TCG) and dev/test workloads — the production runtime stays correctly gated.
- **Linux provisioning collapses to a package install.** `apt install qemu-system-x86 qemu-utils` replaces libkrun-from-source for contributors and CI who only need the dev/builder substrate.
- **No change to the production path or ADR-001.** Firecracker remains the only runtime that executes admitted workloads; ADR-001 governs that path and is untouched. The builder VM already uses a non-Firecracker VMM (libkrun), so a QEMU builder is consistent, not novel.
- **One more backend to maintain** — QEMU argv/console(serial-or-vsock)/networking/lifecycle behind the existing trait. Bounded, but real.
- **TCG is slow.** Heavy nix builds under pure emulation are painful; the rule is KVM-where-present, TCG-only-as-fallback, with a loud "running unaccelerated" warning so the slowness is never a surprise.
- **libkrun stays supported** as a Linux builder option; QEMU becomes the recommended default for portability + provisioning ease (the default-flip is decided in Plan 166, behind doctor visibility).

## Alternatives considered

- **Keep libkrun-only on Linux.** Rejected: leaves no-KVM hosts unable to dev and keeps the from-source provisioning tax.
- **QEMU as a production runtime too.** Rejected: forks the security story (TCG has no isolation; KVM-QEMU is unaudited vs ADR-002) and contradicts ADR-001. QEMU is dev/test only; production favors Firecracker.
- **Reuse the existing `MicrovmNix` ("qemu") path.** Rejected as the primary mechanism: it boots via a microvm.nix runner script, not a directly-driven QEMU process, so it can't offer the KVM/TCG portability or the zero-config dev networking. Plan 166 retires the `"qemu" → MicrovmNix` alias in favor of the real backend.
