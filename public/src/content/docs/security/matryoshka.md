---
title: "The Matryoshka model: how mvm isolates untrusted code"
description: "mvm runs untrusted Linux workloads in microVMs. This page explains the five trust layers, the seven CI-enforced security claims, and which claims hold for each backend."
---

mvm's job is to let you run **untrusted code** — third-party software, AI-generated scripts, CI runners, sandbox workloads — and trust the isolation. This page explains the security model in one diagram and one matrix.

## What you get by default

For the ordinary command — `mvmctl machine run --image ... -- ...` — mvm starts
from a deny-by-default posture. The exact enforcement tier is printed by
`mvmctl doctor` and in launch receipts, but the user-visible contract is:

- **A real microVM boundary:** each workload gets its own guest memory, virtual
  devices, and Linux kernel. A container is never silently substituted.
- **A private filesystem:** the image and the workload's ephemeral writable
  layer are visible inside the guest. Host directories are absent unless you
  explicitly mount them; mounts are a deliberate part of the launch plan.
- **No network by default:** there is no egress until you enable networking and
  admit destinations with `--allow-host`. Inbound access is not implied by an
  outbound rule.
- **No raw host secrets in the guest:** secret-aware egress substitutes
  credentials at the host boundary, so the workload receives only the
  placeholder or response it is authorized to use.
- **An auditable launch decision:** the image, resource limits, mounts, network
  posture, admission profile, and backend are captured in the signed execution
  plan before boot.

These defaults are intentionally stronger than “a VM with a public network.”
They make the safe path the shortest path while keeping explicit escape hatches
visible in the command line and the receipt.

### What mvm defends

mvm is designed to bound an untrusted guest that tries to escape to the host,
read another workload's state, use an undeclared host mount, reach private host
services, or obtain a credential that was not released for its destination.
The guest-to-host control channel is host-brokered and typed; it is not SSH and
does not require an inbound guest listener.

### What mvm does not defend

mvm trusts the host operating system, the selected hypervisor, and the release
or source artifacts used to build it. A compromised host or hypervisor is
outside this boundary. A workload can also misuse a destination, mount, secret,
or capability that its operator explicitly allowed. Multi-tenant sharing inside
one guest and hardware-backed remote attestation are not default guarantees.

### Your responsibility

Use the strictest profile that fits the workload, keep networking disabled when
it is unnecessary, allowlist only the destinations required, prefer read-only
mounts, pin production images by digest, set resource and lifetime limits, and
keep the host patched. The security posture is visible and enforceable, but it
cannot infer whether an explicitly granted capability is safe for your code.

## The five trust layers

```
┌───────────────────────────────────────────────────────────┐
│ L5 — Workload (your untrusted code)                       │
├───────────────────────────────────────────────────────────┤
│ L4 — Guest agent (parses host messages, launches code)    │
├───────────────────────────────────────────────────────────┤
│ L3 — Guest kernel (Linux, ephemeral, isolated)            │
├───────────────────────────────────────────────────────────┤
│ L2 — VMM (Firecracker, Rust, seccomp-jailed)              │
├───────────────────────────────────────────────────────────┤
│ L1 — Host + hypervisor (KVM / HVF)                        │
└───────────────────────────────────────────────────────────┘
```

Each layer trusts only the layer **below** it. An attacker has to break through every boundary above to reach the host. A failure in any one layer is bounded — the layer below still enforces its own contract.

This pattern (sometimes called the *matryoshka* model after the nested Russian dolls) is the same defense-in-depth used across the production microVM / hardened-isolation ecosystem. mvm's adaptation is that **L5 is enforced inside the guest** — even a guest-kernel compromise doesn't give arbitrary access to other in-guest services. See [ADR-001](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md) for the full decision record.

## The seven claims

mvm makes seven CI-enforced security claims. Each one is backed by a continuous-integration check that fails the build if the claim ceases to hold.

| # | Claim | Defends layer | How it's enforced |
|---|---|---|---|
| 1 | No host-fs access from a guest beyond explicit shares | L2 / L5 | Per-service uid + seccomp `standard` default + setpriv bounding-set drop |
| 2 | No guest binary can elevate to uid 0 | L2 / L4 | `setpriv --no-new-privs` in launch path; `/etc/{passwd,group}` are read-only bind-mounts |
| 3 | A tampered rootfs ext4 fails to boot | L3 | dm-verity sidecar + roothash on cmdline + `mvm-verity-init` initramfs |
| 4 | The guest agent does not contain `do_exec` in production builds | L4 | CI symbol-grep on the prod binary; absence is enforced |
| 5 | Vsock framing is fuzzed | L2 / L4 | `cargo-fuzz` targets cover every host↔guest message; `deny_unknown_fields` on every type |
| 6 | Pre-built dev image is hash-verified | supply chain | SHA-256 manifest streamed through the download |
| 7 | Cargo deps are audited on every PR | supply chain | `cargo-deny` + `cargo-audit` jobs; reproducibility double-build |

L1 (host + hypervisor) doesn't carry its own claim — the host is **trusted** by definition. If your host is compromised, every layer falls. Locking down the host (firewall, package hygiene, full-disk encryption) is your responsibility.

## Intent-bound admission profiles

Every workload also goes through a signed admission step before boot. `mvmctl machine run` synthesizes an `ExecutionPlan`, signs it with the host key, checks its validity window and replay nonce, then emits a chain-signed audit entry.

The plan now carries an `admission_profile`: a compact record of the workload's declared intent and the controls selected for that intent:

- intent, for example `vm:boot`, `code:execute`, or `agent:web-research`
- seccomp tier selected for the run
- network, filesystem, egress, and tool policy refs
- secret-release posture (`none`, plan-bound, or attestation-bound)
- audit taxonomy and required labels

This does **not** add a second seccomp implementation or new execution capability inside the sandbox. Runtime syscall filtering still comes from `mvm-security` and the guest `seccomp.json` manifest. The admission profile records the selected tier in the signed plan so the audit chain can prove which security posture the workload was admitted under.

## Per-backend tier matrix

mvm runs on multiple backends. Not all backends carry all seven claims. The tier you actually get depends on which backend mvm picks for your run.

| Backend | L1 | L2 | L3 | L4 | L5 | Tier |
|---|---|---|---|---|---|---|
| **Firecracker** (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | **Tier 1** — full ADR-001. All seven claims hold. |
| **HVF** (macOS 26+ Apple Silicon — auto-default) | ✅ | ✅ | ⚠️ | ✅ | ✅ | Tier 2 — claim 3 (verified boot) partial; `Hypervisor.framework`, vsock-only egress (no guest NIC). The macOS-26 auto-default. |
| **libkrun** (Linux KVM, macOS Apple Silicon HVF) | ✅ | ✅ | ⚠️ | ✅ | ✅ | Tier 2 — same as HVF. |
| **QEMU** (Linux KVM/TCG) | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | Tier 2 — claim 3 partial; QEMU's larger device model raises L2 audit cost. **Dev/test only** (`--hypervisor qemu`; the no-`/dev/kvm` path via TCG software emulation). Never selected by `mvmd`. |

✅ = layer fully enforced.  ⚠️ = layer partial (named exception).  ❌ = layer collapsed (claim does not apply).

### No container fallback

On every default and production path, mvm has **no Tier 3** and no container/Docker fallback. A shared-kernel container is not a microVM: its isolation comes from the host kernel's namespace and cgroup machinery, which is shared with the host. In 2024–2025 the container ecosystem produced multiple CVEs (Leaky Vessels, NVIDIAScape, runc race conditions, Docker Desktop priv-esc, runc masked-path) that yielded **host escape** from inside a container — none of which matter inside a microVM, where the guest kernel is isolated by hardware. If a host has no microVM-capable backend, mvm does not silently drop to a weaker boundary; it fails closed.

The one carve-out is an **explicitly selected dev tier** (ADR-034): `--hypervisor docker` runs the real `mvm-guest-agent` as a container's PID 1 with the real activation contract and RPC surface, so KVM-less dev and CI hosts can exercise workloads against the same code production runs. It is opt-in only (auto-detection never picks it), refused by production admission, labeled Tier 3 shared-kernel everywhere the tier is shown, and carries none of the hardware-isolation claims. It is a development substrate, not a fallback: nothing routes to it by default, by accident, or under production admission.

### Choosing a tier

- **Production / untrusted code** → Tier 1. Linux + KVM + Firecracker. No exceptions.
- **macOS dev or CI on Apple Silicon** → Tier 2 (HVF or libkrun). Verified boot is the open item.
- **Linux dev/test without `/dev/kvm`** → Tier 2 QEMU (`--hypervisor qemu`, TCG software emulation). A real microVM, slower; dev/test only.
- **macOS Intel / native Windows** → unsupported for local microVM isolation today (no container fallback on any default path — only the explicitly selected ADR-034 dev tier). WSL2 with nested `/dev/kvm` is the supported Windows-adjacent libkrun workload path; a Hyper-V managed Linux builder remains future backend work.

`mvmctl doctor` reports your current tier on the running host.

## What's not promised

ADR-001 names three explicit non-goals so we don't accidentally commit to defending against them:

- **A malicious host.** mvm trusts the host with the hypervisor and the build keys. If your laptop or your server is compromised, every layer falls.
- **Multi-tenant guests.** One guest = one workload. Sharing a single guest VM between mutually-distrusting tenants is out of scope.
- **Hardware-backed key attestation** (TPM/SEV/etc.) is out of scope for v1.

If your threat model needs any of those, mvm is not the right tool today. ADR-001 documents these limits explicitly.

## See also

- [ADR-001 (full decision record)](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md)
- [Plan 25 (microVM hardening — the implementation sequence for the seven claims)](https://github.com/tinylabscom/mvm/blob/main/specs/plans/25-microvm-hardening.md)
- [Plan 53 (cross-platform roadmap — backend tier discipline)](https://github.com/tinylabscom/mvm/blob/main/specs/plans/53-cross-platform-roadmap.md)
- ["Your container is not a sandbox" (emirb, 2026)](https://emirb.github.io/blog/microvm-2026/) — the post that crystallized the matryoshka framing in the broader microVM ecosystem.
