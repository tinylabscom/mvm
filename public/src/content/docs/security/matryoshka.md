---
title: "The Matryoshka model: how mvm isolates untrusted code"
description: "mvm runs untrusted Linux workloads in microVMs. This page explains the five trust layers, the seven CI-enforced security claims, and which claims hold for each backend."
---

mvm's job is to let you run **untrusted code** — third-party software, AI-generated scripts, CI runners, sandbox workloads — and trust the isolation. This page explains the security model in one diagram and one matrix.

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
│ L1 — Host + hypervisor (KVM / Apple VZ / HVF)             │
└───────────────────────────────────────────────────────────┘
```

Each layer trusts only the layer **below** it. An attacker has to break through every boundary above to reach the host. A failure in any one layer is bounded — the layer below still enforces its own contract.

This pattern (sometimes called the *matryoshka* model after the nested Russian dolls) is the same defense-in-depth used across the production microVM / hardened-isolation ecosystem. mvm's adaptation is that **L5 is enforced inside the guest** — even a guest-kernel compromise doesn't give arbitrary access to other in-guest services. See [ADR-002](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/002-microvm-security-posture.md) for the full decision record.

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
| **Firecracker** (Linux + KVM) | ✅ | ✅ | ✅ | ✅ | ✅ | **Tier 1** — full ADR-002. All seven claims hold. |
| **Apple Container** (macOS 26+ Apple Silicon) | ✅ | ✅ | ⚠️ | ✅ | ✅ | Tier 2 — claim 3 (verified boot) is partial. Other six claims hold. |
| **libkrun** (Linux KVM, macOS Apple Silicon HVF) | ✅ | ✅ | ⚠️ | ✅ | ✅ | Tier 2 — same as Apple Container. |
| **Docker** (any host with Docker) | ❌ | ❌ | ❌ | ✅ | ✅ | **Tier 3** — claims 1, 2, 3 do **not** hold. L1–L3 collapse to the host kernel. |
| **microvm.nix** (QEMU + KVM) | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | Tier 2 — QEMU's larger device model raises L2 audit cost. |

✅ = layer fully enforced.  ⚠️ = layer partial (named exception).  ❌ = layer collapsed (claim does not apply).

### Tier 3 (Docker) is convenience, not isolation

mvm's Docker backend exists so you can run a workload in a non-virt environment (e.g., a CI host without `/dev/kvm`, a developer laptop without nested virt). It's **not** a microVM. The isolation comes from the Linux kernel's namespace and cgroup machinery, which is *shared with the host kernel*.

In 2024–2025 the container ecosystem produced seven CVEs (Leaky Vessels, NVIDIAScape, runc race conditions, Buildah mount, Docker Desktop priv-esc, runc masked-path, runc `/dev/console`) that all yielded **host escape** from inside a container. None of those matter inside a microVM — the guest kernel is isolated by hardware. They all matter inside a Docker container.

If `mvmctl` auto-selects Tier 3 because no microVM-capable backend is available, the CLI prints a banner naming the dropped claims and the recent CVEs. You can suppress the banner once you've acknowledged the tier with:

```sh
export MVM_ACK_DOCKER_TIER=1
```

or in `~/.mvm/config.toml`:

```toml
[security]
ack_docker_tier = true
```

### Choosing a tier

- **Production / untrusted code** → Tier 1. Linux + KVM + Firecracker. No exceptions.
- **macOS dev or CI on Apple Silicon** → Tier 2 (Apple Container or libkrun). Verified boot is the open item.
- **macOS Intel / native Windows / WSL2** → unsupported for local microVM isolation today. WSL2 nested KVM and Hyper-V managed Linux builder support are future backend work.
- **Anywhere else** → Tier 3 (Docker), with the banner caveats.

`mvmctl doctor` reports your current tier on the running host.

## What's not promised

ADR-002 names three explicit non-goals so we don't accidentally commit to defending against them:

- **A malicious host.** mvm trusts the host with the hypervisor and the build keys. If your laptop or your server is compromised, every layer falls.
- **Multi-tenant guests.** One guest = one workload. Sharing a single guest VM between mutually-distrusting tenants is out of scope.
- **Hardware-backed key attestation** (TPM/SEV/etc.) is out of scope for v1.

If your threat model needs any of those, mvm is not the right tool today. ADR-002 documents these limits explicitly.

## See also

- [ADR-002 (full decision record)](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/002-microvm-security-posture.md)
- [Plan 25 (microVM hardening — the implementation sequence for the seven claims)](https://github.com/tinylabscom/mvm/blob/main/specs/plans/25-microvm-hardening.md)
- [Plan 53 (cross-platform roadmap — backend tier discipline)](https://github.com/tinylabscom/mvm/blob/main/specs/plans/53-cross-platform-roadmap.md)
- ["Your container is not a sandbox" (emirb, 2026)](https://emirb.github.io/blog/microvm-2026/) — the post that crystallized the matryoshka framing in the broader microVM ecosystem.
