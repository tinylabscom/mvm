---
title: Capability status
description: The single authoritative table of what mvm ships today, what is in preview, and what is roadmap. Every marketing surface inherits from this page.
---

This page is the source of truth for **capability status** across the product:
backends, host platforms, deployment tiers, and confidential computing. Every
other surface — the landing page, pricing, decks, and docs — must inherit from
this table rather than restating capabilities. A capability may be described
in shipped-product language only when its row here is **Shipped**.

Status vocabulary matches the [security claim ledger](/security/claim-ledger/):

- **Shipped** — in the current release, selectable through the documented CLI
  surface, and backed by tests.
- **Preview** — exists and works, but is gated (access, platform, or feature
  limits must be named wherever it is described).
- **Planned** — roadmap. May appear in forward-looking material only when
  explicitly labeled as such.
- **Removed** — existed in an earlier design and was taken out. Listed here so
  stale references are recognizable as stale.

For *security* claims (what is enforced, with named test witnesses), the
authoritative table is [CI-enforced claims](/security/ci-claims/), which
mirrors the machine-checked ledger in ADR-001. This page covers capability
availability; that page covers enforcement.

## Execution backends (workload runtimes)

| Backend | Status | Notes |
| --- | --- | --- |
| Firecracker | Shipped | The Linux/KVM workload runtime. Primary production backend. |
| libkrun | Shipped | Default workload backend on macOS 13–25 (Apple Silicon, via the `slp/krun` Homebrew packages). |
| HVF (in-house Hypervisor.framework VMM) | Shipped | Default workload backend on macOS 26+ Apple Silicon. No Homebrew prerequisites. |
| QEMU | Shipped | Dev/test substrate only — opt-in, never auto-selected, and never carries untrusted multi-tenant workload. |
| apple-container | Shipped | Opt-in only (`--hypervisor apple-container`): the HVF runner booting Apple's prebuilt container kernel. Auto-detect never selects it. |

All workload backends boot the guest with **no network device** — egress
leaves the guest only over vsock to the host-side policy endpoint. See the
[threat model](/security/threat-model/) and claim 10 in the
[CI-enforced claims](/security/ci-claims/).

## Host platforms

| Platform | Status | Notes |
| --- | --- | --- |
| Linux with `/dev/kvm` | Shipped | Firecracker directly on the host. |
| macOS 13–25 (Apple Silicon) | Shipped | Via libkrun. |
| macOS 26+ (Apple Silicon) | Shipped | Via the in-house HVF VMM. |
| Windows via WSL2 | Shipped | Inside a WSL2 distro with nested KVM — see the [Windows install guide](/install/windows/). |
| Windows native | Planned | Tracked in [mvm#428](https://github.com/tinylabscom/mvm/issues/428). |

## Deployment tiers

| Tier | Status | Notes |
| --- | --- | --- |
| Local (open-source CLI) | Shipped | The `mvmctl` surface on your own machine. Apache-2.0. |
| Hosted Standard | Preview | Firecracker on Linux/KVM fleet infrastructure. Design-partner access only — request access from the landing page. |
| Edge & Private (BYOC) | Planned | The same signed contract, forward-deployed into customer infrastructure. |
| Hosted Confidential | Planned | See confidential computing below. |

## Confidential computing and attestation

| Capability | Status | Notes |
| --- | --- | --- |
| AMD SEV-SNP / Intel TDX execution | Planned | No shipped backend targets a TEE today. |
| Hardware attestation-gated key release | Planned | **Explicitly out of scope of the current runtime** — the threat model names hardware-backed key attestation *against a malicious host* as out of scope. An opt-in TPM2 provider ships as an attestation input, but nothing gates key release on it. No current page, deck, or answer may describe attestation-gated key release in the present tense. |

## Removed

| Capability | Status | Notes |
| --- | --- | --- |
| Lima (macOS host abstraction) | Removed | Removed May 2026. There is no `--lima` flag and no Lima fallback. |
| Apple Virtualization.framework backend | Removed | HVF is the macOS workload backend; a CI gate keeps Virtualization.framework out of the tree. |
| Incus / containerd backends | Never shipped | Named in earlier marketing material; neither has ever been an mvm backend. |

## Rules for writing about capabilities

1. Before a page, deck, or sales answer states a capability, find its row
   here. No row means the claim is not yet allowed — add the row first.
2. **Shipped** rows may use present-tense product language. **Preview** rows
   must name the gate. **Planned** rows must be labeled roadmap. **Removed**
   rows must not be referenced except to say they were removed.
3. When this page disagrees with the code, the code wins — fix this page in
   the same change, the way [CI-enforced claims](/security/ci-claims/) defers
   to the machine-checked ADR-001 table.

Related ledgers: [CI-enforced claims](/security/ci-claims/) (security
enforcement), [security claim ledger](/security/claim-ledger/) (docs claims),
[sandbox parity status](/security/sandbox-parity-status/) (feature parity).
