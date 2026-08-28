---
title: CI-enforced security claims
description: The security claims that must stay backed by tests and documentation.
---

The public security model is claim-gated. A claim should be presented as a
guarantee only when implementation, tests, and docs agree.

This page mirrors the claims table in
[ADR-001](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/001-microvm-security-posture.md).
**That table is the source of truth**, not this page: it is machine-checked,
so a claim whose named witness stops existing fails the build. When the two
disagree, the ADR is right and this page is stale — please fix it.

## Current claim set

Each numbered claim is backed by a test or a CI workflow gate.

| # | Claim | Category |
| --- | --- | --- |
| 1 | No host-filesystem access from a guest beyond explicit shares. | Guest confinement |
| 2 | No guest binary can elevate to uid 0. | Guest confinement |
| 3 | A tampered rootfs ext4 fails to boot, on the block+ext4 backends. | Verified boot |
| 4 | A production-safe run cannot invoke DevOnly guest-agent verbs. | Guest confinement |
| 5 | Vsock framing, supervisor-config JSON, and the userspace datapath's guest-facing ingress are fuzzed. | Interface hardening |
| 6 | The pre-built dev image is hash-verified. | Supply chain |
| 7 | Cargo dependencies are audited nightly and on every release tag. | Supply chain |
| 8 | Every workload runs from a signed, audited `ExecutionPlan`. | Admission and audit |
| 9 | Every published bundle is content-addressed, key_id-pinned, and re-verified at fetch and at admit time. | Supply chain |
| 10 | No untrusted workload reaches the network unless explicitly admitted by policy. | Data containment |
| 11 | Every application-dependency volume is hash-locked, attestation-checked, CVE-scanned, SBOM-enumerated, and bound to the workload's audit chain. | Supply chain (app layer) |
| 12 | Every host-side broker service is bound to a signed `ExecutionPlan.services` binding, enforced before handler dispatch, and audited. | Admission and audit |
| 13 | No raw secret value crosses the broker channel. | Data containment |
| 14 | Every OCI image admission records provenance in the chain-signed audit log. | Supply chain |
| 15 | A sealed production microVM has no shell, no DevOnly guest-agent verbs, and no PTY. | Guest confinement |

## Preview claims

Three further claims have machine-checked witnesses but have not been promoted
into ADR-001's numbered prose. Treat them as preview: the witnesses run, but
the guarantee is narrower than a numbered claim, and each carries a limits note
in the ADR that you should read before relying on it.

| # | Claim | Why it is still preview |
| --- | --- | --- |
| 16 | Egress substitution keeps a raw secret off the guest — bound-only, with no value in the audit log. | Promotion is a pending maintainer decision. |
| 17 | Workload stdin is grant-gated, single-writer, secret-scanned across frames, and every refusal is audited. | The secret scan matches a length and a rolling hash, not an identity; encoding, derivation, or a window-straddling split defeat it. |
| 18 | A workload's resource consumption is bounded at admission, and bound at spawn where the host has a mechanism. | Admission bounding holds everywhere. CPU is enforced on Linux (a systemd transient scope) and on the in-house HVF VMM (in-process, from the vCPU threads' Mach CPU time), and stays declared-only on libkrun. Wall clock is enforced only where a supervisor process holds the plan — libkrun and HVF — and is absent on Firecracker and QEMU. A same-identity `restore` deliberately re-arms neither, since it does not inherit the parent's plan. |

## What is out of scope

ADR-001 names three explicit non-goals, so no claim above should be read as
covering them:

- A malicious **host**. mvm trusts the host with the hypervisor and the private
  build keys.
- **Multi-tenant guests.** One guest is one workload.
- **Hardware-backed key attestation against a malicious host.** An opt-in TPM2
  provider ships and its quotes are a real host-measured attestation input, but
  the host still owns the TPM and the launch material, so a compromised host
  remains out of scope.

## How to use this page

When writing docs, link strong claims to the [Security claim ledger](/security/claim-ledger/)
or [Matryoshka model](/security/matryoshka/). If the behavior is backend-specific,
name the backend — the [per-backend tier matrix](/security/matryoshka/#per-backend-tier-matrix)
is where which-claims-hold-where is recorded.

## What not to claim

- Do not claim the dev/test QEMU backend carries the same claims as Firecracker (claim 3 partial; Tier 2 dev/test only, and deliberately outside claim 10's egress enforcement).
- Do not claim secret non-leakage for manual file mounts.
- Do not claim cold-start numbers without a published benchmark.
- Do not imply Windows local runtime support is shipped.
- Do not describe claims 16, 17, or 18 as enforced without their limits.
