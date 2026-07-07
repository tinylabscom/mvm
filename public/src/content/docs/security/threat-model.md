---
title: Threat model
description: What mvm is designed to protect, and what remains outside the boundary.
---

`mvm` is designed for running code that may be buggy, generated, or actively
hostile while keeping host access explicit and auditable.

## Protected assets

- Host filesystem outside explicit shares.
- Host credentials and local secret stores.
- Build provenance and signed execution plans.
- Runtime audit records.
- Other workloads on the same host.
- Snapshot and cold-mode state.

## Primary attackers

| Attacker | Examples | Expected control |
| --- | --- | --- |
| Malicious guest code | Generated scripts, dependency install hooks, test payloads. | MicroVM isolation, guest profile gates, file/network policy. |
| Confused SDK caller | Accidental broad mount, plaintext secret in args. | Safer examples, claim lint, explicit policy APIs. |
| Malicious artifact source | Mutable OCI tag, unpinned flake input. | Nix pinning, digest verification, signed plans. |
| Network target abuse | Metadata endpoint, DNS rebinding, wrong host. | Deny-by-default policy and future L7 enforcement. |

## Trusted computing base

The host is trusted. The builder VM, selected hypervisor/backend, `mvmctl`,
guest agent, local key material, and Nix inputs form the practical TCB for a
local run.

If the host is compromised, `mvm` cannot protect guest secrets or audit keys
from that host.

## Non-goals

- Defending against a malicious host.
- Running mutually distrusting tenants in one guest.
- Treating the dev/test QEMU backend as a production isolation tier.
- Claiming universal OCI compatibility before digest-pinned ingest is shipped.
- Claiming secret non-leakage for manual guest-visible secret files.

## Security rules for docs and examples

- Label Planned and Preview behavior honestly.
- Prefer Nix-built artifacts and pinned inputs.
- Keep OCI examples digest-pinned when used for production posture.
- Use secret references instead of plaintext credentials.
- Name backend-specific limits for snapshots and cold mode.
- Do not use broad phrases such as "impossible to leak" or "instant boot."
