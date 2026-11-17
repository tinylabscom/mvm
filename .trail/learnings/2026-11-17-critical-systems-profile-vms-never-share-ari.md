---
title: "Critical-systems profile: VMs never share memory, the controller is configurable, and the host interface is how launches reach any host"
author: Ari
date: 2026-11-17
branch: main
cost: { minutes: 1, tokens: 1992 }
id: l-269b9022
scope: repo
status: active
src: agent
touches:
  - specs/contracts/host-interface-distributed-execution.md
  - specs/adrs/062-workload-actor-lifecycle-and-causal-evidence.md
---

## Decided
- The critical-systems profile keeps VMs truly isolated: no memory page is ever mapped into two VMs. "Only the leader writes, others read" must be built without breaking the vsock-only guest data path. A plan may declare memory for the host to reserve; that is acceptable. Why: Ari said vsock exists to keep VMs isolated and an exception defeats it.
- Every piece of the profile is configurable, not fixed: the controller may be a small host process OR a VM whose only privilege is a mailbox grant to request launches (including on other hosts). The host interface admits those requests against plans signed in advance.
- The host interface design is the launch-anywhere seam and any critical-systems design must build on it, not beside it.
- All three substrates are in scope: Linux with KVM, mvm's own VMM, and a third-party hypervisor. An ESP32 need not host a VM, but its backend must map to the same ideas (plan, admission, mailbox, supervision, evidence). Design is fail-first.

## Tried and ruled out
- A host-owned region mapped writable into one VM and read-only into named reader VMs, as an explicit exception to the vsock-only rule. Ruled out by Ari: it breaks isolation between VMs. Do not propose cross-VM mappings again.
- Fixing the controller as a host process only. Ruled out: it must also be able to be a VM with mailbox launch privileges.

## Watch out
- A recon summary that cites the host interface only as "where the state model comes from" hides it; name it explicitly as the distributed-launch contract.
- The xtask gates check-single-network-path and check-no-virtio-fs guard the vsock-only path, so any guest memory surface outside vsock trips them by design.

In the code:
- specs/contracts/host-interface-distributed-execution.md (issue #5097)
- specs/adrs/062-workload-actor-lifecycle-and-causal-evidence.md (issue #5544)
