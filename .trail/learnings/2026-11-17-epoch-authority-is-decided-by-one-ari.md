---
title: "Epoch authority is decided by one gate every host service calls, and a failover standby gets a read-only epoch"
author: Ari
date: 2026-11-17
branch: docs/critical-systems-profile
cost: { minutes: 34, tokens: 119254 }
id: l-4a9616b3
scope: repo
status: active
src: agent
touches:
  - specs/adrs/064-critical-systems-profile.md
---

## Decided
- A resident failover standby holds a read-only standby epoch: it may read its unit's state cells and nothing else until the host promotes it. Why: the standby needs an accepted identity to obtain state, and promotion must be one step.
- Whether an epoch may perform an operation is decided in one gate with a default of refusal, the same way every boot goes through one admitted dispatch. Mailbox, outbound-request gate, cell service and broker call it; none compares epochs itself, and a build check enforces that. Why: Ari asked to minimise the checkpoints so a standby epoch is one row in one table, not a second case in every service.
- A warm standby's claim-time handover counts as admission because every value comes from a plan signed with the topology beforehand.
- Exclusive cores confine every unpinned VM and mvm's own host processes to the remaining cores.
- Critical VMs keep their full configured memory and are not parked for idleness.
- Per-write cell audit is an option admission checks against the host budget; the default is a periodic signed digest.
- The CNSA 2.0 suite is hybrid (classical plus post-quantum) for now.
- The resource-overhead report is built before pinning, cells and failover, because those admit against measured figures.

## Tried and ruled out
- Letting each host service decide what a standby epoch may do: every service gains a second case and a mistake means two writers.
- Giving the standby no accepted identity until promotion: keeps one epoch per workload but leaves nothing to authorise its state read.
- Pushing every cell value to the standby: needs a queue and a fall-behind rule. Polling: timer wakeups forever, which costs power on embedded hosts.

## Watch out
- About 33 production sites compare epochs inline with no shared helper, roughly 28 of them in mailbox code, and there are two separate epoch types (mailbox contract and host interface) with different error types. The single gate must unify those first.
- The single-decision-point build checks in xtask (grants projection, exec_secs writer, network path) are the model for enforcing the gate.

In the code:
- specs/adrs/064-critical-systems-profile.md, issue #5686
- crates/mvm-contract/src/protocol/mailbox.rs and crates/mvm-core/src/host_interface/state.rs (the two epoch types)
- xtask/src/check_single_exec_secs_writer.rs (closest gate pattern)
