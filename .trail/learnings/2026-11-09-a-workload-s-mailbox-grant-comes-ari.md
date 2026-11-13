---
title: "A workload's mailbox grant comes from both a run flag and the workload definition"
author: Ari
date: 2026-11-09
branch: main
cost: { minutes: 1, tokens: 0 }
id: l-83e069cf
scope: repo
status: active
src: agent
touches:
  - crates/mvm-core/src/plan/synthesis.rs
  - crates/mvm-contract/src/protocol/mailbox.rs
  - crates/mvm-hostd/src/mailbox_service.rs
---

## Decided
The signed plan's mailbox grant is minted by plan synthesis from two sources combined: a flag on `machine run` and a declaration in the workload definition. The owner chose both over either alone, with the demo about a week out.

## Tried and ruled out
- Flag only: smallest path to a booted-guest witness, but a workload could not declare its own mailbox.
- Workload declaration only: cleaner, but touches the compiler, the IR and the SDKs; thought unlikely to fit the demo window on its own.
- Stopping at the simulated local-socket demo: rejected, since the issue asks for delivery verified end to end.

## Watch out
A launch with neither source carries no grant and must bind no guest mailbox port. The host holds the sealing and signing keys; the guest never sees them.

In the code: plan synthesis in `crates/mvm-core/src/plan/synthesis.rs`; grant type in `crates/mvm-contract/src/protocol/mailbox.rs`; launch entry `serve_granted_guest` in `crates/mvm-hostd/src/mailbox_service.rs`.
