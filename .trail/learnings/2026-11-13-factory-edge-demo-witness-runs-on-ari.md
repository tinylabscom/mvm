---
title: "Factory-edge demo witness runs on the demo Mac only after the mission rehearsal, and only when the Mac has memory to spare"
author: Ari
date: 2026-11-13
branch: main
cost: { minutes: 90, tokens: 2763 }
id: l-f3778bb2
scope: repo
status: active
src: agent
touches:
  - specs/contracts/host-interface-distributed-execution.md
---

## Decided
The factory-edge beats 3/4 witness (denied outbound request read back through the client explain path) takes the HVF slot on Ari's Mac AFTER the mission-demo rehearsal, not before. Ari chose that order and later gave the slot to this session explicitly. The run uses its own isolated MVM_HOME, one workload at a time, and the rc binary the rehearsal used. Beats 3/4 stay labelled previews in the spec until the witness is actually observed; no spec text changes before that.
In the code: PR #5396 (specs/contracts/host-interface-distributed-execution.md, 'Proposed factory-edge presentation'). Run recipe verified against rc.2: mvmctl run --image curlimages/curl:8.21.0 --hypervisor hvf -- sh -c 'curl ...' with no --net or --allow-host (default deny), then mvmctl explain <name> --json (mvm_client::explain::explain_local_run) and mvmctl trust audit verify. The rehearsal binary was /tmp/rehearse/bin/mvmctl (v0.28.0-rc.2, MVM_HOME=/tmp/rehearse/home); first launch re-runs bootstrap.

## Tried and ruled out
- Running the witness before the rehearsal: ruled out by Ari, the mission demo has first claim on the Mac.
- Skipping the live witness and presenting 3/4 as previews: kept as the fallback, not the plan.
- Starting the run as soon as the slot was granted: ruled out, the Mac was swap-exhausted (22.1 of 22.5 GB, load about 280; OrbStack and its VM about 9.5 GB, rust-analyzer, ~7 rustc and ~6 cargo from other worktrees). First launch boots a builder VM and would thrash, and any timing would be meaningless.
- Messaging the Kimi and Delta sessions directly: not possible from a Claude session; the only channels were the local claims note and a comment on #5121.

## Watch out
- Peer sessions get renamed mid-day (mvm-36 became cleanup, mvm-63 mailbox-guest, mvm-ec mission-demo); a send to the old name bounces and an idle subscription made under the old name goes stale. Re-run ListAgents first.
- mvm-eb, named as release owner, was never reachable; nobody held the rc.3 decision until Ari said it could be cut after #5442 and #5445 merge. Tagging still needs green main and a completed scheduled Security run.
- Do not kill other sessions' cargo builds to free memory; ask them to pause, or ask Ari to quit OrbStack or reboot.
- A comment on #5121 is an outward write; it needed Ari's explicit allow.
