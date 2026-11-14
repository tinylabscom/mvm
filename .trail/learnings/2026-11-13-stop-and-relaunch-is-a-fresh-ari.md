---
title: "Stop and relaunch is a fresh plan, and keep the shared release binary until the last beat runs"
author: Ari
date: 2026-11-13
branch: docs/factory-edge-witness
cost: { minutes: 40 }
id: l-a55a5099
scope: repo
status: active
src: agent
touches:
  - specs/contracts/host-interface-distributed-execution.md
---

## Decided
Beat 5 is shown as an explicit stop followed by a fresh launch under a new name. The stopped workload's session seals and no supervisor remains; the replacement gets a new plan and session and inherits none of the stopped workload's denials. It is not hot replacement and hands over no state.
In the code: mvmctl run -d --image curlimages/curl:8.21.0 --hypervisor hvf --name fe-suspect --allow-host api.github.com:443 -- sh -c '...; sleep 600'; mvmctl machine stop fe-suspect --yes; mvmctl run ... --name fe-replacement; then mvmctl explain <name> --json and mvmctl trust audit verify. Spec text: specs/contracts/host-interface-distributed-execution.md.

## Tried and ruled out
Telling the peer session it could delete the shared rc.2 install once the first beats were done: beat 5 still needed that binary, so it cost a reinstall and a round of messages. A reinstall with no prewarm worked and reused the isolated MVM_HOME cache.

## Watch out
The same refused request can appear in explain as a refused DNS lookup or as a refused host:port connection depending on the path, so a script should not assert one form. Name collisions: a machine name is reused by explain's name lookup, so give each run its own name.
