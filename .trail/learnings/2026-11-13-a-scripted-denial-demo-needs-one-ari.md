---
title: "A scripted denial demo needs one approved destination, or the host records nothing"
author: Ari
date: 2026-11-13
branch: docs/factory-edge-witness
cost: { minutes: 120 }
id: l-1011c2d1
scope: repo
status: active
src: agent
touches:
  - specs/contracts/host-interface-distributed-execution.md
---

## Decided
The factory-edge denial beat uses a workload granted one real destination that then requests a different one. That request is refused by the host, recorded as a denial, and readable afterwards through the explain path. Witnessed on the demo Mac with the rc.2 release binary: one recorded denial for the granted-elsewhere workload, none for two ungranted workloads running alongside it.
In the code: mvmctl run --image curlimages/curl:8.21.0 --hypervisor hvf --allow-host api.github.com:443 -- sh -c 'curl -sS https://example.com/'; then mvmctl explain <name> --json (calls mvm_client::explain::explain_local_run) and mvmctl trust audit verify. Spec text is in specs/contracts/host-interface-distributed-execution.md.

## Tried and ruled out
A workload with no egress grant at all: curl fails inside the guest (exit 6 for a hostname, exit 7 for a literal address) before anything reaches the host endpoint, so egress_denials stays empty and nothing is recorded. It looks like a denial to the person watching but is not host evidence. Same for a documentation-range IP literal.

## Watch out
Studio's own readback, stop and fresh launch, and the real tasks were not run; only the CLI path was. It was a manual run, not a CI lane. The Mac was swap-exhausted until other sessions paused builds; check load before booting a builder VM.
