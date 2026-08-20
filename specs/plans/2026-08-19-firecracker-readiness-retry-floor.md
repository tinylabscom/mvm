# Firecracker readiness retry floor

Backing: shipped-source
Validation: the one-attempt CONNECT seam and the bounded readiness loop
this plan describes, plus the launch-sample medians it is measured against.

Issue #2574's current Linux/KVM baseline is a 291.4 ms prepared-cold dispatch
median against a 200 ms budget. After the console-volume and process-spawn
fixes, the remaining gap matches a nested retry cadence: the Firecracker boot
loop has its own 1/2/4 ms bounded backoff, but every probe calls the general
RPC connector, whose first transient retry sleeps 100 ms.

## Scope

- [x] Add a one-attempt CONNECT seam that preserves the strict Firecracker
      acknowledgement parser without the general reconnect cadence.
- [x] Make the bounded Firecracker boot-readiness loop use one attempt per
      probe; keep ordinary RPC callers on the resilient multi-attempt API.
- [x] Prove the one-attempt seam does not charge the 100 ms reconnect delay and
      retain the existing restart-race tests for the general connector.
- [x] Run the required 2-warm-up + 20-sample prepared-cold lane on the
      established Linux/KVM host and pass the 200/250/300 ms matrix gate.
- [x] Run formatting, workspace tests/checks, Clippy, and gated Linux checks.
- [x] Publish the measured host/storage-labelled row and update delivery and
      refactor status.
- [x] Open and queue the closing PR.
