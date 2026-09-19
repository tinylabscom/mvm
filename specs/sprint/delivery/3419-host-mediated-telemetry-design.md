# Every-VM host-mediated telemetry design

Epic #3419; implementation workstreams #3420–#3426.

Recorded the product contract and delivery plan in
`specs/plans/2026-09-17-host-mediated-telemetry.md`: authenticated encrypted
typed guest telemetry, VM-lifetime host collection independent of the CLI,
bounded non-waiting emission at every stage, explicit loss and source coverage,
and host-only retention/export. Connected the existing secure-fabric telemetry
migration to this focused delivery track.

This is a design delivery, not a runtime implementation or certification.
Every implementation checkbox remains open. Completion requires registered
producer coverage, real-backend witnesses, deterministic saturation/security
tests, memory/latency measurements and normal queued implementation PRs.
