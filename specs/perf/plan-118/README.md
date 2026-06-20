# Plan 118 Firecracker Bench Proof

Captured on 2026-06-20 on the remote Linux/KVM Firecracker host.

These reports use `readiness_boundary = "firecracker-pid"` because the
current Linux proof image boots under Firecracker but does not expose
the guest-agent ping endpoint. The host descriptor includes this
boundary so these baselines do not compare against guest-agent-ready
libkrun/Vz reports.

Reports:

- `microvm-launch-firecracker.json`: one cold launch, P50
  `total_ready_ms = 1899.851577`.
- `microvm-launch-firecracker-gated.json`: one cold launch rerun
  against the committed baseline, P50 `total_ready_ms = 1590.731061`;
  baseline gate passed at `-16.27%`.
- `microvm-launch-firecracker-warm-pool.json`: one launch with
  `--warm-pool-size 1`, P50 `total_ready_ms = 803.596724`; this is
  `49.48%` faster than the gated cold run.
- `microvm-launch-firecracker-concurrent.json`: concurrency 2,
  P95 `total_ready_ms = 1273.05340545`.
- `microvm-launch-firecracker-concurrent-gated.json`: concurrency 2
  rerun against the committed baseline, P95
  `total_ready_ms = 978.58636765`; baseline gate passed at `-23.13%`.
- `microvm-density-firecracker.json`: count 2, total PSS
  `138852352` bytes, per-instance PSS `69426176` bytes.
- `microvm-density-firecracker-gated.json`: count 2 rerun against the
  committed density baseline, total PSS `139343872` bytes,
  per-instance PSS `69671936` bytes; baseline gate passed at `+0.35%`.

Cleanup proof: after launch/concurrency/density report capture,
`pgrep -af "mvm-bench-fc|mvm-density-fc"` returned no matching VM
processes other than the `pgrep` command itself.
