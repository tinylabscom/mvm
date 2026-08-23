# Network performance evidence

Backing: preview
Validation: `cargo run -p xtask -- network-perf thresholds`

This directory holds machine-readable workload-networking benchmark reports.
Reports are evidence, not portable performance claims: the comparator refuses
to compare different host identities, operating systems, architectures, CPU
models, backends, storage configurations, release profiles, payload matrices,
concurrency matrices, or sample counts.

Each probe writes exactly one strict JSON object of raw observations to stdout:
one positive connect/request latency per sample and concurrent operation, plus
elapsed time, completed bytes or operations, CPU time, peak RSS, and copied
bytes when measurable. The harness computes p50/p95 and throughput itself,
validates the complete matrix, and only then writes the report:

```text
cargo run -p xtask -- network-perf run-probe \
  --backend host-loopback \
  --output specs/benchmarks/network/<report>.json \
  -- <probe-program> [args...]
```

`host-loopback` is the hermetic default. Firecracker, HVF, libkrun, or any
other live backend is refused unless `MVM_NETWORK_PERF_LIVE=1` is set
explicitly. Firecracker and Linux/KVM probes run in the project builder VM.
HVF probes run on the macOS host under the repository's explicit HVF test
exception. The harness passes `MVM_NETWORK_PERF_BACKEND` and a minimum
`MVM_NETWORK_PERF_SAMPLES=30` to the probe.

The manual `Network performance evidence` workflow records the paired
host-loopback reports on a native Linux x86_64 runner and uploads the three
strict JSON artifacts. This avoids cross-architecture emulation and ensures
the legacy and FlowMux measurements share one ephemeral host. It deliberately
does not turn a failed comparison into a passing check: W2 captures the
pre-deletion measurements, while the final closeout gate must either pass the
published ceilings or name an owner-approved exception.

Validate one report or compare a FlowMux candidate against its pre-deletion L3
baseline:

```text
cargo run -p xtask -- network-perf validate --report <report.json>
cargo run -p xtask -- network-perf compare \
  --baseline <legacy-l3.json> \
  --candidate <flow-mux.json> \
  --output <comparison.json>
```

Every payload/concurrency coordinate must contain opaque TCP, UDP, DNS, and
transformed HTTP cases. Reports include p50/p95 request latency, TCP/HTTP
connect latency, byte or operation throughput, CPU time, peak RSS, and copied
bytes when the probe can measure them without guessing.

The permanent comparison thresholds are emitted by `cargo run -p xtask --
network-perf thresholds`:

- opaque TCP/UDP p50 and p95 latency: candidate at most 1.05× baseline;
- opaque TCP/UDP throughput: candidate at least 0.95× baseline;
- peak RSS for every case: candidate at most 1.10× baseline;
- transformed HTTP p50 and p95 latency: candidate at most 1.10× baseline.

Baseline filenames use
`<implementation>-<os>-<arch>-<backend>-<source-commit>.json`. Never edit a
measurement to make a comparison pass; rerun the labelled probe or record an
owner-approved exception in the owning plan with the raw reports attached.

## Recorded pre-deletion evidence

| Host | Legacy report | FlowMux report | Comparison |
| --- | --- | --- | --- |
| macOS arm64, Apple M4 Max, APFS SSD | `legacy-l3-macos-arm64-host-loopback-a14271e9d8.json` | `flow-mux-macos-arm64-host-loopback-a14271e9d8.json` | `comparison-macos-arm64-host-loopback-a14271e9d8.json` |
| Linux x86_64, AMD EPYC 7763, GitHub-hosted ephemeral SSD | `legacy-l3-linux-x86_64-host-loopback-5d2e4c3c5b.json` | `flow-mux-linux-x86_64-host-loopback-5d2e4c3c5b.json` | `comparison-linux-x86_64-host-loopback-5d2e4c3c5b.json` |

Both comparisons are intentionally recorded as failures: 21 threshold checks
miss on macOS and 28 miss on Linux. The largest gaps are opaque TCP/UDP
latency and throughput; transformed HTTP request latency and per-case RSS no
longer fail after the harness stopped charging each request for a complete
authenticated-session handshake and stopped reusing process-lifetime peak
RSS. No exception is approved or implied by these files. They are the
pre-deletion baseline W8 must improve upon or explicitly resolve.

## Recorded post-deletion candidate

| Host | FlowMux report | Comparison to the matching legacy baseline |
| --- | --- | --- |
| macOS arm64, Apple M4 Max, APFS SSD | `flow-mux-macos-arm64-host-loopback-c22db543f1.json` | `comparison-macos-arm64-host-loopback-c22db543f1.json` |

Credit updates are batched in this candidate. It passes 12 of 32 checks and
misses 20: ten opaque-TCP, six UDP, and four transformed-HTTP connect checks.
The comparison remains a failure and no exception is approved or implied.
