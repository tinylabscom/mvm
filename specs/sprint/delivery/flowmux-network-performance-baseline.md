# FlowMux network performance baseline

Backing: shipped-source
Validation: `cargo run -p xtask -- network-perf validate`, `cargo run -p xtask -- network-perf compare`, CI, Network performance evidence workflow

W2 of the FlowMux single-path closeout now has a strict, machine-readable
performance harness before the retired L3 implementation is deleted.
`xtask network-perf` validates a complete opaque TCP, UDP, DNS, and transformed
HTTP payload/concurrency matrix and compares p50/p95 latency, throughput, CPU,
per-case peak RSS, and copies where measurable. It refuses reports whose host,
OS, architecture, CPU, backend, storage, profile, sample count, or matrix do not
match.

The repository records paired pre-deletion reports for Apple M4 Max/macOS
arm64/APFS and AMD EPYC 7763/Linux x86_64/GitHub ephemeral SSD. The hermetic
host-loopback runner is the default; live backend labels require
`MVM_NETWORK_PERF_LIVE=1`. A manual GitHub workflow reproduces the native Linux
x86_64 pair and uploads the strict reports.

The published ceilings are 1.05x opaque latency, 0.95x opaque throughput,
1.10x peak RSS, and 1.10x transformed HTTP latency. The recorded comparisons
currently fail 21 checks on macOS and 28 on Linux, chiefly opaque latency and
throughput. Those failures are evidence, not waivers: no exception is approved,
and the final W8 report must pass or carry an explicit owner-approved measured
exception.
