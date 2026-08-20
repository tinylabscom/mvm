# Firecracker prepared-cold is inside its published budget

The latest #2574 baseline was clean but still red: 291.4 ms dispatch p50
against a 200 ms ceiling. Its remaining ~91 ms gap matched a cadence hidden
inside the readiness probe. Firecracker's boot loop already owned a 60-second
deadline and a 1/2/4 ms bounded backoff, but each probe called the general RPC
connector, which sleeps 100 ms before retrying a transient CONNECT failure.

The connector now exposes one strict attempt using the same bounded
acknowledgement parser. The Firecracker boot loop uses that seam once per probe;
ordinary RPC connections keep the multi-attempt behavior that tolerates
restart races. The remaining poll is a compatibility wait: Firecracker exposes
no stable host event for a guest binding one vsock port. Every pass still
verifies the VMM process identity, and the overall deadline remains bounded.

## Live acceptance

Established Linux/KVM host: Linux 6.8.0-137 x86_64, Intel i7-7700,
Firecracker v1.14.1, rotational md-RAID (`ROTA=1`). Release build at
`b107dfb22c`; `prepared_cold`; 2 discarded warm-ups followed by 20 measured
launches.

| Dispatch window | Budget | Measured |
| --- | ---: | ---: |
| p50 | 200 ms | **171.5 ms** |
| p95 | 250 ms | **176.0 ms** |
| p99 | 300 ms | **178.0 ms** |

All 20 samples were non-degraded, selected `block_ext4`, and reported no image
pull, image build, mount materialization, warm claim, artifact hashing, or
process-table scan. The matrix validator accepted the report.

Raw evidence:
`specs/evidence/performance/2574-prepared-cold-firecracker-2026-08-19.json`
(schema 5, SHA-256
`523ffd3f2904696141edd806861093abb1011de00d6c345b7acc3be27f4ee6c4`).

Formatting, the complete host workspace library/binary/integration suite,
workspace check, all-target Clippy with warnings denied, and the Linux
all-target plus BDD-gated cross-check all pass.
