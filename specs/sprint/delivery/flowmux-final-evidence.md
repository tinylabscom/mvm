# FlowMux single-path closeout: final evidence status

The implementation for the FlowMux single-path closeout is recorded on PR
#2768 and is based on the merged FlowMux predecessor stack. The source now
has one authenticated `NetworkFlow` endpoint for workload networking, no guest
NIC or raw-packet compatibility path, no second ingress socket owner, and
explicit migration errors for stale forwarding input.

Host validation completed before publication:

- `cargo test --workspace` passed.
- Workspace all-target/all-feature Clippy passed with `-D warnings`.
- BDD completed 56 features, 194 scenarios (193 passed and one capability-gated
  skip), and 802 steps (801 passed and one skip).
- Python SDK live tests passed 51 tests; TypeScript SDK live tests passed 52
  tests and the SDK build passed.
- Public-site checks, schema/protocol checks, permanent networking gates,
  supply-chain checks, and documentation/claim gates passed.

The recorded macOS arm64 host-loopback comparison is intentionally not marked
passing. The raw comparison JSON remains `passed: false`: 12 of 32 checks pass
and 20 fail. The failures are concentrated in short-flow authenticated
TCP/UDP latency and throughput plus transformed-HTTP connection latency. The
raw candidate and comparison files are retained under
`specs/benchmarks/network/`. A fresh release run at source commit `642140ec38`
is also recorded there; it remains failing (12/32 checks pass, maximum latency
ratio 14.5x, minimum throughput ratio 0.325x). The current evidence diagnoses
per-flow authenticated framing/session setup and endpoint-relay cost against
the deleted direct-L3 short-flow baseline; thresholds and raw evidence remain
unchanged, and no performance exception has been recorded.

The live backend matrix is not complete. Existing HVF evidence covers the
host-first FlowMux handshake and deny-all/egress witnesses. The approved Lima
KVM Firecracker environment now has a successful admitted TCP/DNS witness:
`machine run --hypervisor firecracker --image alpine --allow-host
example.com:80 -- wget -q -O - http://example.com` returned the Example Domain
body and exit code zero. Earlier attempts remain recorded as infrastructure or
witness-shape failures: a missing Cargo path after the Stage0 build, BusyBox
HTTPS absolute-URI refusal, and a correctly denied port-80 request under the
bare-host port-443 default. A libkrun builder bootstrap reached its Stage0 Nix
build and was interrupted before the final shell job completed.

The post-stack validation rerun exposed six independent defects. The
standalone SDK fuzz lockfile was stale; the active FlowMux session
implementation applied outbound UDP admission to an ingress reply even after
the external peer had been observed; an old evidence-tree snapshot overwrote
newer SDK boot-source, command, egress, and browser support while retiring
dynamic forwarding; the generated Python protocol binding still contained the
deleted guest port-forward request; outer nightly-only Cargo flags leaked into the pinned
stable nested cross-compiler; and the refreshed fuzz
resolver selected `blake3` 1.8.7, leaving the reviewed vendored `arrayref`
patch unused. Ingress UDP replies now bypass outbound admission while the
relay's observed-peer table continues to reject unseen destinations. The
Python and TypeScript SDKs now preserve typed manifest and OCI sources,
boot-command overrides, literal environment and egress lowering, the pinned
browser provider, and bounded readiness checks while declaring ingress before
boot; dynamic post-admission forwarding fails with migration guidance. The
SDK protocol bindings now match the canonical schema. The
nested build boundary clears outer toolchain, wrapper, and Rust flag variables,
with a focused regression test. The fuzz lock pins `blake3` 1.8.6
so the reviewed patch remains active. The full host workspace test, check,
doc-test, and formatting chain passes; the focused ingress test passes five
consecutive runs; the locked fuzz check passes on Rust 1.91.1; and hostd
all-target Clippy passes with warnings denied.

One implementation decision is resolved, but the live and performance gates
remain open before this tracker can be closed:

1. The authenticated guest FlowMux client now launches when a valid signed
   ingress plan is present under outbound deny-all, while retaining the
   existing secret-bearing suppression rule. Unit tests cover both paths.
2. The performance budget remains a merge blocker until the measured
   regression is fixed or separately approved by the owner.

Until the performance decision and remaining live evidence are resolved, issue
#2751 and the W8 acceptance boxes remain open.
