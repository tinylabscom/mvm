# Bounded invocation capture and non-waiting completion

Issue #3422, preparatory W3a of `2026-09-17-host-mediated-telemetry`.
Epic #3419 and W1–W7 remain open.

Existing pipe readers used an unbounded channel; the downstream handoff's finish
waited for queue capacity. Both now reuse the same private bounded handoff and
retention rings. Reader/pump completion transfers an owned bounded tail instead
of sending into a full channel. Gap summaries identify the stage so independent
byte losses can be summed without confusing their local sequence positions.
Direct read errors and reader panics mark an unknown tail, without formatting the I/O
error or payload into the diagnostic. Reserved agent kinds cannot be forged by
fd3 producers; control records remain cumulatively bounded and are not evicted
by stdout/stderr pressure.

## Validation

All cargo commands use the isolated worktree environment and Rust 1.97.1.

- Test-first: the stopped-consumer completion regression failed against the old
  blocking sender before implementation, then passed with owned completion tails.
- 81 focused stream unit tests and nine authenticated encrypted stream integration
  tests pass. Tests include 16 MiB floods, exact delivered-plus-dropped accounting,
  zero-byte retention caps, per-stream FIFO, fd3 tails, interrupted/error reads,
  panic containment, disconnected-reader cleanup, cancellation, child deadlines
  and reserved-kind refusal. The buffered invocation forgery test now distinguishes
  valid reader-loss controls from the workload's forged marker.
- The `@stream_capture` BDD scenario passes (two steps). Its second input gate
  releases the flood only after the consumer is paused; an independent pipe
  observes child completion before the consumer resumes. The other 332 scenarios
  were explicitly not selected; this is not whole-product BDD certification.
- `cargo-zigbuild check --target x86_64-unknown-linux-gnu --workspace --all-targets`
  passes. This cross-check executes no Linux syscall/VM test on macOS.
- Workspace clippy and BDD-feature all-target clippy pass with warnings denied.
- `cargo audit` and `cargo deny check` pass, retaining the pre-existing allowed
  unmaintained `proc-macro-error2` advisory warning. `cargo machete` reports the
  same six existing findings: `mvm-capture` (anyhow, tracing), `mvm-client` (tar),
  `mvm-hostd` (etherparse), `mvm-runtime-fuzz-backend` (tempfile), and
  `third_party/am-fs-ext4` (am-fs-core). No dependencies changed.

Delivery also requires the serialized host workspace suite, all repository gates
and queued Linux CI; their final results are recorded on the implementation PR
and #3422. The host command unsets `RUST_LOG`, pins `RUSTDOC` through
`rustup which --toolchain 1.97.1 rustdoc`, and excludes the two
`run_build_surfaces_environment_gaps` probes plus
`mk_guest_eval_assertions_all_pass_when_nix_available`. Those existing tests may
launch a builder or evaluate Nix and therefore must not run on macOS. This is
not a claim that an unrestricted host `cargo test --workspace` passed.

## Boundaries

The fixed live queues contain eight events each. Stdout/stderr pending rings use
the configured byte/chunk limits, retaining one newest frame even for a smaller
byte cap. Accepted fd3 records use the existing cumulative wire-byte limit.
Ring/frame allowances, queue slots and record overhead all count toward memory;
this is not a hardware-qualified resident-memory or allocation budget.

This work removes waits for queue capacity, not internal synchronization from
the standard channel implementation. Generic formatting, synchronous downstream
sinks, pipe EOF/reaping, periodic loss delivery and source-side redaction are not
certified by these tests. Existing fd3 malformed-frame/skip/budget diagnostics
still use their prior stderr path, not complete structured loss reporting.
Tails/gaps can remain pending until another offer or EOF;
cross-pipe tail order is undefined. A disconnected peer or crash still leaves an
unknown delivery tail. The fixture uses ordinary Unix pipes and encrypted mock
streams, not a real microVM or backend-specific vsock transport.

No dedicated typed telemetry service, full tracing subscriber, VM-lifetime host
collector, startup witness, exporter change or default-on rollout is enabled.
All 28 inventoried runtime entries remain declared capture gaps. This is safe
preparatory work on an existing capture path; W1/W2 dependencies still govern
the new feature. Do not close #3422 or #3419 on this delivery alone.
