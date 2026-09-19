# Prepared-record telemetry handoff

Issue #3422, preparatory W3b of `2026-09-17-host-mediated-telemetry`.
The issue and epic #3419 remain open.

## Implemented boundary

`mvm_core::net::telemetry::outbox` reserves fixed storage before exposure to
producers: one to 256 slots of 32 KiB plus slot metadata, with a separately
configured admitted-byte limit. Admission borrows a validated `PreparedRecord`,
makes one `try_lock` attempt and copies bounded bytes. It does not allocate,
destroy caller-owned records, invoke formatters, perform I/O, notify a worker,
retry or wait for a contended lock. A full or contended queue sheds the attempted
record and retains independent cumulative record/byte evidence.

Preparation uses the existing allocating typed encoder. This API therefore does
not yet establish bounded source callback capture. Runtime adapters must not
move that preparation into tracing callbacks and claim allocation-free emission.
There is no new production unsafe code, dependency, background polling loop or
drop-time join. The allocation regression uses a test-only allocator observer;
both tests pass under Miri.

The transport worker pops owned bounded bytes and releases the queue before
encryption or socket writes. Prepared records reuse the authenticated session
without decoding/re-encoding. A failed write ends the session and marks that
record's delivery uncertain; the next call on the closed session does not consume
another queued record. A newly authenticated session can drain remaining records.
The supervisor must discard the queue across restore/generation changes.

Capacity, contention, unavailable and uncertain transport counts survive a full
queue and all reads. Snapshots are cumulative, not atomic across fields while
producers or the transport worker run. Counter wrap and poisoned-queue tails are
explicit degradation.
Transport failure counts describe failed attempts, not proof of non-receipt.
Automatic delta summaries and reserved summary bandwidth are not implemented by
this component and remain part of the supervised worker integration.

## Component merged; runtime capture remains open

PR #3464 delivered this handoff through the merge queue, on top of the merged
transport foundation from #3449. Its PR and merge-group checks passed.

The six new queue tests initially failed to compile before implementation. They
now pass, along with a seventh queue test for atomic close, two new encrypted
transport tests and the existing nine transport tests (18 total). They cover limits, FIFO/reuse, held-lock contention,
closed and poisoned queues, counter overflow, redacted Debug output, failed-write
accounting and closed-session non-consumption.

Two additional allocation regressions cover the cold first offer, full and
closed rejection, loss reads, close, and fresh producer threads. The cold-path
test first failed with one allocation: macOS lazily initializes the native mutex
on first use. Construction now warms that mutex before exposing the queue.
Both tests pass with zero allocations, reallocations and deallocations in the
measured operations, natively and under Miri (`nightly-2026-08-25`,
`cargo miri test -p mvm-core --test telemetry_outbox_alloc`). Preparation and
thread creation remain outside measurement; this is not a source-capture or
end-to-end latency benchmark.

The stall witness arms a deterministic barrier inside the authenticated worker's
writer. While it is held, 1,000 prepared offers finish: two enter the queue and
998 are rejected with exact byte counts. Only after producer completion is the
writer released. The host receiver then decrypts the admitted records and an
explicit typed loss summary built from the retained evidence. No sleeps are used
for synchronization. This is a component witness with a controlled writer, not
a booted VM, actual stopped host socket reader or detached runtime collector.

The host workspace suite completed with 13,970 passed, zero failures and 31
ignored tests across 226 test/doc-test results. It used the build preceding the
final atomic-close and native-mutex initialization changes. After those changes,
the entire core library passed
2,009 tests, including all 18 transport/handoff tests; all eight contract tests
also passed. Final workspace all-target clippy, BDD-feature all-target clippy,
fmt, the Linux all-target cross-check, all 69 repository gates and the separate
declared-backing gate pass. Cross-compilation is not execution of Linux-specific
tests. PR #3464's required checks passed and actual merge-queue entry was
observed on 2026-09-19 UTC (position 5, `AWAITING_CHECKS`). It merged at
2026-09-19T02:31:31Z as `22f1ea9a102734b7c706f4ec4657b2ff9c3534a9` after
[merge-group run 35414129921](https://github.com/tinylabscom/mvm/actions/runs/35414129921)
completed successfully. The main checkout was immediately synchronized, and
the merge evidence was recorded on issue #3422. Runtime capture acceptance
remains open; this component merge does not close W3 or epic #3419.

Host validation uses isolated MVM_HOME/CARGO_HOME/CARGO_TARGET_DIR and Rust
1.97.1. The full workspace run excludes `run_build_surfaces_environment_gaps`
(two builder-boot probes) and `mk_guest_eval_assertions_all_pass_when_nix_available`
(Nix), which the repository rules prohibit on macOS. No live VM was booted for
this component validation.

`cargo audit` and `cargo deny check` pass with the unchanged allowed
`proc-macro-error2` unmaintained advisory (RUSTSEC-2026-0173). `cargo machete`
reports the same six existing findings: `anyhow`/`tracing` in mvm-capture, `tar`
in mvm-client, `etherparse` in mvm-hostd, `tempfile` in mvm-runtime-fuzz-backend,
and `am-fs-core` in third_party/am-fs-ext4. No dependency or lockfile changed.

## Runtime acceptance still required

Bounded capture and policy for all sources; producer epoch/sequence ownership;
event-driven worker wakeup, cancellation and reaping; automatic wire loss
summaries with reserved bandwidth; backend endpoint and generation registration;
VM-lifetime host collection and retention; detached retrieval; actual VM stall
and workload-progress witnesses. No runtime source or collector is enabled here.
