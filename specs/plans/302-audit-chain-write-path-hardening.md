# Plan 302 — Audit-chain write-path hardening

**Status: PARTIAL — WS1–WS3 landed, WS4–WS5 open**

## Why

An audit chain accuses. When the writer can produce a broken chain by itself,
every break it ever reports carries an asterisk, and the first person to find
that asterisk is an auditor rather than us. This plan covers the write-path
defects found by auditing our chain writers against a published post-mortem of
the same class of bug in another signed-receipt system.

The distinction that organises the work: a chain link is created at *write*
time, from an observation of the head. Serializing the write is not enough —
the *read of the head* has to be inside the same lock, or two writers link to
one parent and produce a fork. A fork is not distinguishable, to anyone holding
only the log, from a deleted or reordered entry.

## Workstreams

- [x] **WS1 — `ReceiptStore` linked outside its own lock.** `head()` took the
      lock and released it; the emitter then signed and called `append()`,
      which retook it. Two emitters could observe one head and claim one
      parent. Replaced `append` with `append_chained`, which reads the head,
      runs the caller's build-and-sign closure, and persists, all under one
      lock. The parent is inside both the receipt id and the signed bytes, so
      signing has to be under the lock too — a receipt cannot be re-linked
      afterwards without re-signing.
- [x] **WS2 — the receipt lock was not a lock.** It used `fcntl(F_SETLKW)`
      record locks, which are owned by the *process*: two threads each
      "acquired" it and proceeded. Switched to `flock`, held per open file
      description, which serializes threads and processes alike. Reused the
      helper the primary chain already had rather than growing a second one.
- [x] **WS3 — `audit_signer::Chain` write path.** Three fixes: an exclusive
      non-blocking lock taken at `open` and held for the chain's lifetime, so
      the in-memory head is a *checked* sole-writer assumption rather than a
      convention; one `write_all` of line-plus-newline instead of `writeln!`,
      which emitted two writes that O_APPEND made individually — not jointly —
      atomic; and a `resync_needed` flag so an append that fails partway
      re-seeds the head from the on-disk tail instead of handing the next
      entry a parent the tail already claimed.

Regression coverage, all three verified to fail with the fix reverted:
`concurrent_writers_extend_one_chain_without_forking`,
`concurrent_writer_processes_extend_one_chain_without_forking` (re-execs real
writer processes — a same-process test cannot stand in for two supervisors),
`a_second_chain_on_the_same_file_is_refused`,
`an_entry_and_its_newline_are_written_together`,
`a_failed_append_does_not_leave_the_head_behind_the_tail`,
`a_failed_build_advances_nothing`.

- [x] **WS4 — audit emission was advisory, so a missing entry was invisible.**
      Every `emit_*` call site warned and continued. The chain proves
      completeness of what was *retained*; nothing detected an entry that was
      never written, because a missing entry leaves no gap — the line after it
      links to the line before it and the chain verifies clean. Claim 8 reads
      "every workload runs from a signed, audited `ExecutionPlan`", and the
      audited half was best-effort.

      `mvm_hostd::audit::durability` is now the single decision point:
      `AuditDurability::{Required, BestEffort}` plus `record_admission`, which
      turns a failed `plan.admitted` into a refused boot on the sealed tier and
      a warning elsewhere. A missing emitter counts as a failure under
      `Required` — having nowhere to record an admission is not better than
      failing to record it. The tier signal is `restrict_agent_verbs`, reusing
      the sealed-production signal the shell-entrypoint refusal already keys on
      rather than inventing a second notion of "prod".

      Only the admission is gated, deliberately. `plan.launched` and
      `plan.failed` describe what has already happened, so refusing on them
      prevents nothing and would trade a missing record for a killed workload.
      The admission is written before the backend starts, so refusing on it
      actually stops the unaudited run — witnessed by
      `a_required_admission_record_that_cannot_be_written_stops_the_boot`,
      which asserts the backend holds no VM rather than merely that an error
      surfaced.

- [ ] **WS5 — two canonicalization schemes for one job.**
      `supervisor/audit_file.rs` signs `serde_json::to_vec(entry) || prev_hash`,
      so every verifier must reproduce serde's field order forever and any
      future field-layout change silently invalidates history.
      `audit_signer/chain.rs` signs JCS bytes and stores them base64, so its
      verifier never re-serializes anything. The second is strictly better and
      the two should converge on it. This is a format change to the primary
      chain, so it needs a migration story for existing on-disk logs — which is
      the reason it is not folded into this pass.

## Not in scope

The `prev_hash`-over-raw-line decision and the single parity-tested verifier
(`mvm-contract`'s wasm-clean implementation, pinned against the hostd verifier
by `mvm_verify_matches_supervisor_chain` and the frozen-vector corpus) were
already right and are unchanged.
