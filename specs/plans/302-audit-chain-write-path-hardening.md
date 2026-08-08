# Plan 302 — Audit-chain write-path hardening

**Status: WS1–WS3 + WS5 landed; WS4 in review (#2242)**

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

- [ ] **WS4 — audit emission is advisory, so a missing entry is invisible.**
      Every `emit_*` call site warns and continues
      (`crates/mvm-cli/src/commands/vm/up/admission.rs`,
      `crates/mvm-hostd/src/plan_admission.rs`). The chain proves completeness
      of what was *retained*; nothing detects an entry that was never written,
      because there is no gap to detect. Claim 8 reads "every workload runs
      from a signed, audited `ExecutionPlan`" and the audited half is currently
      best-effort. Proposal: `--prod` fails closed when `plan.admitted` cannot
      persist, making the receipt a control rather than a record. Dev keeps the
      warn-and-continue behaviour. Needs a decision on whether a chain that is
      unreachable at boot should block the boot.

- [x] **WS5 — the primary chain re-derived its signed bytes at verify time.**

      The original framing of this workstream was "converge on JCS", and that
      was wrong twice over. Recorded here because the wrong version is the
      tempting one:

      1. *There was no second implementation to converge with.* The browser
         verifier is not an independent reimplementation — `web/audit-verify`
         is a `wasm_bindgen` shim over `mvm-contract`, the same Rust code. The
         cross-language divergence this was meant to fix did not exist.
      2. *Our JCS is not JCS.* `serde_jcs` 0.1.0 orders object keys by UTF-8
         byte value; RFC 8785 mandates UTF-16 code units. They disagree on
         astral-plane keys — `mvm-core`'s `canonicalizer_equivalence` module
         documents this, and `audit_chain_spine.rs` exercises a `U+1F600` key.
         Adopting it would have replaced "reproduce serde's field order" with
         "reproduce a non-conformant JCS", which is worse for looking standard.

      The actual defect was re-derivation itself. `verify_audit_chain` re-ran
      `serde_json::to_vec(entry)` on the parsed entry and checked the signature
      against the result, so the signature was a claim about the *current
      struct definition* rather than about the past. Add one always-serialized
      field to `AuditEntry` and every historical line stops verifying — the log
      accuses itself of tampering because a struct grew.

      `SignedEnvelope` now carries `canonical`: the exact bytes the signature
      covers. Verification reads them and re-derives nothing. The readable
      `entry` stays beside them — an audit log nobody can `grep` is an audit
      log nobody reads — and both verifiers check the two agree, so the
      readable copy cannot drift from the attested one. Because the stored
      bytes are never re-sorted by a reader, the canonicalizer ordering
      problem above becomes structurally unreachable rather than merely
      unlikely; no key-charset restriction was needed.

      No cutover. Lines without `canonical` verify by the original rule
      indefinitely, pinned by `the_pre_stored_bytes_corpus_still_verifies`
      against the committed v1 fixture, which must never be regenerated. The
      v2 fixture pins today's shape.

      Witnesses: `a_line_whose_signed_bytes_differ_from_our_serializer_still_verifies`
      (the decisive one — a genuine line whose signed bytes differ from what
      this crate would emit verifies now and did not before),
      `a_chain_written_without_stored_bytes_still_verifies`,
      `a_readable_entry_that_disagrees_with_the_signed_bytes_is_refused`,
      `tampering_with_either_copy_of_the_entry_is_refused`,
      `a_consistently_rewritten_line_still_fails_the_signature`.

      `audit_signer/chain.rs` was already right on this point — it stores its
      canonical bytes and its verifier never re-serializes. It is unchanged.

## Not in scope

The `prev_hash`-over-raw-line decision and the single parity-tested verifier
(`mvm-contract`'s wasm-clean implementation, pinned against the hostd verifier
by `mvm_verify_matches_supervisor_chain` and the frozen-vector corpus) were
already right and are unchanged.
