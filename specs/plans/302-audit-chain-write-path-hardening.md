# Plan 302 — Audit-chain write-path hardening

**Status: WS1–WS3 + WS5 + WS6 landed; WS4 in review (#2242)**

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

- [x] **WS6 — a broken chain was reported as a missing audit entry.** Issue
      #2258. The read side of the same defect WS1–WS3 fixed on the write side:
      once a writer had forked a chain, `SignedChainAnchor::load` warned, skipped
      it, and continued with an empty index, so every lookup returned `None` and
      the operator was told the checkpoint *had never been audited*. That is a
      different finding with an opposite response — "you skipped a step,
      re-capture with a signer present" versus "your integrity chain is damaged,
      investigate" — and reporting the second as the first buried a tamper signal
      under a routine message. The anchor now remembers which chains failed
      verification and returns `Err` when a lookup misses *and* at least one
      chain was unverifiable; a miss with every chain clean keeps the original
      message, which is then true. Same fail-closed verdict either way, so no
      admission decision changes.

      The two reasons are kept apart everywhere downstream rather than only in
      the message text: `mvm_runtime::lineage` exports `NO_SIGNED_ENTRY` and
      `LEDGER_UNVERIFIABLE` as the sentinels both the emitter and the classifier
      share (they were retyped string literals before), and the warm-pool claim
      seam gained `ClaimRefusal::LedgerUnverifiable` so an unreadable ledger no
      longer falls through to `ParentTampered` — which would blame a parent that
      may be perfectly sound.

      `mvmctl doctor` reports an `audit chain` line and fails the check when a
      chain does not verify, so a damaged ledger is a posture finding in its own
      right instead of surfacing later through an unrelated verb. The sweep
      loads the host signer only when its secret half already exists: a
      diagnostic must not mint a signing key as a side effect
      (`scanning_a_fresh_home_creates_no_host_signer_key`).

      **What running it on a real host found.** The first live `doctor` after
      the forked chain was quarantined reported `1 of 3 chain(s) FAIL
      verification` against `~/.mvm/audit/secrets.jsonl`, with the reason
      ``unknown field `action` ``. That file is not a chain: it is the unsigned
      plain-JSON operator log `mvmctl secret …` writes into the same directory,
      and it matches the `<tenant>.jsonl` lifecycle shape by accident. The
      exclusion existed in `mvm-client`'s enumerator and nowhere else, so the
      anchor had always mis-scanned it and merely warned — and this workstream
      would have promoted that latent mis-scan into a hard, unfixable refusal of
      every un-anchored record on any host that has ever used secrets. Fixed by
      moving `SECRETS_OPERATOR_LOG` next to `WORKLOAD_AUDIT_SUFFIX` in
      `mvm-core::config`, excluding it from `is_host_lifecycle_chain`, and
      collapsing `mvm-client`'s private copy onto the shared one. Both
      regression tests were confirmed to fail with the exclusion removed. This
      is the concrete instance of the drift the predicate's own doc warns about:
      there were three copies of the rule and the most correct one was not the
      one the anchor used.

      Coverage:
      `a_miss_against_an_unverifiable_chain_is_an_error_not_a_silent_none`,
      `a_miss_against_clean_chains_still_reports_never_audited`,
      `a_hit_still_resolves_even_when_another_chain_is_unverifiable`,
      `the_image_anchor_reports_an_unverifiable_ledger_the_same_way`,
      `an_empty_anchor_reports_no_entry_rather_than_an_unreadable_ledger`,
      `lineage_refusals_separate_an_unreadable_ledger_from_unaudited_and_tampered`,
      `the_unsigned_secrets_operator_log_never_makes_a_lookup_unanswerable`,
      `the_unsigned_secrets_operator_log_is_not_a_lifecycle_chain`,
      plus the doctor mapping tests. All run against a chain synthesized and then
      deliberately damaged inside a temp `MVM_HOME`, never the developer's own.

      **Consequence worth stating.** The image-lineage self-heal
      (`heal_ancestry`) reads the same anchor, so a build whose lineage tip lacks
      an `audit_ref` marker now fails against a damaged chain instead of
      re-emitting the node as an orphan. That is the correct direction — healing
      an ancestry against a ledger you cannot read appends more entries to a log
      that proves nothing — but it does widen where a broken chain is felt. A
      marked tip short-circuits before any lookup, so a healthy tree is
      unaffected.

## Not in scope

The `prev_hash`-over-raw-line decision and the single parity-tested verifier
(`mvm-contract`'s wasm-clean implementation, pinned against the hostd verifier
by `mvm_verify_matches_supervisor_chain` and the frozen-vector corpus) were
already right and are unchanged.

A `trust audit repair` / chain-reset verb, per #2258. Someone able to damage one
line could then force a reset, converting tamper-*detection* into
tamper-*erasure*. Recovery stays a deliberate human act that leaves a visible
artifact: quarantine the file under a new name, never delete it and never
re-sign it. Both the refusal message and the doctor line say exactly that, and
`the_broken_chain_guidance_says_quarantine_and_never_re_sign` pins the wording
so it cannot soften into "reset it" later.

Re-framing an already-forked chain is likewise out of scope, and cannot be made
to work: a fork means several entries each claim the same `prev_hash`, so no
re-parse recovers a single history. Only re-signing would, and re-signing is the
thing that has to stay impossible.
