# Local mailbox/audit handshake: test-only prototype

Backing: preview
Validation: none

This is a bounded fixture experiment, not a shipped mailbox capability.
It follows the explicitly approved test-only follow-up to the audit-chain
ownership prerequisite. Production sources, manifests, dependencies, protocol
and public APIs are unchanged by this experiment. No Signal or transport
integration is included.

Fresh combined recovery validation passed all 11 prototype tests, workspace
clippy and the serialized workspace suite. See the
[combined validation report](audit-directory-policy-report.md#combined-recovery-validation)
for exact commands, other gates and limitations. Independent source review
found no concrete blocker in this test-only slice. These results supersede
the incomplete isolated recovery run, not the production-evidence limits below.

## Boundary and source evidence

The existing `MailboxJournal` has a private `JournalEvent` and private
`append` implementation. Public `admit_local` commits the existing acceptance
record and same-host anchor through that implementation; it has no public
parameter or transaction hook for jointly committing a new audit obligation.
Wrapping real acceptance and then writing an obligation would introduce the
very crash gap under investigation, so this prototype does not do that.

Instead, `tests/mailbox_audit_handshake/fixture.rs` defines a clearly separate
fixture journal. A single `atomic_write_durable` snapshot contains the
ciphertext transition and its exact audit obligation. The prototype uses:

- Real `mvm_core::atomic_io::atomic_write_durable` and directory sync.
- Real AES-GCM ciphertext produced by the existing core helper.
- Real `audit::audit_file::FileAuditSigner`, host-held fixture Ed25519 key,
  signed JSONL envelope and `verify_chain_bytes`.
- A fixture-only journal format, transition identity, pending/completion
  state and publisher protocol. It does **not** use real `MailboxJournal`
  acceptance, local-anchor recovery or key-custody manifests.

Every reopened handle contains only paths and shared synchronization. Journal
and audit state are re-read from disk; no in-memory journal, cursor or lookup
cache substitutes for recovery.

## Modeled protocol

Inputs stand for already-authorized transitions. The fixture models Call,
Reply and Cast for host/workload, VM-to-VM and audit-service recipients. It
does not implement authorization or route negotiation. Both accepted and
expired event labels are exercised on the same message identifier to show
that a message identifier alone cannot identify a lifecycle transition.
Expiry is a second modeled transition, not a real TTL/lease/ACK implementation.

The immutable identity includes history, monotonic cursor, hash of the
ciphertext-bearing transition and event. The request replay key is message
plus event; an exact retry retains the original cursor and obligation, while
different evidence at that key refuses before mutation. Signed audit labels
carry identity, principal/kind metadata and a ciphertext commitment only:
neither plaintext nor its hash enters the audit record.

The fixture states are:

1. No record: bounds and replay conflict checks happen before mutation.
2. Joint transition/obligation committed: pending and not visible.
3. Audit owner verifies the chain and reuses exactly matching evidence, or
   appends the expected obligation under a serialized publication operation.
4. File and directory synchronization are required even when a matching line
   already exists: exact-record lookup alone does not repair ambiguous sync.
5. Completion containing the signed-line digest is durably written before
   success/visibility. Exact completed retries re-verify/re-sync evidence and
   durably rewrite the completion snapshot before returning success.

The mailbox mutex is released before publication. The test-only publisher
uses a distinct shared mutex across verify/lookup/append/reverify/sync, with
all fixture writers participating. **This is not integration with the
production sidecar lock**, and thread tests do not prove a cross-process
publisher protocol. A production caller cannot safely copy this sequence
around an arbitrary shared chain writer.

Post-commit interruptions and unavailable/corrupt audit evidence return
Pending/Unknown, not a claim that the transition was refused or rolled back.
Verification failure is never treated as an absent audit entry. Missing
evidence for a completed transition also refuses repair-by-new-append.

## Bounds and progress headroom

The fixture accepts four transitions, each with at most 256 ciphertext bytes.
Journal reads are capped at 32 KiB, and admission reserves the worst-case
completion representation for every accepted transition before the snapshot
write. Completing pending work does not need a new transition slot.

The dedicated audit file has a 32 KiB scan limit and at most four records.
Admission bounds the serialized obligation so three copies plus 1 KiB of
envelope overhead fit its per-transition share; each accepted transition
reserves one audit record, with no second record needed for completion.
This is a reservation proof only for this dedicated, bounded fixture chain,
not for a shared production chain with unrelated writers or rotation.
It reserves logical slots/encoded-byte budget, not physical disk blocks;
ENOSPC or an unavailable directory can still leave committed work pending.

## Witnesses and limits

The integration test exercises deterministic interruption at:

- Before joint commit: no acceptance.
- After joint commit: one pending obligation, no visibility.
- After audit append but before completion: retry reuses one logical record.
- An injected ambiguous audit outcome: retry explicitly re-syncs.
- After durable completion but before response: retry returns the same evidence.

It also covers conflicting requests and signed evidence, corrupt and wrong-key
chains, missing completed evidence, a wrong completion digest against valid
extant signed evidence, concurrent same-request publication and competing
different request bytes at the same replay key,
mailbox-lock release during audit wait, full refusal without mutation,
completion headroom at capacity, unavailable audit recovery, bounded reads,
and ciphertext-only evidence across message kinds and endpoint roles, including
the audit service as both sender and recipient.

A fresh source review reported no concrete correctness defect and requested
the wrong-completion, conflicting-concurrent-request and audit-service-sender
witnesses above. Those additions do not change production code or the fixture
protocol; a narrow helper only corrupts stored completion evidence for a test.

The stop points model loss of control/response deterministically. They are
not process kills, power failures, failing kernel fsync calls or a physical
durability proof. In particular, the real signer may already have synced the
entry when the ambiguous-outcome stop point runs. The retry test proves that
the protocol re-syncs regardless, not that a failed syscall was injected.

The fixture journal is not authenticated by a separate anchor and provides
no whole-host rollback detection or malicious-host protection. It does not
establish real mailbox atomicity, policy admission, lease/ACK correctness,
multi-process exclusion, rotated-chain lookup, compaction, GC, retention,
or cross-host delivery. The trusted host retains the fixture keys; this adds
no security guarantee beyond ADR-001.

## Archived validation

The results below are preserved from the original experiment, not evidence
that checks have run on the recovery checkout.

Tests were written before the fixture implementation. Build shells source
`scripts/dev-env.sh` with the existing Cargo registry cache, isolated target
directory, `TMPDIR=/tmp` and `CARGO_NET_OFFLINE=true`.

| Command | Observed result |
| --- | --- |
| `cargo test -p mvm-hostd --test mailbox_audit_handshake` | 11 passed, zero failed/ignored after review additions; includes table-driven stop points and message/endpoint combinations |
| `cargo clippy -p mvm-hostd --test mailbox_audit_handshake -- -D warnings` | Passed |
| `rustfmt --edition 2024 --check crates/mvm-hostd/tests/mailbox_audit_handshake.rs` | Passed, including the support module |

The preceding relocation's workspace check, workspace clippy and gated
cross-check passed **before this prototype was added**. Its full workspace
tests failed the directory-policy gate after unchanged files moved into its
watched directory; check-all was stopped during non-Cargo dependency
resolution. Those outcomes are recorded separately in
`adr-061/audit-chain-implementation-report.md`; they are not a broad green
validation of this later test-only prototype.

## Recovery validation

Recovered from successful edit-tool inputs in the archived transcript.
Chronological patch replay and rustfmt normalization matched both Rust files
and this original report. The only code adaptation is importing the signer
and verifier through `supervisor::audit`, the available compatibility path.
The recovered target still contains eleven tests.

The recovery checkout's scoped test/clippy batch ended without an exit status
and its output became unavailable. Neither test nor clippy success is inferred
from that run. A separate `rustfmt --edition 2024 --check
crates/mvm-hostd/tests/mailbox_audit_handshake.rs` passed, including the support
module. The integrating parent owns the authoritative fresh test/clippy run;
the archived eleven-test result above remains historical evidence only.
No production mailbox atomicity, process-crash or power-loss claim is made.
