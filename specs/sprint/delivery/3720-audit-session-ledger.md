# Per-session audit seals and ledger (PS-10, part of #3720)

The chain-signed audit log already made every entry tamper-evident. What it
could not say is whether a run's entries were all there. A removed entry breaks
the chain, but a run whose tail was cut, or whose last entries were never
written, reads as a shorter run rather than a damaged one.

## Session seal

A session is one admitted run: every entry carrying the plan id that a
`plan.admitted` entry introduced. At the session's end the host appends a
chain-signed `session.sealed` entry (`mvm_hostd::audit::session`). The end is
one of three things:

- `LaunchOutcome` exit reporting, before the closing root is published;
- a failed boot (`mvm_client::admission::emit_failed`);
- a persistent machine's stop (`LocalBackend::stop_machine`, which reads the
  admitted plan before the state dir goes).

The seal records:

- the entry count
- the position and SHA-256 of the first and last entries
- the chain head it was computed against
- an RFC 6962 root over exactly the session's lines, using the existing
  `mvm_contract::merkle::merkle_root`
- how the session ended
- the measured compute-environment digest when the plan recorded one
- a reserved `snapshot_root` for PS-08

Sealing is idempotent: a session whose last seal still covers its end is not
sealed twice.

**Positions are relative to the head.** They are checked relative to the
recorded chain head, so a deliberate prune shifts every index equally and
does not read as tampering. Any change within the session still does.

**Cost at exit.** Sealing prefilters lines by the serialized `plan_id` field
before decoding, so it does not decode the whole log at every exit. The first
version decoded every line and cost 0.4–0.7 s per seal on this host's chain.
Measured in release on that real chain (53,891 entries, 25 MB, host load
around 28), a seal adds about 110–130 ms for the verified read and 115–135 ms
to compute, on top of the root the exit path already published.

## Session ledger

Each seal carries `seal.prev_seal`, the hash of the previous `session.sealed`
line. The seals are therefore a hash-chained ledger that lives inside the
audit chain. I chose this over a separate ledger file under the audit
directory. A separate file would have to be either unauthenticated (a cache
that must be re-derived from the chain anyway) or a second signed artifact
under a second trust root. The derived ledger is under the same key and the
same genesis walk as every other entry. The only cost is that listing reads
the segment set, which rotation bounds.

## CLI

The existing `trust audit` verbs were extended rather than adding a parallel
namespace:

- `trust audit sessions [--since] [--until] [--json]` lists admitted runs
  with their counts and seals, and checks the ledger's linkage.
- `trust audit show <session>` accepts a plan id or a unique prefix of at
  least 8 hex characters, and adds `--kind <glob>`, `--since`, and `--until`.
  It now reads every segment of a verified chain; before, it read only the
  active file and did not verify it.
- `trust audit verify <session> [--json]` prints one of four verdicts, each
  with its own exit status:
  - `VERIFIED` (exit 0)
  - `MISMATCH` (exit 1), with the reason: `chain_break`, `signature`,
    `malformed`, `truncated_tail`, `count_mismatch`, `sequence_mismatch`,
    `root_mismatch`, `head_mismatch`, `ledger_break`, `malformed_seal`, or
    `io`
  - `UNSEALED` (exit 2)
  - `NOT_FOUND` (exit 3)

  A chain that does not verify makes the session a `MISMATCH` with the
  chain's own reason. Verifying walks from genesis once and serves both the
  selector and the verdict from that walk.
- Time bounds accept RFC 3339, `YYYY-MM-DD`, or a duration back from now,
  parsed by the existing `parse_ttl`.
- The glob matcher moved from the command gate to `mvm_core::util::glob`
  rather than being written twice.

## Durability

The existing per-event policy is the right one, and it is now stated in the
audit guide and pinned for the new records. Authorizing and boundary events
are fsync barriers; descriptive records ride the next barrier. The barrier
events are:

- `plan.admitted`, `plan.failed`, `plan.exited`
- `session.sealed`
- `chain.sealed`, `chain.continued`, `chain.pruned`
- terminal `cmd.*` events
- anything unrecognised

The alternative, fsync on every entry, was measured and rejected. On 1 KiB
appends, append-only costs 6–10 µs. Append plus fsync costs 4.3–5.2 ms on
this Mac and 44–49 ms on the rotational RAID of the Linux KVM host. A lost
deferred entry is a truncation; a barrier after every authorization means it
can never be a missing authorization. The new witness is
`session_and_segment_boundaries_are_sync_barriers`.

## Rotation default

The code and CLAUDE.md agree. The lifecycle chain rotates at 4 MiB by default
(`AUDIT_SEGMENT_DEFAULT_BYTES`, used by `RotationPolicy::from_env` in every
production signer constructor, and pinned by `audit_chain_rotation.rs`). This
host shows it live: five retired `local.seg-00000N.jsonl` segments of about
4.19 MB each.

What does not rotate:

- the per-VM workload chains, which are bounded by one machine's life;
- `RotationPolicy::never()`, which is used only in tests.

The unsigned command log rolls at 10 MiB. The audit guide now states all
three.

## Anchoring

The audit guide documents what anchoring does and does not cover:

- `publish-root` roots at admission, exit, and stop.
- The `MVM_AUDIT_WITNESS` off-host copy.
- Exactly what a seal adds. It detects truncation through a session's seal
  (the session becomes `UNSEALED`) and any seal that misdescribes its session.
  It does not detect a session that never sealed or whole sessions cut from
  the tail; those need a witnessed root.

## Claim 8

ADR-001 row 8 and `model/claims.toml` gain
`a_correctly_signed_seal_that_lies_is_refused_field_by_field` and
`truncating_through_the_seal_leaves_the_session_unsealed`. Both live in
`session.rs` itself so the mutation lane breaks the verifier they guard, and
the mutation surface is re-pinned.

## Tests

- **Hostd**: seal/verify roundtrip, interleaved sessions, an edited entry
  (signature), a removed entry (chain break), reordered entries (chain break),
  a seal signed by another key (signature), each lying field of a correctly
  signed seal, a malformed seal, truncation through and after a seal, a
  mid-record cut, late entries, unknown and unsealed sessions, a broken ledger
  link, host entries under no plan, time and kind filters, prefix resolution
  and ambiguity, label roundtrip, JSON shape, a seal across a rotation, and
  idempotent sealing.
- **CLI** (`tests/audit_sessions_cli.rs`): the listing and ledger JSON, filters,
  every verdict and exit status against a real chain in an isolated
  `MVM_HOME`, and help text.

## Still open

- Snapshot roots in the ledger, which wait on PS-08.

## Measurements

- **Listing.** On this host's real chain (about 54,000 entries across six
  segments), a debug build lists 2,838 sessions in about 6 s under load.
- **Session verify.** The genesis walk behind `verify <session>` takes
  4.5–7 s in release.
- **Seal at exit.** About 0.25 s, as described under Session seal.
- **Live check on this host.** All 2,838 existing sessions list as unsealed,
  because they predate the seal. One of them verifies as `UNSEALED` (exit 2)
  from a clean genesis walk.
