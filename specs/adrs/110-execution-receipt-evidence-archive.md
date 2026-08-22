# ADR-110 — The evidence archive, and the difference between checked and asserted

Backing: preview
Validation: none

**Status: Accepted**

## Context

`mvmctl trust audit receipts export` printed a JSON array of signed
`ExecutionReceipt`s derived from the chain-signed audit log. Two things made
that less than it appeared.

**It dropped evidence without saying so.** `map_event_to_receipt_type` matched
thirteen event names and returned `None` for everything else; the caller wrote
`None => continue`. Every `flow.egress.allowed` / `flow.egress.denied`,
`stream.subscribed`, `stream.input_granted`, and `gateway.transcript_sealed`
entry left no trace in the output. An export containing no egress was
byte-indistinguishable from an export whose egress entries were skipped — and
egress decisions are the record backing claim 10.

**A receipt did not link back to the log.** It carried a `plan_id` and some
hoisted labels, but no digest of the audit line it derived from, no leaf index,
no inclusion proof, and no signed root. The RFC 6962 machinery to fix that
already existed (`mvm_contract::merkle`, `mvm_hostd::audit::merkle`) and nothing
connected receipts to it.

## Decision

Ship a `.mvmev` evidence archive: a plain tar with a signed manifest, mirroring
the `.mvmpkg` manifest-plus-signature shape in `mvm_core::plan::bundle`.

```
manifest.json              signed EvidenceManifest
manifest.sig               detached signature
host.pub / host.did        the key everything is checked under
receipts/NNNN-<type>.json  signed ExecutionReceipts
cited/<leaf>.json          in-scope entries with no receipt mapping
proofs/leaf-<index>.json   one inclusion proof per LEAF
audit/<tenant>*.jsonl      the raw chain lines
```

Four decisions inside that are worth recording.

### 1. Every in-scope entry is accounted for, exactly once

`map_event` returns a two-armed `EntryMapping` rather than an `Option`. An
event with no receipt mapping becomes a citation; the match is exhaustive, so
an event added later cannot leave the export by falling through. The compiler
refuses the shape of the original bug — an attempt to reinstate it as a guarded
arm fails with `E0004`.

Receipts plus citations cover every in-scope entry. That is what makes "this
export is complete" checkable rather than a property of whichever events
happened to be on the mapping list.

### 2. Completeness is `attested` or `derivable`, never a boolean

Under a `--plan-id` filter a verifier can check that every listed leaf really
sits in the authenticated tree at its stated index, and that no listed leaf was
fabricated. It **cannot** rule out an omitted in-scope entry: a subsequence
carries nothing that would attest its own completeness, and detecting the gap
needs the whole log.

So the manifest carries a signed host assertion and records that it is one.
`--full-chain` removes the limit by construction — a tenant-scoped archive
embeds every leaf, so a verifier compares `leaves.len()` against
`audit_root.tree_size` and derives coverage with no host assertion involved.

`CompletenessResult` therefore has three arms, not two. Folding `Attested` into
`Passed` is how an assertion gets reported as a check.

### 3. Every leaf gets a proof, not every receipt

The first implementation gave proofs only to receipts. Running it end to end
produced a legitimate archive — one whose in-scope entries were all citations —
that the verifier rejected for having no proofs.

The fix was not to relax the check. A citation carried a leaf index and a
digest bound to nothing a verifier could check independently of the host's
signature over the manifest. Proofs are now keyed by leaf index
(`proofs/leaf-<index>.json`) so one rule covers both kinds, and every leaf in
the manifest is independently bound to the signed root.

### 4. Inclusion is two checks

`verify_membership` attests that a leaf is in the host-signed tree. It says
nothing about *which* leaf the member beside it came from: a proof built for a
different entry verifies perfectly well and attests the wrong thing.

So inclusion also requires `proof.leaf_index == leaf.index`. This is not
theoretical — mutating the writer to build every proof for leaf 0 leaves a
"every proof verifies against the signed root" test green, and fails only the
binding test.

## Consequences

`mvmctl trust audit receipts verify <archive>` reports three independent
results and exits with a bitmask (1 integrity, 2 inclusion, 4 completeness).
One failing does not short-circuit the others, so a report names every problem
rather than the first. `Attested` contributes no bit — it is not a failure —
and the caveat prints on the always-on `ui::notice` channel, because a limit
nobody sees is not a limit that was stated.

The membership composition moved from a private function in `mvm-cli` into
`mvm_contract::merkle::verify_membership`, so the archive verifier and the
existing `verify-inclusion` verb cannot drift apart. `publish_root`'s
build-and-sign half moved to `mvm_hostd::audit::merkle::sign_root_in` for the
same reason: the archive needs a signed root as a value, without the sidecar
write.

## Limits

Stated so no later reader has to infer them:

- Plan-scoped completeness is host-attested. Only `--full-chain` makes it
  verifier-derivable.
- Tail truncation of the underlying chain stays undetectable, unchanged from
  claim 8. An archive cannot be more complete than the log it reads.
- Sealed transcripts are cited by the root already written into the chain, not
  embedded. `--with-transcripts` is **not implemented and not advertised**; the
  writer refuses it rather than quietly citing roots while a caller believes it
  carried ciphertext. See the open question below.
- `SignedEvidenceManifest.signed_at` is outside the signed material and remains
  forgeable, exactly as on a receipt envelope. The archive's content address is
  signed.
- `ArchiveScope` does not carry `deny_unknown_fields` — it is an internally
  tagged enum, where that attribute interacts badly with serde's tag buffering.
  The four structs an untrusted archive actually deserializes into
  (`LeafCitation`, `TranscriptCitation`, `EvidenceManifest`,
  `SignedEvidenceManifest`) all carry it.

## Open question: which transcript store is authoritative

Embedding sealed chunks is blocked on a question this ADR does not answer.
There are two locations:

- `config::vm_stream_transcript_dir` — `<vm_state_dir>/stream`, written by
  `mvm_hostd::stream::plane`.
- `config::mvm_transcripts_dir` — `<mvm_home>/audit/transcripts/`, read by
  `mvmctl trust audit transcript` and, as far as this branch can tell, written
  by nothing.

The two disagree about layout as well: `mvm_transcripts_dir`'s doc comment
describes `<tenant>/<vm>/<capture-id>/`, while its only consumer builds
`<tenant>/<capture-id>`. An embedder has to pick one, and picking wrong
produces an archive that silently carries nothing. Resolving that is a
prerequisite for `--with-transcripts`, not part of it.
