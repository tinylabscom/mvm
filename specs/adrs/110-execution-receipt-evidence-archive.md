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
  carried ciphertext. The store and layout are decided below; the remaining
  blocker is that nothing anchors a transcript in production.
- `SignedEvidenceManifest.signed_at` is outside the signed material and remains
  forgeable, exactly as on a receipt envelope. The archive's content address is
  signed.
- `ArchiveScope` does not carry `deny_unknown_fields` — it is an internally
  tagged enum, where that attribute interacts badly with serde's tag buffering.
  The four structs an untrusted archive actually deserializes into
  (`LeafCitation`, `TranscriptCitation`, `EvidenceManifest`,
  `SignedEvidenceManifest`) all carry it.

## Which transcript store the archive uses

The archive's transcript citations come from **`config::mvm_transcripts_dir`** —
`<mvm_home>/audit/transcripts/<tenant>/<capture-id>/` — and never from
`config::vm_stream_transcript_dir`.

These are two subsystems, not two homes for one thing:

| | `vm_stream_transcript_dir` | `mvm_transcripts_dir` |
|---|---|---|
| What | the workload's captured stdout/stderr | operator-armed forensic capture |
| Path | `<vm_state_dir>/stream/` | `<audit_dir>/transcripts/<tenant>/<capture-id>/` |
| Lifetime | lives and dies with the VM | outlives it, under `audit/` |
| Addressed by | VM name | tenant, then capture id |
| Read by | `mvmctl machine logs` | `mvmctl trust audit transcript` |
| Anchored in the chain | no | yes, by design |

An archive only ever learns of a transcript through a
`gateway.transcript_sealed` chain entry, and that anchor belongs to the
forensic subsystem. The stream capture is operational VM state that is
deliberately outside the chain; carrying it in an evidence archive would place
unanchored bytes beside anchored ones and blur what the archive attests.

### The layout is `<tenant>/<capture-id>`, and now has one definition

Two doc comments in `config.rs` disagreed: one described
`<tenant>/<capture-id>/`, the other `<tenant>/<vm>/<capture-id>/`. The only
consumer built the former, so the latter was stale. The VM is deliberately not
a path component — a capture names its VM in its manifest binding, and readers
discover captures by scanning tenants, which a VM-keyed path would defeat.

`config::transcript_capture_dir{,_at}` is now the single constructor, and
`a_forensic_capture_is_tenant_then_capture_id_with_no_vm_component` pins the
shape so the two ends cannot drift again.

## Prerequisite for `--with-transcripts`: the anchor is not wired

Choosing the store does not unblock embedding. `emit_transcript_sealed` has
**no production caller** — all three call sites are tests (`emitter.rs` unit,
`transcript.rs`'s `#[cfg(test)] mod tests`, and a conformance step). So
`gateway.transcript_sealed` never reaches a real audit chain, `collect_transcripts`
returns an empty list on any real host, and an embedder would have nothing to
find.

Wiring the sealing verb to emit its anchor in production is the prerequisite,
and it is a transcript-subsystem defect rather than an archive one. Until it
lands, an archive honestly reports zero transcripts because there are zero
anchored transcripts, and `--with-transcripts` stays unadvertised.
