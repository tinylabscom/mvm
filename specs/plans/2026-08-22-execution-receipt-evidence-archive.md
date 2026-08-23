# Execution-receipt evidence archive

Backing: preview
Validation: none

**Status:** WS1-WS4 + WS6 shipped. WS3 shipped except transcript embedding.
WS5 (mvmd storage) is specced in the mvmd repo and not started.

**Shipped differences from this design**, recorded here rather than left for a
reader to discover:

- Proofs are per **leaf**, not per receipt (`proofs/leaf-<index>.json`). A
  citation with no proof was bound to nothing a verifier could check
  independently of the host's signature. Found by running the exporter.
- The sealed-transcript event is `gateway.transcript_sealed`, not
  `transcript.sealed` as first written here.
- Inclusion is two checks, not one: membership *plus*
  `proof.leaf_index == leaf.index`. A proof for the wrong leaf verifies.
- `--with-transcripts` is not implemented and not advertised. The store is
  now decided (the forensic `mvm_transcripts_dir`, layout
  `<tenant>/<capture-id>`); embedding is blocked on `emit_transcript_sealed`
  having no production caller, so nothing is anchored to embed. ADR-110.

**Date:** 2026-08-22
**Owner:** mvm
**Source:** [`specs/plans/298-nanda-receipts-and-conformance-badges.md`](298-nanda-receipts-and-conformance-badges.md) WS3/WS4

**Goal:** Make an `ExecutionReceipt` export render the *whole* evidence set for
one workload run — the egress and ingress decisions, the transcript anchors,
and every other chain entry in scope — either as one JSON document or as a
signed `.mvmev` archive that re-verifies with no access to the host that
produced it.

---

## Problem

`mvmctl trust audit receipts export` today
(`crates/mvm-hostd/src/audit/receipt_export.rs:33`) verifies the tenant chain,
maps entries to receipts, signs each one, and prints a JSON array. Three things
keep that from being a full rendering.

### 1. Evidence is dropped without saying so

`map_event_to_receipt_type` (`receipt_export.rs:103`) matches thirteen event
names and `return None`s everything else. The caller's `None => continue`
(`receipt_export.rs:55`) discards the entry silently. Dropped today:

| Event family | Emitted by | Carries |
|---|---|---|
| `flow.egress.allowed` / `flow.egress.denied` | `EventCategory::Flow`, `audit_recorder.rs` | the claim-10 decision per outbound connection |
| `stream.subscribed` | `emitter.rs:85` | who attached to workload output, and from which seq |
| `stream.input_granted` | `emitter.rs:105` | who was admitted to workload stdin |
| `gateway.transcript_sealed` | `emitter.rs:1005` | the sealed transcript manifest root |
| `dns.*`, `policy.*`, `secret.*`, `key.*` | `audit_recorder.rs` taxonomy | resolution, policy load, secret CRUD, key rotation |

An operator reading the current output has no way to tell an export with no
egress from an export whose egress entries were skipped. That ambiguity is the
defect; the archive format is the fix for it.

### 2. A receipt does not link back to the chain it came from

The payload carries `plan_id` and hoisted labels, but not the digest of the
audit line it derives from, no leaf index, no inclusion proof, and no signed
root. The primitives already exist and are unwired:

- `mvm_contract::merkle` — RFC 6962 `InclusionProof` and `SignedAuditRoot`,
  `no_std`, browser-runnable.
- `mvm_hostd::audit::merkle::build_root_in` / `build_inclusion_in`
  (`merkle.rs:93`, `merkle.rs:101`) — builds both over the *verbatim*
  `<tenant>.jsonl` lines, and refuses to build over a chain
  `verify_audit_chain` rejects.
- `mvm_hostd::audit::evidence::audit_entry_digest_hex` — the exact
  signed-bytes digest of one entry.

### 3. There is no archive

Nothing bundles the receipts with the chain segments, the transcript
manifests, and the host public key. A receipt array alone cannot be re-checked
away from the host, because the material it would be checked against is not in
it.

---

## Non-goals

- **Fleet aggregation.** A second-order Merkle tree over per-host
  `SignedAuditRoot`s is a separate design and a separate ADR. This spec keeps
  every archive anchored to exactly one host's tree.
- **Promoting egress/ingress to receipt types.** A chatty workload emits
  egress decisions at network rates; one signature each would make receipt
  volume a function of traffic. They are cited, not minted.
- **Folding in the gateway's RBAC log.** `mvmd-gateway`'s SQLite `audit_logs`
  table records control-plane API calls under its own HKDF chain key. That is
  a different evidence class with a different actor model and stays in its own
  chain.
- **Decrypting transcripts.** Sealed chunks travel as ciphertext or not at all.

---

## Design

### Scope unit

One archive covers **one plan** — one admitted workload run — selected by
`--plan-id`. That matches what a receipt is about and what gets handed to
someone. `--full-chain` widens to the whole tenant; see *Completeness* for why
that mode exists.

### Archive layout

A plain tar named `<plan-id-short>.mvmev`, mirroring the `.mvmpkg`
manifest-plus-signature shape in `crates/mvm-core/src/plan/bundle.rs:46`. No
gzip: the members are JSON and already-compressed ciphertext.

```
manifest.json                    the signed index (schema below)
manifest.sig                     64-byte Ed25519 over JCS(manifest.json)
host.pub                         32-byte host verifying key
host.did                         did:key form, for readers that want the string
receipts/<seq>-<type>.json       SignedExecutionReceipt, chain order
proofs/<receipt_id>.json         InclusionProof against manifest.audit_root
audit/<tenant>.jsonl             the raw signed lines in scope
audit/<tenant>.seg-NNNNNN.jsonl  retired segments, when the range spans them
cited/<leaf_index>.json          in-scope entries with no receipt mapping
transcripts/<capture>/manifest.json   sealed manifest (always)
transcripts/<capture>/chunks/…        ciphertext (only under --with-transcripts)
```

`cited/` is what closes gap 1. Every in-scope chain entry lands in exactly one
of `receipts/` or `cited/`, and the manifest counts both.

### `manifest.json`

```jsonc
{
  "schema_version": 1,
  "archive_id": "sha256:…",        // over JCS of this object minus archive_id
  "tenant": "local",
  "scope": { "kind": "plan", "plan_id": "sha256:…" },   // or { "kind": "tenant" }
  "host_did": "did:key:z6Mk…",
  "audit_root": { "root_hash": "…", "tree_size": 41230, "signature": "…" },
  "leaves": [
    { "index": 903, "digest": "sha256:…", "event": "plan.admitted",
      "member": "receipts/001-plan.admitted.json" },
    { "index": 904, "digest": "sha256:…", "event": "flow.egress.denied",
      "member": "cited/904.json" }
  ],
  "counts_by_event": { "plan.admitted": 1, "flow.egress.denied": 17, … },
  "transcripts": [
    { "capture_id": "capture-1", "vm_name": "vm-1", "root": "sha256:…",
      "chunk_count": 3, "embedded": false, "anchored_at_leaf": 1102 }
  ],
  "members": { "receipts/001-plan.admitted.json": "sha256:…", … },
  "completeness": "attested"      // or "derivable" under --full-chain
}
```

`audit_root` is a `SignedAuditRoot` verbatim, so the same `no_std` verifier a
browser runs checks it.

### Citation model

For each leaf in `manifest.leaves`, the archive carries an `InclusionProof`
whose `leaf_line` is the exact `SignedEnvelope` JSON line. A reader:

1. verifies `audit_root` against `host.pub` (`verify_signed_root`);
2. verifies each `InclusionProof` and checks `proof.root == audit_root.root_hash`
   **and** `proof.tree_size == audit_root.tree_size` — the binding step
   `mvm_contract::merkle` calls out at `merkle.rs:120`, without which a
   fabricated proof self-verifies;
3. re-hashes each member against `manifest.members`;
4. verifies each receipt's own Ed25519 signature and recomputes its
   `receipt_id` from `JCS(payload)`.

Transcripts are cited by the root already written into the chain by
`emit_transcript_sealed`, so `transcripts[].root` is checkable against a leaf
whether or not the chunks travel.

### Receipt payload extensions

`ExecutionReceipt.extensions` is a `BTreeMap<String, Value>` with
`#[serde(default)]`, so three new namespaced keys need no schema bump and no
migration:

- `mvm.audit_digest` — the entry digest from `audit_entry_digest_hex`
- `mvm.audit_root` — the root hash the receipt was exported against
- `mvm.tree_size` — that root's tree size

A receipt lifted out of the archive and mailed on its own now names where it
came from. These are part of the signed payload, so they are covered by the
receipt signature.

### Completeness, and the limit on it

Under `--plan-id`, a verifier can check that every listed leaf really sits in
the authenticated tree at its stated index, and that no listed leaf was
fabricated. It **cannot** independently rule out an omitted in-scope entry: a
subsequence carries nothing that would attest its own completeness, and
detecting the gap needs the whole log.

So the manifest carries a host assertion — *"these leaf indices are every entry
with `plan_id = X` in the tree at `tree_size = T`"* — signed with the rest of
the manifest. The verifier reports it as `attested`, distinct from what it
checked itself. This is the same class of limit as claim 8's tail-truncation
gap, and it gets stated in the CLI output rather than hidden under a single
green line.

`--full-chain` removes the limit by construction: a tenant-scoped archive
embeds every leaf, so a verifier compares `leaves.len()` against
`audit_root.tree_size` and derives completeness with no host assertion
involved. The manifest then records `"completeness": "derivable"`.

### CLI surface

```
mvmctl trust audit receipts export --plan-id <id> [--json | --archive <path>]
                                   [--with-transcripts] [--full-chain]
mvmctl trust audit receipts verify <archive.mvmev> [--json]
```

`--json` gains the citations inline — the same content as the archive manifest
plus the receipts and cited entries, as one document, for the case where a file
is the wrong shape. `--archive` writes the tar.

`verify` reports three independent results and does not collapse them:

| Result | Basis | Exit bit |
|---|---|---|
| chain + signature integrity | checked from the archive | 1 |
| leaf inclusion under the signed root | checked from the archive | 2 |
| scope completeness | checked only under `--full-chain`, else host-attested | 4 |

Nonzero exit means at least one failed; the bits say which. A run whose
completeness is attested rather than checked exits 0 and says so on stderr.

---

## mvmd side: store and index, one level up

mvmd can hold an archive; it cannot produce or extend one. The tree is over a
single host's `<tenant>.jsonl`, the proofs bind to that host's signed root, the
transcripts live in that host's state dir, and the signature is that host's
signer key. So the contract is deliberately narrow.

**Store.** A content-addressed blob store keyed by `archive_id`, per fleet
instance. Archives are opaque: mvmd never unpacks to re-sign, never merges two
hosts' archives, never rewrites a manifest. Retention is a storage policy, not
an evidence decision.

**Index.** A row per archive:

| Column | Source |
|---|---|
| `archive_id` | manifest |
| `tenant`, `plan_id` | `manifest.scope` |
| `host_did` | manifest |
| `audit_root`, `tree_size` | `manifest.audit_root` |
| `completeness` | manifest |
| `instance_id`, `pool_id` | mvmd's own placement records |
| `receipt_ids[]` | `manifest.leaves` where `member` is under `receipts/` |

That is enough to answer "which host's archive covers this run" and "give me
every archive for this tenant" without opening a blob.

**Verification stays borrowed.** mvmd links `mvmctl` already
(`mvmctl = { path = "../mvm" }`), so `receipts verify` runs as library code on
ingest. mvmd records the three results as attributes on the index row. It does
not implement a second verifier — two verifiers drift, and the drift is
invisible until one is wrong.

**Explicitly out.** No fleet-wide root, no cross-host completeness claim, no
promotion of the gateway RBAC log into this store.

---

## Limits

Stated here so no later reader has to infer them:

- Plan-scoped completeness is host-attested. Only `--full-chain` makes it
  verifier-derivable.
- Tail truncation of the underlying chain stays undetectable, unchanged from
  claim 8. An archive cannot be more complete than the log it reads.
- An archive without `--with-transcripts` cites transcript roots it does not
  carry. A reader can check the root against a leaf; it cannot read the bytes.
- Embedded transcript chunks stay AEAD-sealed under the host KEK. An archive
  handed to an auditor does not open without that key.
- `SignedExecutionReceipt.signed_at` is outside the signed payload and remains
  forgeable, as `receipt.rs` already notes. `issued_at` is signed.

---

## Workstreams

### WS1 — Manifest and archive types

- [ ] Add `EvidenceArchiveManifest`, `LeafCitation`, `TranscriptCitation`,
      `Completeness` to `mvm-core` (or `mvm-contract` if the verifier is to be
      browser-runnable — decide in WS1, it drives everything downstream).
- [ ] JCS canonicalization + Ed25519 signing over the manifest, reusing the
      existing helpers rather than adding a second path.
- [ ] Serde roundtrip, default-value, and tampered-manifest rejection tests.

### WS2 — Exporter: stop dropping entries

- [ ] Replace `map_event_to_receipt_type`'s silent `None` with an explicit
      `Mapped(type, outcome) | Cited` split so an unmapped event is a recorded
      outcome, not a fallthrough.
- [ ] Emit `cited/` entries with leaf index and digest for every in-scope
      entry with no receipt mapping.
- [ ] Populate `mvm.audit_digest` / `mvm.audit_root` / `mvm.tree_size` on
      exported receipts.
- [ ] Test: a fixture chain carrying `flow.egress.denied` and
      `stream.input_granted` exports them as citations; assert the count
      matches the chain's, and mutate the fixture to confirm the test goes red.

### WS3 — Archive writer

- [ ] Build the tar (manifest, signature, host key, receipts, proofs, audit
      lines, cited entries, transcript manifests).
- [ ] `--with-transcripts` embeds ciphertext chunks; default cites only.
- [ ] `--full-chain` widens scope and sets `completeness: derivable`.
- [ ] Reuse `bundle.rs`'s path-safety rules for tar member names; a member
      name is attacker-influenced the moment an archive is read back.

### WS4 — Verifier and CLI

- [ ] `mvmctl trust audit receipts verify <archive>` with the three-result
      report and the exit-bit encoding.
- [ ] Extend `--json` export to carry citations inline.
- [ ] Negative tests, one per rejection: bad manifest signature, member digest
      mismatch, proof whose root disagrees with the signed root, receipt whose
      recomputed `receipt_id` differs, leaf count inconsistent with
      `tree_size` under `--full-chain`, unsafe tar member path.
- [ ] Test that an attested-completeness archive does not report as derivable.

### WS5 — mvmd store and index

- [ ] Content-addressed archive blob store per fleet instance.
- [ ] Index table and the query surface for it.
- [ ] Ingest calls `mvmctl`'s verifier as a library and records all three
      results.
- [ ] Test: an archive whose inclusion check fails is stored but indexed as
      failing, and is not served as evidence.

### WS6 — Documentation

- [ ] `public/src/content/docs/reference/cli-commands.md` entries.
- [ ] An ADR for the archive format and the attested-versus-derivable split.
- [ ] Update `specs/plans/298-nanda-receipts-and-conformance-badges.md` WS3/WS4
      to point here.

---

## Files touched

**mvm**

- `crates/mvm-core/src/receipt.rs` — extension key constants
- `crates/mvm-contract/src/merkle.rs` — read-only consumer, no change expected
- `crates/mvm-hostd/src/audit/receipt_export.rs` — mapping split, citations
- `crates/mvm-hostd/src/audit/receipt_archive.rs` — new, the writer
- `crates/mvm-hostd/src/audit/receipt_archive_verify.rs` — new, the verifier
- `crates/mvm-cli/src/commands/ops/audit.rs` — `export` flags, `verify`
- `tests/audit_receipt_export.rs` — extended
- `tests/audit_receipt_archive.rs` — new

**mvmd**

- `crates/mvmd-core/src/audit.rs` — evidence-archive types re-exported
- store + index crate placement decided in WS5

---

## Testing

Beyond the per-workstream tests: every rejection path gets a test that mutates
a good archive into a bad one and asserts the specific refusal, rather than
asserting a generic error. A test that would pass against an archive with no
egress entries at all is not a test of the completeness rule.
