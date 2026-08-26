# Plan: `.mvmev` Offline Verifiability — Format-Level Canonicalization and Transcript Anchoring

Backing: preview
Validation: none

**Status:** Draft
**Date:** 2026-08-25
**Branch:** `docs/mvmev-canonicalization-spec`
**Issue:** #2863
**Related:** ADR-110, `specs/plans/2026-08-25-execution-contract-qualification-plan.md` (WS1 is separately in flight on `feat/ws1-execution-receipt-completeness`)

## Context

`.mvmev` evidence archives exist so a party outside mvm can check what a host
admitted and executed. Two things stand between that intent and a working
third-party verifier, both surfaced while auditing the qualification answers.

**First, the canonicalization is pinned in Rust and nowhere in the format.**
The manifest ships pretty-printed (`crates/mvm-hostd/src/audit/receipt_archive.rs:471`)
while the signature covers `canonical_json(&manifest)`
(`crates/mvm-core/src/receipt_archive.rs:189`). A reader therefore cannot verify
over the bytes it read — it must parse and re-canonicalize first, and nothing in
the archive says so. The rule itself is good: JCS via `serde_jcs` over a value
space that `validate_value_space` (`crates/mvm-core/src/receipt.rs:288-302`)
restricts to integers and ASCII strings, which is exactly what makes the two
real JCS divergences (ECMAScript float formatting; UTF-16 vs UTF-8 key ordering,
already documented at `crates/mvm-core/src/semantic_address.rs:19`) unreachable
rather than merely specified. It is simply invisible to the audience it was
built for.

**Second, the transcript root is not anchored into the audit chain.** A receipt
carries `mvm.audit_root` / `mvm.tree_size` / `mvm.audit_digest`
(`crates/mvm-core/src/receipt.rs:70-80`), and the tree's leaves are audit JSONL
lines (`crates/mvm-contract/src/merkle.rs:327`). Those leaves are host-observed
control-plane events, carrying no payload bytes by design
(`stream_audit_entries_carry_the_binding_and_no_payload_bytes`,
`crates/mvm-hostd/src/audit/emitter.rs:1627`). The workload's own output does get
a durable encrypted transcript under `StreamRetention::Persist`
(`crates/mvm-contract/src/plan/types.rs:596`) with its own `sealed_root_hex`
(`crates/mvm-hostd/src/stream/durable.rs:312`) — but nothing in
`crates/mvm-hostd/src/stream/` emits to the chain. `emit_transcript_sealed`
(`crates/mvm-hostd/src/audit/emitter.rs:1024`) has exactly one production caller,
the opt-in forensic *network* capture path in
`crates/mvm-cli/src/commands/ops/transcript.rs`. So the stream-plane transcript
of what the workload actually printed sits beside the chain rather than inside
it, and `.mvmev` carries neither the transcript nor a commitment to it.

## Goals

- An outside verifier can implement `.mvmev` verification from published
  documentation and frozen vectors, without reading `mvm-core`.
- The stream-plane transcript root is chain-anchored, so a receipt's audit root
  transitively covers the workload's recorded output.

## Non-goals

- Changing `plan_id`'s derivation (`crates/mvm-core/src/plan/content_id.rs:44`).
  It is host-only by design, the plan body is not in the archive, and no
  external verifier is asked to recompute it.
- Putting payload bytes or plaintext digests into the audit chain. The anchor is
  a ciphertext-manifest root, matching what the existing network-capture path
  already does.
- Re-doing WS1 of the qualification plan (exit code, timing, capabilities,
  network destinations). That work is in flight elsewhere.

---

## Workstream 1 — Specify the canonicalization at the format level

**Priority:** P0. Blocks any third-party verifier.

- [ ] **1.1 Write the canonicalization section.** In ADR-110 or a companion
      reference doc: JCS (RFC 8785) as the base, the admissible value space
      (integers only, ASCII strings only), and why the restriction exists.
- [ ] **1.2 Document the verification order.** Parse `manifest.json`,
      re-canonicalize, then check Ed25519 — stated explicitly, since the shipped
      bytes are not the signed bytes.
- [ ] **1.3 Document the same rule for the other two digests.**
      `SignedExecutionReceipt` (`crates/mvm-core/src/receipt.rs:281`) and
      `EvidenceManifest::compute_id` (`crates/mvm-core/src/receipt_archive.rs:144`,
      which clears `archive_id` before hashing).
- [ ] **1.4 Publish the member layout.** `manifest.json`, `manifest.sig`,
      `host.pub`, `host.did`, and the per-leaf proof members
      (`crates/mvm-hostd/src/audit/receipt_archive.rs:48-62`).
- [ ] **1.5 Publish the three-result verification procedure.** Integrity,
      inclusion, completeness — kept separate, per
      `crates/mvm-hostd/src/audit/receipt_archive_verify.rs:1-26`, including why
      inclusion is two checks rather than one.

## Workstream 2 — Cross-language conformance vectors

**Priority:** P1. Turns WS1's prose into something checkable.

- [ ] **2.1 Freeze a vector set.** Canonical-form inputs and expected bytes
      covering key ordering, escaping, integer bounds, empty containers, and
      nested objects.
- [ ] **2.2 Freeze an end-to-end archive vector.** One `.mvmev` with a known
      host key and expected outcomes for each of the three results.
- [ ] **2.3 Add a negative vector set.** Tampered manifest, wrong-leaf proof,
      missing member, digest drift.
- [ ] **2.4 Gate the vectors.** A test that reads the frozen vectors, so a
      canonicalization change is a red test rather than a silent break.

## Workstream 3 — Value-space constraint as a documented input rule

**Priority:** P2. Small, but currently a surprise failure.

- [ ] **3.1 Document the ASCII constraint where operators see it.** A non-ASCII
      tenant id, workload id, or member path makes a manifest unsignable —
      export fails rather than emitting an unverifiable archive.
- [ ] **3.2 Decide the boundary.** Reject non-ASCII identifiers at admission
      instead of at export, or keep the late failure and say so.
- [ ] **3.3 Add a test for whichever boundary is chosen.**

## Workstream 4 — Anchor the stream-plane transcript root

**Priority:** P1. This is the gap between "what the host authorized" and "what
the workload did".

- [ ] **4.1 Confirm the seal point.** `durable.rs:312` computes
      `sealed_root_hex`; `journal.rs:258` recomputes it on a replayed seal for a
      capture whose owning process died. Both paths need the same anchor, and a
      replayed seal is already marked `adopted`.
- [ ] **4.2 Emit the anchor.** Call the existing `emit_transcript_sealed`
      (`crates/mvm-hostd/src/audit/emitter.rs:1024`) from the stream plane's seal
      path. Reuse it rather than adding a second entry kind.
- [ ] **4.3 Decide the adopted-seal representation.** A replayed seal cannot
      account for records shed at hand-off; the entry should carry that
      distinction rather than presenting a partial transcript as complete.
- [ ] **4.4 Surface the transcript root on the receipt.** As an extension key
      alongside `mvm.audit_root`, so a receipt lifted out of an archive still
      names the transcript it belongs to.
- [ ] **4.5 Tests.** Anchor emitted on seal; anchor emitted on replayed seal and
      distinguishable from a live one; label set pinned exhaustively so a future
      label carrying payload bytes fails, mirroring
      `stream_audit_entries_carry_the_binding_and_no_payload_bytes`.
- [ ] **4.6 Run gates.** `just fmt-check`, `just clippy`, `just check-gated`,
      `cargo nextest run --workspace`, `just test-doc`, and the xtask gates.

## Open questions

- Should the manifest carry a canonicalization identifier, so a future change is
  detectable by a verifier rather than silent? (WS1)
- Does `Ephemeral` retention need an explicit chain entry recording that no
  transcript exists, so absence is attested rather than merely absent? (WS4)
