# Execution-receipt evidence archive — implementation plan

Backing: preview
Validation: none

**Status:** Tasks 1-8 complete. Transcript chunk embedding remains; see
ADR-110's open question.

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans` to implement this task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `mvmctl trust audit receipts export` render a run's whole
evidence set — receipts, inclusion proofs, and a citation for every in-scope
audit entry with no receipt mapping — as JSON or as a signed `.mvmev` tar that
re-checks with no access to the host that wrote it.

**Architecture:** Compose what already exists rather than adding a parallel
stack. `mvm_hostd::audit::merkle` already builds roots and inclusion proofs
over the verbatim chain lines; `mvm_cli`'s private `run_verify_inclusion`
already composes the four-step membership check. Task 1 moves that composition
down into `mvm-contract` so both the archive verifier and a browser can call
it. The archive itself is a plain tar with a signed manifest, mirroring
`mvm_core::plan::bundle`'s `.mvmpkg` shape.

**Tech Stack:** Rust, `tar` 0.4 (no gzip), `ed25519-dalek` 3, `serde_jcs`,
`sha2` 0.11, `mvm-contract` (`no_std` + alloc).

**Spec:** [`specs/plans/2026-08-22-execution-receipt-evidence-archive.md`](2026-08-22-execution-receipt-evidence-archive.md)

## Global Constraints

- **Crate placement is fixed by dependency direction.** `mvm-contract` has
  `serde`, `serde_json` (alloc), `sha2`, `ed25519-dalek` and deliberately **no
  `serde_jcs`** — JCS is host-only there. So: pure membership checking goes in
  `mvm-contract`; anything that canonicalizes for signing goes in `mvm-core`
  (which owns `receipt::canonical_json`); anything touching the filesystem or
  tar goes in `mvm-hostd`.
- **No `#[allow(clippy::too_many_arguments)]`.** Banned outright. A function
  that trips the lint gets a params struct with a builder.
- **No plan/PR/ADR references in code comments.** CI-gated by
  `check-no-spec-refs-in-comments`.
- **All `~/.mvm` paths go through `mvm_core::config`** helpers
  (`mvm_audit_dir`, `audit_root_path`, …). Never `std::env::var("HOME")`.
- **New `specs/` files need a `Backing:` / `Validation:` header** in the first
  40 lines, or `check-declared-backing` fails.
- Gate command after every task: `cargo nextest run -p <crate>` for the touched
  crate, then `just check-gated` before any push.

---

### Task 1: Move the membership check into `mvm-contract`

The four-step check (signed root verifies, root is for the intended tenant,
proof is internally consistent, proof binds to *this* root) lives today as a
private `fn run_verify_inclusion` in `crates/mvm-cli/src/commands/ops/audit.rs`.
The archive verifier needs the same composition. Copying it would create the
second verifier the spec rules out, so it moves down.

**Files:**
- Modify: `crates/mvm-contract/src/merkle.rs` (add `verify_membership` + `MembershipError`)
- Modify: `crates/mvm-cli/src/commands/ops/audit.rs:877` (`run_verify_inclusion` delegates)
- Test: `crates/mvm-contract/src/merkle.rs` (inline `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `mvm_contract::merkle::verify_membership(proof: &InclusionProof, root: &SignedAuditRoot, vk: &VerifyingKey, expected_tenant: &str) -> Result<(), MembershipError>`
- Produces: `pub enum MembershipError { RootSignature(MerkleError), TenantMismatch { signed: String, expected: String }, Inclusion(MerkleError), RootBinding { proof: String, signed: String }, TreeSizeBinding { proof: u64, signed: u64 } }`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/mvm-contract/src/merkle.rs`. The existing
module already has helpers for building a tree and signing a root; reuse them
rather than adding new fixtures.

```rust
#[test]
fn membership_rejects_a_self_consistent_proof_over_an_unsigned_root() {
    let (key, leaves) = fixture_chain(8);
    let signed = fixture_signed_root(&key, "local", &leaves);
    // A proof built over a *different* leaf set folds to its own root fine,
    // but that root is not the one the host signed.
    let (_other_key, other_leaves) = fixture_chain(4);
    let proof = build_inclusion_proof(&other_leaves, 1).expect("proof");
    let err = verify_membership(&proof, &signed, &key.verifying_key(), "local")
        .expect_err("a proof over a different tree must not pass");
    assert!(matches!(err, MembershipError::RootBinding { .. }));
}

#[test]
fn membership_rejects_a_genuinely_signed_root_for_another_tenant() {
    let (key, leaves) = fixture_chain(8);
    let signed = fixture_signed_root(&key, "other-tenant", &leaves);
    let proof = build_inclusion_proof(&leaves, 3).expect("proof");
    let err = verify_membership(&proof, &signed, &key.verifying_key(), "local")
        .expect_err("a root for another tenant is not evidence for this one");
    assert!(matches!(err, MembershipError::TenantMismatch { .. }));
}

#[test]
fn membership_accepts_a_proof_bound_to_its_own_signed_root() {
    let (key, leaves) = fixture_chain(8);
    let signed = fixture_signed_root(&key, "local", &leaves);
    let proof = build_inclusion_proof(&leaves, 3).expect("proof");
    verify_membership(&proof, &signed, &key.verifying_key(), "local").expect("membership");
}
```

If `fixture_chain` / `fixture_signed_root` do not exist under those names in
the module, read the existing `mod tests` and use whatever it already calls;
do not add a parallel fixture set.

- [ ] **Step 2: Run the tests, verify they fail**

```
cargo nextest run -p mvm-contract membership
```

Expected: FAIL, `cannot find function verify_membership`.

- [ ] **Step 3: Implement `verify_membership`**

```rust
/// Why [`verify_membership`] refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    /// The signed root did not verify under the trusted key.
    #[error("signed-root verification failed: {0}")]
    RootSignature(MerkleError),
    /// The root is genuinely signed, but for a different tenant.
    #[error("tenant binding failed: signed root is for '{signed}', expected '{expected}'")]
    TenantMismatch {
        /// Tenant the signed root names.
        signed: String,
        /// Tenant the caller intended.
        expected: String,
    },
    /// The proof is not internally consistent.
    #[error("inclusion-proof verification failed: {0}")]
    Inclusion(MerkleError),
    /// The proof folds to a root other than the signed one.
    #[error("root binding failed: proof root {proof} is not the signed root {signed}")]
    RootBinding {
        /// Root the proof folds to.
        proof: String,
        /// Root the host signed.
        signed: String,
    },
    /// The proof's tree size disagrees with the signed root's.
    #[error("tree-size binding failed: proof says {proof}, signed root says {signed}")]
    TreeSizeBinding {
        /// Tree size the proof carries.
        proof: u64,
        /// Tree size the signed root carries.
        signed: u64,
    },
}

/// The full membership check: a verified proof plus the binding that makes it
/// attest membership in a real published log rather than in its own arithmetic.
///
/// Fail-closed and ordered, so a refusal names the check that failed.
pub fn verify_membership(
    proof: &InclusionProof,
    root: &SignedAuditRoot,
    vk: &VerifyingKey,
    expected_tenant: &str,
) -> Result<(), MembershipError> {
    verify_signed_root(root, vk).map_err(MembershipError::RootSignature)?;
    if root.tenant != expected_tenant {
        return Err(MembershipError::TenantMismatch {
            signed: root.tenant.clone(),
            expected: expected_tenant.into(),
        });
    }
    verify_inclusion(proof).map_err(MembershipError::Inclusion)?;
    if proof.root != root.root_hash {
        return Err(MembershipError::RootBinding {
            proof: proof.root.clone(),
            signed: root.root_hash.clone(),
        });
    }
    if proof.tree_size != root.tree_size {
        return Err(MembershipError::TreeSizeBinding {
            proof: proof.tree_size,
            signed: root.tree_size,
        });
    }
    Ok(())
}
```

- [ ] **Step 4: Run the tests, verify they pass**

```
cargo nextest run -p mvm-contract membership
```

Expected: 3 passed.

- [ ] **Step 5: Make the CLI delegate**

Replace the body of `run_verify_inclusion` in
`crates/mvm-cli/src/commands/ops/audit.rs` so the four checks are no longer
spelled out there. Keep the function and its success message — its callers and
tests stay as they are.

```rust
fn run_verify_inclusion(
    proof: &InclusionProof,
    signed_root: &SignedAuditRoot,
    vk: &VerifyingKey,
    expected_tenant: &str,
) -> Result<String> {
    mvm_contract::merkle::verify_membership(proof, signed_root, vk, expected_tenant)?;
    Ok(format!(
        "inclusion verified: leaf {idx} of {n} in tenant '{expected_tenant}' (root {root})",
        idx = proof.leaf_index,
        n = proof.tree_size,
        root = signed_root.root_hash,
    ))
}
```

Keep the existing success-message wording if it differs; the CLI tests assert
on it.

- [ ] **Step 6: Run the CLI's existing inclusion tests**

```
cargo nextest run -p mvm-cli inclusion
```

Expected: PASS with no test changes. If a test fails on message wording, the
message moved — restore the original string rather than editing the test.

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-contract/src/merkle.rs crates/mvm-cli/src/commands/ops/audit.rs
git commit -m "contract: lift the inclusion-membership check out of the CLI

The archive verifier needs the same four-step composition the CLI already
had privately. Two copies would drift, and the drift stays invisible until
one of them is wrong, so it moves down to where both can call it."
```

---

### Task 2: Manifest types and signing in `mvm-core`

**Files:**
- Create: `crates/mvm-core/src/receipt_archive.rs`
- Modify: `crates/mvm-core/src/lib.rs` (add `pub mod receipt_archive;`)
- Test: inline `#[cfg(test)] mod tests` in the new file

**Interfaces:**
- Consumes: `mvm_core::receipt::canonical_json`, `mvm_core::did_key::DidKey`
- Produces: `EvidenceManifest`, `LeafCitation`, `TranscriptCitation`, `Completeness`, `ArchiveScope`, `SignedEvidenceManifest`
- Produces: `SignedEvidenceManifest::sign(EvidenceManifest, &SigningKey, impl Into<String>) -> Result<Self, ReceiptError>` and `::verify(&self) -> Result<(), ReceiptError>`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fixture_manifest() -> EvidenceManifest {
        EvidenceManifest {
            schema_version: 1,
            archive_id: String::new(),
            tenant: "local".into(),
            scope: ArchiveScope::Plan { plan_id: "sha256:aa".into() },
            host_did: "did:key:z6MkTest".into(),
            audit_root: fixture_signed_root(),
            leaves: vec![LeafCitation {
                index: 903,
                digest: "sha256:bb".into(),
                event: "flow.egress.denied".into(),
                member: "cited/903.json".into(),
            }],
            counts_by_event: [("flow.egress.denied".to_string(), 1u64)].into_iter().collect(),
            transcripts: Vec::new(),
            members: [("cited/903.json".to_string(), "sha256:bb".to_string())]
                .into_iter().collect(),
            completeness: Completeness::Attested,
        }
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let m = fixture_manifest();
        let s = serde_json::to_string(&m).expect("serialize");
        let back: EvidenceManifest = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(m, back);
    }

    #[test]
    fn completeness_serializes_as_a_word_not_a_bool() {
        let s = serde_json::to_string(&Completeness::Attested).expect("serialize");
        assert_eq!(s, "\"attested\"");
        let s = serde_json::to_string(&Completeness::Derivable).expect("serialize");
        assert_eq!(s, "\"derivable\"");
    }

    #[test]
    fn signing_populates_the_archive_id_as_a_content_address() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = SignedEvidenceManifest::sign(fixture_manifest(), &key, "2026-08-22T00:00:00Z")
            .expect("sign");
        assert!(signed.manifest.archive_id.starts_with("sha256:"));
        signed.verify().expect("verify");
    }

    #[test]
    fn a_tampered_manifest_field_fails_verification() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut signed = SignedEvidenceManifest::sign(fixture_manifest(), &key, "2026-08-22T00:00:00Z")
            .expect("sign");
        signed.manifest.completeness = Completeness::Derivable;
        assert!(signed.verify().is_err(), "flipping completeness must break the signature");
    }

    #[test]
    fn an_unknown_manifest_field_is_refused() {
        let raw = r#"{"schema_version":1,"archive_id":"sha256:aa","tenant":"local",
            "scope":{"kind":"plan","plan_id":"sha256:aa"},"host_did":"did:key:z",
            "audit_root":{},"leaves":[],"counts_by_event":{},"transcripts":[],
            "members":{},"completeness":"attested","surprise":true}"#;
        assert!(serde_json::from_str::<EvidenceManifest>(raw).is_err());
    }
}
```

Write `fixture_signed_root()` returning a `mvm_contract::merkle::SignedAuditRoot`
with fixed field values; it is not verified in these tests.

- [ ] **Step 2: Run the tests, verify they fail**

```
cargo nextest run -p mvm-core receipt_archive
```

Expected: FAIL, the module does not exist.

- [ ] **Step 3: Implement the module**

Every struct gets `#[serde(deny_unknown_fields)]` — the host↔guest rule in
this repo applies to anything crossing a trust boundary, and an archive read
back from disk is exactly that. `archive_id` is computed over the JCS of the
manifest with `archive_id` blanked, the same trick `ExecutionReceipt::compute_id`
uses; follow that function's shape rather than inventing a second convention.

```rust
//! The signed index of an evidence archive.

use crate::did_key::DidKey;
use crate::receipt::{ReceiptError, canonical_json};
use mvm_contract::merkle::SignedAuditRoot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Whether the archive's scope completeness was checked or asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Completeness {
    /// The host asserts the leaf set is every in-scope entry. A verifier
    /// cannot check this from a filtered archive alone.
    Attested,
    /// The archive carries every leaf, so a verifier derives completeness by
    /// comparing the leaf count against the signed root's tree size.
    Derivable,
}

/// What one archive covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum ArchiveScope {
    /// One admitted plan.
    Plan {
        /// Content address of the plan.
        plan_id: String,
    },
    /// A whole tenant's chain.
    Tenant,
}
```

Then `LeafCitation { index: u64, digest: String, event: String, member: String }`,
`TranscriptCitation { capture_id, vm_name, root, chunk_count: u64, embedded: bool, anchored_at_leaf: u64 }`,
`EvidenceManifest` with the fields the fixture names, and:

```rust
impl EvidenceManifest {
    /// Content address of this manifest: `sha256(JCS(self with archive_id blanked))`.
    pub fn compute_id(&self) -> Result<String, ReceiptError> {
        let mut probe = self.clone();
        probe.archive_id = String::new();
        let canonical = canonical_json(&probe)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(&canonical))))
    }
}
```

`SignedEvidenceManifest { manifest, signed_by, signed_at, signature }` mirrors
`SignedExecutionReceipt` exactly — including that `signed_at` is outside the
signed material. `sign` sets `archive_id` from `compute_id` before signing.

- [ ] **Step 4: Run the tests, verify they pass**

```
cargo nextest run -p mvm-core receipt_archive
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/receipt_archive.rs crates/mvm-core/src/lib.rs
git commit -m "core: add the evidence-archive manifest types

Content-addressed and signed the same way a receipt is, so an archive
carries its own identity rather than borrowing its filename's."
```

---

### Task 3: Stop the exporter dropping entries

`map_event_to_receipt_type` returns `Option` and the caller writes
`None => continue`, so an entry with no receipt mapping leaves no trace. Make
the outcome a two-armed enum so the compiler forces every call site to say what
happens to an unmapped entry.

**Files:**
- Modify: `crates/mvm-hostd/src/audit/receipt_export.rs:33` (`export_receipts`), `:103` (`map_event_to_receipt_type`)
- Test: `tests/audit_receipt_export.rs`

**Interfaces:**
- Produces: `pub enum EntryMapping { Receipt { receipt_type: &'static str, outcome: ReceiptOutcome }, Cited }`
- Produces: `pub struct ExportedEvidence { pub receipts: Vec<SignedExecutionReceipt>, pub cited: Vec<CitedEntry> }`
- Produces: `pub struct CitedEntry { pub leaf_index: u64, pub digest: String, pub event: String, pub plan_id: String, pub timestamp: String }`
- Produces: `pub fn export_evidence(audit_dir: &Path, tenant: &str, plan_id_filter: Option<&str>, signing_key: &SigningKey) -> Result<ExportedEvidence>`

Keep the existing `export_receipts` as a thin wrapper returning
`export_evidence(...).receipts`, so current callers and tests are untouched.

- [ ] **Step 1: Write the failing test**

In `tests/audit_receipt_export.rs`, beside the existing fixture helpers:

```rust
#[test]
fn every_in_scope_entry_is_either_a_receipt_or_a_citation() {
    let (dir, key, plan_id) = fixture_chain_with_egress_and_input();
    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        dir.path(), "local", Some(&plan_id), &key,
    )
    .expect("export");

    let chain = mvm_hostd::supervisor::audit_file::verify_audit_chain_entries(
        &mvm_hostd::audit::emitter::audit_path_for_tenant(dir.path(), "local"),
        &key.verifying_key(),
    )
    .expect("chain");
    let in_scope = chain.iter().filter(|e| e.plan_id.0 == plan_id).count();

    assert_eq!(
        evidence.receipts.len() + evidence.cited.len(),
        in_scope,
        "every in-scope entry must be accounted for exactly once",
    );
}

#[test]
fn egress_decisions_are_cited_rather_than_dropped() {
    let (dir, key, plan_id) = fixture_chain_with_egress_and_input();
    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        dir.path(), "local", Some(&plan_id), &key,
    )
    .expect("export");
    assert!(
        evidence.cited.iter().any(|c| c.event == "flow.egress.denied"),
        "an egress denial must appear as a citation; cited events were {:?}",
        evidence.cited.iter().map(|c| &c.event).collect::<Vec<_>>(),
    );
}
```

`fixture_chain_with_egress_and_input` builds a chain containing at minimum:
`plan.admitted`, `plan.launched`, `flow.egress.denied`, `stream.input_granted`,
`plan.exited`. Model it on whatever fixture builder the file already has.

- [ ] **Step 2: Run the tests, verify they fail**

```
cargo nextest run --test audit_receipt_export
```

Expected: FAIL, `export_evidence` not found.

- [ ] **Step 3: Verify the test can go red for the right reason**

Before implementing, temporarily make `fixture_chain_with_egress_and_input`
emit no `flow.egress.denied` entry and confirm
`egress_decisions_are_cited_rather_than_dropped` fails on the assertion rather
than passing vacuously. Restore the fixture afterwards. A test that would pass
against an empty cited list is not testing this.

- [ ] **Step 4: Implement the mapping split**

```rust
/// What an audit entry becomes in an export.
///
/// Two arms rather than an `Option` so a new event has to be classified
/// rather than silently falling out of the export.
pub enum EntryMapping {
    /// Maps to a receipt of this type and outcome.
    Receipt {
        /// Wire-stable receipt type.
        receipt_type: &'static str,
        /// Outcome the receipt records.
        outcome: ReceiptOutcome,
    },
    /// No receipt mapping; carried as a citation instead.
    Cited,
}

fn map_event(event: &str) -> EntryMapping {
    match event {
        "plan.admitted" => EntryMapping::Receipt {
            receipt_type: receipt_type::PLAN_ADMITTED,
            outcome: ReceiptOutcome::Authorized,
        },
        // … the existing twelve arms, unchanged …
        _ => EntryMapping::Cited,
    }
}
```

`export_evidence` walks the verified entries once, tracking the leaf index (the
position in the full verified chain, **not** the filtered position — the index
has to address the real tree), and pushes into `receipts` or `cited`. Compute
each citation's digest with
`crate::audit::evidence::audit_entry_digest_hex(&entry)`.

- [ ] **Step 5: Run the tests, verify they pass**

```
cargo nextest run --test audit_receipt_export
```

Expected: PASS, including the pre-existing tests in the file.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-hostd/src/audit/receipt_export.rs tests/audit_receipt_export.rs
git commit -m "hostd: account for every in-scope audit entry in an export

An entry with no receipt mapping used to hit None => continue and leave no
trace, so an export with no egress read identically to an export whose
egress was skipped. Unmapped entries are now carried as citations."
```

---

### Task 4: Self-locating receipts

**Files:**
- Modify: `crates/mvm-core/src/receipt.rs` (extension key constants)
- Modify: `crates/mvm-hostd/src/audit/receipt_export.rs` (populate them)
- Test: `tests/audit_receipt_export.rs`

**Interfaces:**
- Consumes: `EntryMapping` from Task 3
- Produces: `mvm_core::receipt::extension_key::{AUDIT_DIGEST, AUDIT_ROOT, TREE_SIZE}` — the string values `"mvm.audit_digest"`, `"mvm.audit_root"`, `"mvm.tree_size"`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn an_exported_receipt_names_the_chain_position_it_came_from() {
    let (dir, key, plan_id) = fixture_chain_with_egress_and_input();
    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        dir.path(), "local", Some(&plan_id), &key,
    )
    .expect("export");
    let first = evidence.receipts.first().expect("at least one receipt");
    let ext = &first.payload.extensions;
    assert!(ext.contains_key(mvm_core::receipt::extension_key::AUDIT_DIGEST));
    assert!(ext.contains_key(mvm_core::receipt::extension_key::AUDIT_ROOT));
    assert!(ext.contains_key(mvm_core::receipt::extension_key::TREE_SIZE));
    // The extensions are inside the signed payload, so the receipt still verifies.
    first.verify().expect("receipt still verifies with extensions present");
}
```

- [ ] **Step 2: Run it, verify it fails**

```
cargo nextest run --test audit_receipt_export chain_position
```

Expected: FAIL on the first `contains_key`.

- [ ] **Step 3: Implement**

Add the constants to `receipt.rs` in a `pub mod extension_key` beside the
existing `pub mod receipt_type`. In `export_evidence`, build the root once
before the loop with `crate::audit::merkle::build_root_in(audit_dir, tenant, vk)`
and insert all three keys into each receipt's `extensions` **before**
`compute_id` runs — they are signed material, so an insert after the id is
computed produces a receipt whose id does not match its content.

- [ ] **Step 4: Run it, verify it passes**

```
cargo nextest run --test audit_receipt_export
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/receipt.rs crates/mvm-hostd/src/audit/receipt_export.rs tests/audit_receipt_export.rs
git commit -m "core, hostd: let a receipt name where in the chain it came from

A receipt lifted out of an archive and sent on alone carried no way back to
the log it derives from. Three namespaced extensions fix that, inside the
signed payload so they travel under the existing signature."
```

---

### Task 5: The archive writer

**Files:**
- Create: `crates/mvm-hostd/src/audit/receipt_archive.rs`
- Modify: `crates/mvm-hostd/src/audit/mod.rs` (declare the module)
- Test: `tests/audit_receipt_archive.rs` (new)

**Interfaces:**
- Consumes: `ExportedEvidence` (Task 3), `SignedEvidenceManifest` (Task 2)
- Produces: `pub struct ArchiveRequest { pub audit_dir: PathBuf, pub tenant: String, pub scope: ArchiveScope, pub with_transcripts: bool }` plus `ArchiveRequest::builder()`
- Produces: `pub fn write_archive(req: &ArchiveRequest, signing_key: &SigningKey) -> Result<Vec<u8>>` — returns the tar bytes; the caller writes the file

A params struct, not five positional arguments: the constraint against
`too_many_arguments` is absolute here.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn an_archive_carries_a_member_for_every_manifest_entry() {
    let (dir, key, plan_id) = fixture_chain_with_egress_and_input();
    let req = ArchiveRequest::builder()
        .audit_dir(dir.path())
        .tenant("local")
        .scope(ArchiveScope::Plan { plan_id: plan_id.clone() })
        .build();
    let bytes = write_archive(&req, &key).expect("write");

    let names = tar_member_names(&bytes);
    let manifest = read_manifest(&bytes);
    for member in manifest.manifest.members.keys() {
        assert!(names.contains(member), "manifest names {member}, archive lacks it");
    }
    assert!(names.contains("manifest.json"));
    assert!(names.contains("host.pub"));
}

#[test]
fn a_plan_scoped_archive_records_completeness_as_attested() {
    let (dir, key, plan_id) = fixture_chain_with_egress_and_input();
    let req = ArchiveRequest::builder()
        .audit_dir(dir.path())
        .tenant("local")
        .scope(ArchiveScope::Plan { plan_id })
        .build();
    let bytes = write_archive(&req, &key).expect("write");
    assert_eq!(read_manifest(&bytes).manifest.completeness, Completeness::Attested);
}

#[test]
fn a_tenant_scoped_archive_records_completeness_as_derivable() {
    let (dir, key, _plan_id) = fixture_chain_with_egress_and_input();
    let req = ArchiveRequest::builder()
        .audit_dir(dir.path())
        .tenant("local")
        .scope(ArchiveScope::Tenant)
        .build();
    let bytes = write_archive(&req, &key).expect("write");
    let m = read_manifest(&bytes).manifest;
    assert_eq!(m.completeness, Completeness::Derivable);
    assert_eq!(m.leaves.len() as u64, m.audit_root.tree_size,
        "a derivable archive must carry every leaf");
}
```

Write `tar_member_names(&[u8]) -> Vec<String>` and
`read_manifest(&[u8]) -> SignedEvidenceManifest` as test helpers in the same file.

- [ ] **Step 2: Run them, verify they fail**

```
cargo nextest run --test audit_receipt_archive
```

Expected: FAIL, module does not exist.

- [ ] **Step 3: Implement the writer**

Order of operations matters and is not arbitrary:

1. `export_evidence(...)` for the scope.
2. `build_root_in(...)` once — every proof binds to this one root.
3. Sign the root into a `SignedAuditRoot` the way
   `AuditEmitter::publish_root` (`emitter.rs:1111`) already does; call that
   rather than re-deriving the signing bytes.
4. `build_inclusion_in(...)` per receipt leaf index.
5. Copy the in-scope raw chain lines into `audit/`.
6. Collect transcript citations from `gateway.transcript_sealed` entries; embed chunks
   only when `with_transcripts`.
7. Hash every member, fill `members`, `counts_by_event`, `leaves`.
8. Set `completeness` from the scope: `Plan` → `Attested`, `Tenant` → `Derivable`.
9. Sign the manifest, then write the tar with `manifest.json` and
   `manifest.sig` first, mirroring `bundle.rs:853`.

Reuse `mvm_core::plan::bundle::ensure_safe_path` on every member name before
writing it. A name is attacker-influenced the moment an archive is read back,
and the rule already exists.

- [ ] **Step 4: Run them, verify they pass**

```
cargo nextest run --test audit_receipt_archive
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/audit/receipt_archive.rs crates/mvm-hostd/src/audit/mod.rs tests/audit_receipt_archive.rs
git commit -m "hostd: write signed evidence archives

A tar carrying the receipts, an inclusion proof per receipt against one
signed root, the raw chain lines, and a citation for every in-scope entry
with no receipt mapping."
```

---

### Task 6: The archive verifier

**Files:**
- Create: `crates/mvm-hostd/src/audit/receipt_archive_verify.rs`
- Modify: `crates/mvm-hostd/src/audit/mod.rs`
- Test: `tests/audit_receipt_archive.rs`

**Interfaces:**
- Consumes: `mvm_contract::merkle::verify_membership` (Task 1)
- Produces: `pub struct VerifyReport { pub integrity: CheckResult, pub inclusion: CheckResult, pub completeness: CompletenessResult }`
- Produces: `pub enum CheckResult { Passed, Failed(String) }`
- Produces: `pub enum CompletenessResult { Derived, Attested, Failed(String) }`
- Produces: `pub fn verify_archive(bytes: &[u8]) -> Result<VerifyReport>`
- Produces: `impl VerifyReport { pub fn exit_code(&self) -> i32 }` — bit 1 integrity, bit 2 inclusion, bit 4 completeness

`CompletenessResult` has three arms, not two, because "the host said so" is
neither a pass nor a failure and collapsing it into `Passed` is the
wrong-reason pass this whole design exists to avoid.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_good_archive_verifies_and_reports_attested_completeness() {
    let bytes = fixture_plan_scoped_archive();
    let report = verify_archive(&bytes).expect("verify");
    assert!(matches!(report.integrity, CheckResult::Passed));
    assert!(matches!(report.inclusion, CheckResult::Passed));
    assert!(matches!(report.completeness, CompletenessResult::Attested));
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn a_tenant_scoped_archive_derives_completeness() {
    let bytes = fixture_tenant_scoped_archive();
    let report = verify_archive(&bytes).expect("verify");
    assert!(matches!(report.completeness, CompletenessResult::Derived));
}

#[test]
fn a_tampered_member_fails_inclusion_and_sets_its_exit_bit() {
    let bytes = tamper_one_receipt_byte(fixture_plan_scoped_archive());
    let report = verify_archive(&bytes).expect("verify runs to completion");
    assert!(matches!(report.inclusion, CheckResult::Failed(_)));
    assert_eq!(report.exit_code() & 2, 2);
}

#[test]
fn a_proof_bound_to_a_foreign_root_is_refused() {
    let bytes = swap_in_a_foreign_signed_root(fixture_plan_scoped_archive());
    let report = verify_archive(&bytes).expect("verify runs to completion");
    assert!(matches!(report.inclusion, CheckResult::Failed(_)));
}

#[test]
fn a_derivable_archive_missing_a_leaf_fails_completeness() {
    let bytes = drop_one_leaf(fixture_tenant_scoped_archive());
    let report = verify_archive(&bytes).expect("verify runs to completion");
    assert!(matches!(report.completeness, CompletenessResult::Failed(_)));
    assert_eq!(report.exit_code() & 4, 4);
}

#[test]
fn an_unsafe_member_path_is_refused_before_any_write() {
    let bytes = inject_member_named("../escape.json", fixture_plan_scoped_archive());
    assert!(verify_archive(&bytes).is_err());
}
```

- [ ] **Step 2: Run them, verify they fail**

```
cargo nextest run --test audit_receipt_archive verify
```

Expected: FAIL, `verify_archive` not found.

- [ ] **Step 3: Implement**

`verify_archive` reads members into memory (bounded — refuse an archive over a
configured size before allocating), then:

- **integrity**: manifest signature verifies under the embedded `host.pub`;
  every member's sha256 matches `manifest.members`; every receipt's own
  `verify()` passes and its recomputed `receipt_id` matches.
- **inclusion**: for each leaf, `verify_membership(proof, &manifest.audit_root,
  &vk, &manifest.tenant)`.
- **completeness**: `Derivable` → compare `leaves.len()` against
  `audit_root.tree_size`, report `Derived` or `Failed`. `Attested` → report
  `Attested` without checking, because there is nothing here to check it with.

Each of the three runs independently and records its own result; one failing
does not short-circuit the others, so a report names every problem rather than
the first.

- [ ] **Step 4: Run them, verify they pass**

```
cargo nextest run --test audit_receipt_archive
```

Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/audit/receipt_archive_verify.rs crates/mvm-hostd/src/audit/mod.rs tests/audit_receipt_archive.rs
git commit -m "hostd: verify evidence archives, reporting three results separately

Integrity and inclusion are checked from the archive. Scope completeness is
only checked for a tenant-scoped archive; for a plan-scoped one it is what
the host asserted, and the report says so rather than showing one green
line over all three."
```

---

### Task 7: CLI surface

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/audit.rs:235` (`ReceiptsAction`), `:486` (`audit_receipts_export`)
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `write_archive`, `verify_archive`, `VerifyReport::exit_code`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn receipts_export_accepts_archive_and_transcript_flags() {
    let out = mvmctl(&["trust", "audit", "receipts", "export", "--help"]);
    assert!(out.contains("--archive"));
    assert!(out.contains("--with-transcripts"));
    assert!(out.contains("--full-chain"));
}

#[test]
fn receipts_verify_is_a_dispatched_verb() {
    let out = mvmctl(&["trust", "audit", "receipts", "verify", "--help"]);
    assert!(out.contains("archive"));
}
```

The second test matters more than it looks: this repo has shipped an
unreachable `up::Args` whose flags were never wired to a `Commands` variant.
Asserting the verb dispatches is what keeps that from recurring.

- [ ] **Step 2: Run them, verify they fail**

```
cargo nextest run --test cli receipts
```

Expected: FAIL, unknown subcommand `verify`.

- [ ] **Step 3: Implement**

Extend `ReceiptsAction::Export` with `archive: Option<PathBuf>`,
`with_transcripts: bool`, `full_chain: bool`. Add
`ReceiptsAction::Verify { archive: PathBuf, json: bool }`. Wire both into the
existing `match` at `:373`.

`--json` and `--archive` are mutually exclusive; use clap's `conflicts_with`
rather than checking at runtime.

`verify` prints all three results and exits with `report.exit_code()`. When
completeness is `Attested`, print a line on stderr saying it was asserted by
the host and not checked, and name `--full-chain` as the mode that checks it.

- [ ] **Step 4: Run them, verify they pass**

```
cargo nextest run --test cli receipts
```

- [ ] **Step 5: Round-trip by hand**

```
cargo run -- trust audit receipts export --tenant local --archive /tmp/ev.mvmev
cargo run -- trust audit receipts verify /tmp/ev.mvmev; echo "exit=$?"
```

Expected: exit 0, three result lines, and a note that completeness is attested.
Write scratch files under `/tmp` only — never inside the repo tree.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/audit.rs tests/cli.rs
git commit -m "cli: export and verify evidence archives"
```

---

### Task 8: Documentation, ADR, and the rollups

**Files:**
- Modify: `public/src/content/docs/reference/cli-commands.md`
- Create: `specs/adrs/0NN-evidence-archive.md` (next free number; scan `specs/adrs/` first)
- Modify: `specs/plans/298-nanda-receipts-and-conformance-badges.md` (WS3/WS4 point here)
- Modify: `specs/REFACTOR-STATUS.md` (add the entry, bump "Last updated")
- Create: `specs/sprint/delivery/<issue>-evidence-archive.md`

- [ ] **Step 1: Write the ADR**

Record the format, and the attested-versus-derivable split with its reasoning.
The ADR needs a `Backing:` / `Validation:` header like any other `specs/` file.

- [ ] **Step 2: Update the CLI reference**

`check-cli-help-matches-docs` compares the doc against actual `--help` output,
so copy the real text rather than paraphrasing.

- [ ] **Step 3: Update the rollups**

Tick the matching boxes in `specs/REFACTOR-STATUS.md` and bump its date.
**Do not append to `specs/SPRINT.md`** — `check-sprint-append` fails if its
delivery section grows. Delivery goes in its own file under
`specs/sprint/delivery/`.

- [ ] **Step 4: Run the full gate set**

```
cargo fmt --all -- --check
cargo nextest run --workspace
cargo test --workspace --doc
cargo clippy --workspace -- -D warnings
just check-gated
```

Run every `xtask` gate the workflows invoke, from **inside this worktree** —
a binary built elsewhere roots its paths at the wrong tree and reports ~50
bogus failures.

- [ ] **Step 5: Commit**

```bash
git add public specs
git commit -m "docs: document the evidence archive and record the ADR"
```

---

## Self-review

**Spec coverage.** WS1 → Task 2 (types) + Task 1 (the placement fork, resolved:
pure checking in `mvm-contract`, JCS signing in `mvm-core`). WS2 → Tasks 3–4.
WS3 → Tasks 5, 8 (transcripts and `--full-chain` are folded into the writer
rather than split out; they are one code path and a reviewer could not
meaningfully accept one and reject the other). WS4 → Tasks 6–7. WS6 → Task 8.
WS5 is mvmd's and is out of this plan.

**Type consistency.** `ExportedEvidence.cited` is `Vec<CitedEntry>` in Task 3
and is what Task 5 turns into `LeafCitation` (Task 2) for the manifest — the
two are deliberately distinct: one is an export result, one is a wire type.
`Completeness` is the same enum in Tasks 2, 5, and 6. `verify_membership`'s
signature in Task 1 is what Task 6 calls.

**Known gap.** The bounded-read limit in Task 6 ("refuse an archive over a
configured size") has no number in it. Pick one when implementing, from
whatever `mvm-core` already uses for bounded reads, and state it in the ADR.
