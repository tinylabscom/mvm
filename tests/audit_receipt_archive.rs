//! End-to-end test of the evidence-archive writer.
//!
//! Builds a synthetic chain-signed audit log, writes a `.mvmev` archive over
//! it, and asserts the archive is internally consistent: every manifest member
//! is present, every leaf is accounted for, and the completeness mode matches
//! the scope it was written for.

use std::collections::BTreeMap;
use std::io::Read;

use ed25519_dalek::SigningKey;
use mvm_core::plan::{PlanId, TenantId};
use mvm_core::receipt_archive::{ArchiveScope, Completeness, SignedEvidenceManifest};
use mvm_hostd::audit::receipt_archive::{ArchiveRequest, write_archive};
use mvm_hostd::supervisor::audit::PlanAuditEntry;
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner};
use tempfile::TempDir;

fn sample_plan_id() -> PlanId {
    PlanId("sha256:0000000000000000000000000000000000000000000000000000000000000001".into())
}

fn sample_audit_entry(event: &str, labels: BTreeMap<String, String>) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: chrono::Utc::now(),
        tenant: TenantId("local".into()),
        plan_id: sample_plan_id(),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "test-image".into(),
        image_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000002"
            .into(),
        event: event.into(),
        labels,
    }
}

/// A chain with receipts, citations, and a sealed-transcript anchor.
fn write_chain(dir: &std::path::Path) -> SigningKey {
    std::fs::create_dir_all(dir).unwrap();
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let signer = FileAuditSigner::open(signing_key.clone(), dir).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let entries = vec![
        sample_audit_entry("plan.admitted", BTreeMap::new()),
        sample_audit_entry("plan.launched", BTreeMap::new()),
        {
            let mut labels = BTreeMap::new();
            labels.insert("host".into(), "evil.example".into());
            sample_audit_entry("flow.egress.denied", labels)
        },
        {
            let mut labels = BTreeMap::new();
            labels.insert(
                mvm_hostd::supervisor::audit::LABEL_CAPTURE_ID.into(),
                "capture-1".into(),
            );
            labels.insert(
                mvm_hostd::supervisor::audit::LABEL_VM_NAME.into(),
                "vm-1".into(),
            );
            labels.insert(
                mvm_hostd::supervisor::audit::LABEL_TRANSCRIPT_ROOT.into(),
                "ab".repeat(32),
            );
            labels.insert(
                mvm_hostd::supervisor::audit::LABEL_CHUNK_COUNT.into(),
                "3".into(),
            );
            sample_audit_entry(
                mvm_hostd::supervisor::audit::TRANSCRIPT_SEALED_EVENT,
                labels,
            )
        },
        sample_audit_entry("plan.exited", BTreeMap::new()),
    ];

    for entry in &entries {
        rt.block_on(signer.sign_and_emit(entry)).unwrap();
    }
    signing_key
}

fn tar_member_names(bytes: &[u8]) -> Vec<String> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    archive
        .entries()
        .expect("tar entries")
        .map(|e| {
            e.expect("tar entry")
                .path()
                .expect("path")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn read_member(bytes: &[u8], want: &str) -> Vec<u8> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    for entry in archive.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        if entry.path().expect("path").to_string_lossy() == want {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).expect("read member");
            return buf;
        }
    }
    panic!(
        "member {want} not in archive; had {:?}",
        tar_member_names(bytes)
    );
}

fn read_manifest(bytes: &[u8]) -> SignedEvidenceManifest {
    serde_json::from_slice(&read_member(bytes, "manifest.json")).expect("decode manifest")
}

fn build(dir: &std::path::Path, scope: ArchiveScope) -> (Vec<u8>, SigningKey) {
    let key = write_chain(dir);
    let req = ArchiveRequest::builder()
        .audit_dir(dir)
        .tenant("local")
        .scope(scope)
        .build()
        .expect("request");
    let bytes = write_archive(&req, &key).expect("write archive");
    (bytes, key)
}

#[test]
fn an_archive_carries_a_member_for_every_manifest_entry() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(
        dir.path(),
        ArchiveScope::Plan {
            plan_id: sample_plan_id().0,
        },
    );

    let names = tar_member_names(&bytes);
    let signed = read_manifest(&bytes);
    for member in signed.manifest.members.keys() {
        assert!(
            names.contains(member),
            "manifest names {member}, archive lacks it; had {names:?}"
        );
    }
    assert!(names.contains(&"manifest.json".to_string()));
    assert!(names.contains(&"manifest.sig".to_string()));
    assert!(names.contains(&"host.pub".to_string()));
}

#[test]
fn the_archive_manifest_verifies_under_its_own_signature() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(
        dir.path(),
        ArchiveScope::Plan {
            plan_id: sample_plan_id().0,
        },
    );
    read_manifest(&bytes).verify().expect("manifest verifies");
}

#[test]
fn a_plan_scoped_archive_records_completeness_as_attested() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(
        dir.path(),
        ArchiveScope::Plan {
            plan_id: sample_plan_id().0,
        },
    );
    assert_eq!(
        read_manifest(&bytes).manifest.completeness,
        Completeness::Attested,
        "a filtered archive cannot have its coverage checked by a verifier"
    );
}

#[test]
fn a_tenant_scoped_archive_records_completeness_as_derivable() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let m = read_manifest(&bytes).manifest;
    assert_eq!(m.completeness, Completeness::Derivable);
    assert_eq!(
        m.leaves.len() as u64,
        m.audit_root.tree_size,
        "a derivable archive must carry every leaf so the count is checkable"
    );
}

#[test]
fn every_leaf_is_accounted_for_and_counted_by_event() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let m = read_manifest(&bytes).manifest;

    let counted: u64 = m.counts_by_event.values().sum();
    assert_eq!(
        counted,
        m.leaves.len() as u64,
        "counts_by_event must total the leaf set: {:?}",
        m.counts_by_event
    );
    assert!(
        m.counts_by_event.contains_key("flow.egress.denied"),
        "the egress denial must be counted; had {:?}",
        m.counts_by_event
    );
}

#[test]
fn a_transcript_anchor_becomes_a_citation_pointing_at_its_chain_leaf() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let m = read_manifest(&bytes).manifest;

    let t = m
        .transcripts
        .first()
        .expect("the sealed-transcript entry must produce a citation");
    assert_eq!(t.capture_id, "capture-1");
    assert_eq!(t.vm_name, "vm-1");
    assert_eq!(t.chunk_count, 3);
    assert!(
        !t.embedded,
        "chunks must not travel unless --with-transcripts asked for them"
    );
    let anchor = m
        .leaves
        .iter()
        .find(|l| l.index == t.anchored_at_leaf)
        .expect("anchor leaf must be in the leaf set");
    assert_eq!(
        anchor.event,
        mvm_hostd::supervisor::audit::TRANSCRIPT_SEALED_EVENT
    );
}

#[test]
fn every_receipt_member_has_a_matching_inclusion_proof() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let names = tar_member_names(&bytes);
    let receipts = names.iter().filter(|n| n.starts_with("receipts/")).count();
    let proofs = names.iter().filter(|n| n.starts_with("proofs/")).count();
    assert!(receipts > 0, "expected receipts; had {names:?}");
    assert_eq!(
        receipts, proofs,
        "one proof per receipt, so a reader can bind each to the signed root"
    );
}

#[test]
fn member_digests_match_the_bytes_actually_written() {
    use sha2::{Digest, Sha256};
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let signed = read_manifest(&bytes);
    for (member, want) in &signed.manifest.members {
        let actual = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(read_member(&bytes, member)))
        );
        assert_eq!(&actual, want, "digest mismatch for {member}");
    }
}

#[test]
fn every_proof_in_the_archive_verifies_against_the_signed_root() {
    // The crux: a proof that folds to its own root proves nothing. Each one
    // must bind to the root the host signed, for the tenant claimed.
    let dir = TempDir::new().unwrap();
    let (bytes, key) = build(dir.path(), ArchiveScope::Tenant);
    let signed = read_manifest(&bytes);

    let names = tar_member_names(&bytes);
    let proof_members: Vec<&String> = names.iter().filter(|n| n.starts_with("proofs/")).collect();
    assert!(!proof_members.is_empty(), "expected proofs; had {names:?}");

    for member in proof_members {
        let proof: mvm_contract::merkle::InclusionProof =
            serde_json::from_slice(&read_member(&bytes, member)).expect("decode proof");
        mvm_contract::merkle::verify_membership(
            &proof,
            &signed.manifest.audit_root,
            &key.verifying_key(),
            "local",
        )
        .unwrap_or_else(|e| panic!("{member} failed membership: {e}"));
    }
}

#[test]
fn the_embedded_host_key_is_the_one_that_signed_the_manifest() {
    // An archive that shipped a key other than the signer's would verify
    // against itself and mean nothing.
    let dir = TempDir::new().unwrap();
    let (bytes, key) = build(dir.path(), ArchiveScope::Tenant);
    let embedded = read_member(&bytes, "host.pub");
    assert_eq!(
        embedded,
        key.verifying_key().to_bytes().to_vec(),
        "host.pub must be the signer's key"
    );
    let signed = read_manifest(&bytes);
    assert_eq!(
        signed.signed_by,
        mvm_core::did_key::DidKey::from_verifying_key(key.verifying_key()).to_did_key()
    );
}

#[test]
fn asking_to_embed_transcripts_refuses_rather_than_silently_citing() {
    // Until chunk embedding lands, --with-transcripts must fail loudly. An
    // archive that quietly cited roots while the caller believed it carried
    // ciphertext would be the worst of both.
    let dir = TempDir::new().unwrap();
    let key = write_chain(dir.path());
    let req = ArchiveRequest::builder()
        .audit_dir(dir.path())
        .tenant("local")
        .scope(ArchiveScope::Tenant)
        .with_transcripts(true)
        .build()
        .expect("request");
    let err = write_archive(&req, &key).expect_err("must refuse");
    assert!(
        format!("{err:#}").contains("not implemented"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn a_request_missing_its_scope_is_refused_by_the_builder() {
    let err = ArchiveRequest::builder()
        .audit_dir("/tmp")
        .tenant("local")
        .build()
        .expect_err("scope is required");
    assert!(format!("{err:#}").contains("scope"), "{err:#}");
}

#[test]
fn each_proof_is_bound_to_the_leaf_its_own_receipt_came_from() {
    // A proof for the wrong leaf still verifies against the root -- it just
    // attests the wrong thing. The binding that makes a proof mean something
    // about *this* receipt is proof.leaf_index == the receipt's leaf citation.
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let signed = read_manifest(&bytes);

    let receipt_leaves: Vec<&mvm_core::receipt_archive::LeafCitation> = signed
        .manifest
        .leaves
        .iter()
        .filter(|l| l.member.starts_with("receipts/"))
        .collect();
    assert!(!receipt_leaves.is_empty());

    for leaf in receipt_leaves {
        let receipt: mvm_core::receipt::SignedExecutionReceipt =
            serde_json::from_slice(&read_member(&bytes, &leaf.member)).expect("decode receipt");
        let proof_member = format!(
            "proofs/{}.json",
            receipt.payload.receipt_id.replace(':', "_")
        );
        let proof: mvm_contract::merkle::InclusionProof =
            serde_json::from_slice(&read_member(&bytes, &proof_member)).expect("decode proof");
        assert_eq!(
            proof.leaf_index, leaf.index,
            "{} cites leaf {} but its proof is for leaf {}",
            leaf.member, leaf.index, proof.leaf_index
        );
    }
}
