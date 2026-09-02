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
        caller_commitment: None,
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
    let proofs = names.iter().filter(|n| n.starts_with("proofs/")).count();
    let signed = read_manifest(&bytes);
    assert!(proofs > 0, "expected proofs; had {names:?}");
    assert_eq!(
        proofs,
        signed.manifest.leaves.len(),
        "one proof per LEAF -- a citation with no proof is bound to nothing a \
         verifier can check independently of the host's signature"
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
        let proof_member = mvm_hostd::audit::receipt_archive::proof_member_for(leaf.index);
        let proof: mvm_contract::merkle::InclusionProof =
            serde_json::from_slice(&read_member(&bytes, &proof_member)).expect("decode proof");
        assert_eq!(
            proof.leaf_index, leaf.index,
            "{} cites leaf {} but its proof is for leaf {}",
            leaf.member, leaf.index, proof.leaf_index
        );

        // The receipt's own self-locating extension and the manifest's
        // citation must name the same audit entry. They are written by
        // different passes, so agreeing is a property worth pinning rather
        // than an identity.
        let stamped = receipt
            .payload
            .extensions
            .get(mvm_core::receipt::extension_key::AUDIT_DIGEST)
            .and_then(|v| v.as_str())
            .expect("receipt carries its audit digest");
        assert_eq!(
            format!("sha256:{stamped}"),
            leaf.digest,
            "{} stamps a different entry than the manifest cites",
            leaf.member
        );
    }
}

// ─────────────────────────────────────────────────────────────────
// Verifier
// ─────────────────────────────────────────────────────────────────

use mvm_hostd::audit::receipt_archive_verify::{CheckResult, CompletenessResult, verify_archive};

/// Rebuild an archive, applying `edit` to the member map first.
fn rewrite(bytes: &[u8], edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>)) -> Vec<u8> {
    use std::io::Cursor;
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    {
        let mut archive = tar::Archive::new(Cursor::new(bytes));
        for entry in archive.entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let name = entry.path().expect("path").to_string_lossy().into_owned();
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).expect("read");
            members.push((name, buf));
        }
    }
    edit(&mut members);

    let mut out = Cursor::new(Vec::<u8>::new());
    {
        let mut tar = tar::Builder::new(&mut out);
        for (name, bytes) in &members {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, name, Cursor::new(bytes))
                .expect("append");
        }
        tar.finish().expect("finish");
    }
    out.into_inner()
}

fn set_member(members: &mut [(String, Vec<u8>)], name: &str, bytes: Vec<u8>) {
    let slot = members
        .iter_mut()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("member {name} not present"));
    slot.1 = bytes;
}

#[test]
fn a_good_plan_scoped_archive_verifies_and_reports_attested_completeness() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(
        dir.path(),
        ArchiveScope::Plan {
            plan_id: sample_plan_id().0,
        },
    );
    let report = verify_archive(&bytes).expect("verify");
    assert_eq!(report.integrity, CheckResult::Passed, "{report:?}");
    assert_eq!(report.inclusion, CheckResult::Passed, "{report:?}");
    assert_eq!(
        report.completeness,
        CompletenessResult::Attested,
        "a filtered archive's coverage is asserted, never checked"
    );
    assert_eq!(report.exit_code(), 0, "attested is not a failure");
}

#[test]
fn a_tenant_scoped_archive_derives_its_completeness() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let report = verify_archive(&bytes).expect("verify");
    assert_eq!(
        report.completeness,
        CompletenessResult::Derived,
        "{report:?}"
    );
    assert_eq!(report.exit_code(), 0, "{report:?}");
}

#[test]
fn a_tampered_receipt_member_fails_integrity_and_sets_only_that_bit() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let signed = read_manifest(&bytes);
    let victim = signed
        .manifest
        .members
        .keys()
        .find(|k| k.starts_with("receipts/"))
        .expect("a receipt member")
        .clone();

    let tampered = rewrite(&bytes, |m| {
        let mut b = m.iter().find(|(n, _)| *n == victim).unwrap().1.clone();
        let last = b.len() - 1;
        b[last] ^= 0x01;
        set_member(m, &victim, b);
    });

    let report = verify_archive(&tampered).expect("verify runs to completion");
    assert!(
        matches!(report.integrity, CheckResult::Failed(_)),
        "{report:?}"
    );
    assert_eq!(report.exit_code() & 1, 1, "integrity bit must be set");
}

#[test]
fn a_proof_swapped_between_receipts_fails_inclusion() {
    // Both proofs are genuine and both verify against the signed root. Only
    // the binding to each receipt's own leaf catches the swap.
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let names = tar_member_names(&bytes);
    let proofs: Vec<String> = names
        .iter()
        .filter(|n| n.starts_with("proofs/"))
        .cloned()
        .collect();
    assert!(proofs.len() >= 2, "need two proofs to swap; had {proofs:?}");

    let swapped = rewrite(&bytes, |m| {
        let a = m.iter().find(|(n, _)| *n == proofs[0]).unwrap().1.clone();
        let b = m.iter().find(|(n, _)| *n == proofs[1]).unwrap().1.clone();
        set_member(m, &proofs[0], b);
        set_member(m, &proofs[1], a);
    });

    let report = verify_archive(&swapped).expect("verify runs to completion");
    assert!(
        matches!(report.inclusion, CheckResult::Failed(_)),
        "swapping two valid proofs must still fail: {report:?}"
    );
    assert_eq!(report.exit_code() & 2, 2, "inclusion bit must be set");
}

#[test]
fn a_derivable_archive_missing_a_leaf_fails_completeness() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);

    // Drop a leaf from the manifest. The manifest signature breaks too, which
    // is correct and expected -- what this pins is that completeness reports
    // its own failure rather than staying silent because integrity spoke.
    let dropped = rewrite(&bytes, |m| {
        let raw = m
            .iter()
            .find(|(n, _)| n == "manifest.json")
            .unwrap()
            .1
            .clone();
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let leaves = v["manifest"]["leaves"].as_array_mut().unwrap();
        leaves.pop();
        set_member(m, "manifest.json", serde_json::to_vec_pretty(&v).unwrap());
    });

    let report = verify_archive(&dropped).expect("verify runs to completion");
    assert!(
        matches!(report.completeness, CompletenessResult::Failed(_)),
        "{report:?}"
    );
    assert_eq!(report.exit_code() & 4, 4, "completeness bit must be set");
}

#[test]
fn a_foreign_host_key_fails_integrity() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let other = SigningKey::from_bytes(&[3u8; 32]);
    let swapped = rewrite(&bytes, |m| {
        set_member(m, "host.pub", other.verifying_key().to_bytes().to_vec());
    });
    let report = verify_archive(&swapped).expect("verify runs to completion");
    assert!(
        matches!(report.integrity, CheckResult::Failed(_)),
        "an archive shipping a key other than its signer's must not pass: {report:?}"
    );
}

/// Append a raw ustar member with an arbitrary name.
///
/// `tar::Builder` refuses to write a `..` path at all, which is a good
/// property of that crate and useless for testing ours: the archive we need
/// is one a hostile writer produced without it. So the header is hand-rolled.
fn raw_tar_member(name: &str, data: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..107].copy_from_slice(b"0000600");
    header[108..115].copy_from_slice(b"0000000");
    header[116..123].copy_from_slice(b"0000000");
    let size = format!("{:011o}", data.len());
    header[124..135].copy_from_slice(size.as_bytes());
    header[136..147].copy_from_slice(b"00000000000");
    header[148..156].copy_from_slice(b"        "); // checksum field as spaces
    header[156] = b'0'; // regular file
    header[257..262].copy_from_slice(b"ustar");
    header[263..265].copy_from_slice(b"00");
    let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
    let sum_field = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(sum_field.as_bytes());

    let mut out = header.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[test]
fn an_unsafe_member_path_is_refused_before_anything_is_checked() {
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);

    // Splice a traversal member in ahead of the real archive body, then the
    // two terminating zero blocks.
    let mut evil = raw_tar_member("../escape.json", b"{}");
    evil.extend_from_slice(&bytes);

    let names = tar_member_names(&evil);
    assert!(
        names.iter().any(|n| n.contains("..")),
        "the traversal name must survive into the archive or this test proves \
         nothing; members were {names:?}"
    );

    let err = verify_archive(&evil).expect_err("must refuse, not report");
    assert!(format!("{err:#}").contains("rejected"), "{err:#}");
}

#[test]
fn an_oversize_archive_is_refused_before_allocating() {
    let big = vec![0u8; mvm_hostd::audit::receipt_archive_verify::ARCHIVE_MAX_BYTES + 1];
    let err = verify_archive(&big).expect_err("must refuse");
    assert!(format!("{err:#}").contains("limit"), "{err:#}");
}

#[test]
fn the_three_results_are_reported_independently() {
    // One failure must not mask the others: a report names every problem.
    let dir = TempDir::new().unwrap();
    let (bytes, _key) = build(dir.path(), ArchiveScope::Tenant);
    let broken = rewrite(&bytes, |m| {
        let raw = m
            .iter()
            .find(|(n, _)| n == "manifest.json")
            .unwrap()
            .1
            .clone();
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        v["manifest"]["leaves"].as_array_mut().unwrap().pop();
        set_member(m, "manifest.json", serde_json::to_vec_pretty(&v).unwrap());
    });
    let report = verify_archive(&broken).expect("verify runs to completion");
    // Integrity fails (signature) AND completeness fails (leaf count). Both
    // bits, not just the first one encountered.
    assert_eq!(report.exit_code() & 1, 1, "{report:?}");
    assert_eq!(report.exit_code() & 4, 4, "{report:?}");
}
