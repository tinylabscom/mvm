//! Frozen end-to-end `.mvmev` archive vectors.
//!
//! [`mvmev_canonicalization_vectors`](../../mvm-core/tests/mvmev_canonicalization_vectors.rs)
//! freezes the canonical *bytes* an implementation must produce. This freezes
//! the layer above: a whole archive, and what a verifier must conclude about
//! it. A non-Rust verifier can be pointed at `tests/vectors/mvmev-archive-v1.tar`
//! and checked against `tests/vectors/mvmev-archive-v1.json` without reading
//! `mvm-core`.
//!
//! **Why the archive is committed rather than rebuilt.** `signed_at` comes from
//! the wall clock and is deliberately outside the signature, so two builds of
//! the same chain differ byte-for-byte. A frozen artifact is also the only
//! honest cross-language vector: it pins what an *existing* archive must verify
//! as, not what this code happens to emit today. Regenerate with
//! `MVM_REGENERATE_VECTORS=1 cargo test -p mvm-hostd --test mvmev_archive_vectors -- --ignored`.
//!
//! **The negatives are derived from the same frozen bytes**, so each one is a
//! single named mutation of a known-good archive rather than an independently
//! built artifact that might differ for reasons the test did not intend.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use mvm_core::receipt_archive::SignedEvidenceManifest;
use sha2::{Digest, Sha256};

use ed25519_dalek::SigningKey;
use mvm_core::plan::{PlanId, TenantId};
use mvm_core::receipt_archive::ArchiveScope;
use mvm_hostd::audit::receipt_archive::{ArchiveRequest, proof_member_for, write_archive};
use mvm_hostd::audit::receipt_archive_verify::verify_archive;
use mvm_hostd::supervisor::audit::PlanAuditEntry;
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner};

const ARCHIVE_PATH: &str = "../../tests/vectors/mvmev-archive-v1.tar";

/// The directory prefix proof members live under, taken from the naming rule
/// itself. Hardcoding it let three mutations below silently become no-ops when
/// the guess was wrong; the guard assertions caught it, and this stops the
/// guess existing at all.
fn proof_prefix() -> String {
    let sample = proof_member_for(0);
    sample
        .split_once('/')
        .map(|(dir, _)| format!("{dir}/"))
        .unwrap_or(sample)
}

const EXPECTED_PATH: &str = "../../tests/vectors/mvmev-archive-v1.json";

fn archive_bytes() -> Vec<u8> {
    std::fs::read(ARCHIVE_PATH).expect("the frozen .mvmev archive vector must exist")
}

/// What a verifier must conclude about the frozen archive.
///
/// Read from the sidecar rather than hardcoded here: the sidecar is the
/// cross-language contract, and a Rust test asserting its own private
/// expectations would let the two drift without anything noticing.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    #[allow(dead_code)]
    description: String,
    host_pubkey_hex: String,
    integrity: String,
    inclusion: String,
    completeness: String,
    exit_code: i32,
    #[allow(dead_code)]
    negatives: Vec<Negative>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Negative {
    name: String,
    mutation: String,
    fails: String,
}

fn expected() -> Expected {
    serde_json::from_slice(&std::fs::read(EXPECTED_PATH).expect("sidecar must exist"))
        .expect("sidecar must deserialize")
}

/// The key the frozen archive was signed under. Test-only and committed on
/// purpose: a vector nobody can verify is not a vector.
const VECTOR_KEY_SEED: [u8; 32] = [7u8; 32];

fn entry(event: &str, secs: i64) -> PlanAuditEntry {
    PlanAuditEntry {
        // Fixed, not `now()`: a vector whose contents drift with the clock
        // cannot be reasoned about by whoever reads it next.
        timestamp: chrono::DateTime::from_timestamp(1_756_080_000 + secs, 0)
            .expect("fixed vector timestamp is valid"),
        tenant: TenantId("local".into()),
        plan_id: PlanId(
            "sha256:0000000000000000000000000000000000000000000000000000000000000001".into(),
        ),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "vector-image".into(),
        image_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000002"
            .into(),
        event: event.into(),
        labels: BTreeMap::new(),
    }
}

/// Rebuild the vector archive from a fixed chain under a fixed key.
fn build_vector_archive() -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = SigningKey::from_bytes(&VECTOR_KEY_SEED);
    let signer = FileAuditSigner::open(key.clone(), dir.path()).expect("signer");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    for (i, event) in ["plan.admitted", "plan.launched", "plan.exited"]
        .iter()
        .enumerate()
    {
        rt.block_on(signer.sign_and_emit(&entry(event, i as i64)))
            .expect("emit");
    }
    let req = ArchiveRequest::builder()
        .audit_dir(dir.path())
        .tenant("local")
        .scope(ArchiveScope::Tenant)
        .build()
        .expect("request");
    write_archive(&req, &key).expect("write archive")
}

#[test]
#[ignore = "regenerates a committed fixture; run explicitly"]
fn regenerate_the_frozen_archive_vector() {
    assert!(
        std::env::var("MVM_REGENERATE_VECTORS").is_ok(),
        "refusing to overwrite a committed vector without MVM_REGENERATE_VECTORS=1"
    );
    std::fs::write(ARCHIVE_PATH, build_vector_archive()).expect("write the frozen archive");
}

#[test]
fn the_frozen_archive_matches_its_declared_outcomes() {
    // Tenant scope, so completeness is Derivable and checkable from the
    // archive alone rather than asserted by the host.
    let want = expected();
    let report = verify_archive(&archive_bytes()).expect("the frozen archive parses");

    assert_eq!(
        report.integrity.passed(),
        want.integrity == "pass",
        "integrity: {:?}",
        report.integrity
    );
    assert_eq!(
        report.inclusion.passed(),
        want.inclusion == "pass",
        "inclusion: {:?}",
        report.inclusion
    );
    assert_eq!(report.exit_code(), want.exit_code);
    assert!(
        format!("{:?}", report.completeness)
            .to_lowercase()
            .contains(&want.completeness),
        "completeness must be {}, got {:?}",
        want.completeness,
        report.completeness
    );

    // The key is part of the contract: a verifier that cannot check the
    // signature under the published key has not verified anything.
    let embedded = explode(&archive_bytes())
        .into_iter()
        .find(|(n, _)| n == "host.pub")
        .expect("host.pub member")
        .1;
    assert_eq!(
        hex::encode(&embedded),
        want.host_pubkey_hex,
        "the archive's embedded key must be the one the sidecar publishes"
    );
}

/// Read a tar into ordered `(name, bytes)` pairs.
fn explode(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut ar = tar::Archive::new(Cursor::new(bytes));
    for entry in ar.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        let name = entry.path().expect("path").to_string_lossy().into_owned();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).expect("read member");
        out.push((name, buf));
    }
    out
}

/// Rebuild a tar from `(name, bytes)` pairs, preserving order.
fn implode(members: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut builder = tar::Builder::new(&mut buf);
        for (name, bytes) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            builder
                .append_data(&mut header, name, Cursor::new(bytes.clone()))
                .expect("append");
        }
        builder.finish().expect("finish");
    }
    buf.into_inner()
}

/// Swap two members' bodies while leaving their names in place.
trait SwapBodies {
    fn swap_bodies(&mut self, a: usize, b: usize);
}

impl SwapBodies for Vec<(String, Vec<u8>)> {
    fn swap_bodies(&mut self, a: usize, b: usize) {
        let tmp = self[a].1.clone();
        self[a].1 = self[b].1.clone();
        self[b].1 = tmp;
    }
}

/// Apply one named mutation to the frozen archive.
fn mutate(f: impl Fn(&mut Vec<(String, Vec<u8>)>)) -> Vec<u8> {
    let mut members = explode(&archive_bytes());
    f(&mut members);
    implode(&members)
}

#[test]
fn a_tampered_manifest_fails_integrity() {
    // The signature covers the canonical form of the manifest, so any edit to
    // its content breaks it -- even one that leaves valid JSON.
    let bytes = mutate(|members| {
        for (name, body) in members.iter_mut() {
            if name == "manifest.json" {
                let mut v: serde_json::Value = serde_json::from_slice(body).expect("manifest json");
                v["manifest"]["tenant"] = serde_json::Value::String("not-local".into());
                *body = serde_json::to_vec_pretty(&v).expect("reserialize");
            }
        }
    });
    let report = verify_archive(&bytes).expect("a tampered archive still parses");
    assert!(
        !report.integrity.passed(),
        "a tampered manifest must fail integrity"
    );
    assert_ne!(report.exit_code() & 1, 0, "integrity bit must be set");
}

#[test]
fn a_missing_member_fails_integrity() {
    // The manifest names its members; one that is gone cannot be digested.
    let bytes = mutate(|members| {
        let before = members.len();
        let prefix = proof_prefix();
        members.retain(|(name, _)| !name.starts_with(&prefix));
        assert!(
            before > members.len(),
            "the fixture must really drop a member"
        );
    });
    let report = verify_archive(&bytes).expect("parses");
    assert!(
        !report.integrity.passed(),
        "a manifest naming an absent member must fail integrity"
    );
}

#[test]
fn digest_drift_in_a_member_fails_integrity() {
    // The member is present and the manifest is untouched; only the bytes
    // moved. This is the case a presence-only check would wave through.
    let bytes = mutate(|members| {
        let prefix = proof_prefix();
        let mut touched = false;
        for (name, body) in members.iter_mut() {
            if name.starts_with(&prefix) && !touched {
                body.push(b' ');
                touched = true;
            }
        }
        assert!(touched, "the fixture must really perturb a member");
    });
    let report = verify_archive(&bytes).expect("parses");
    assert!(
        !report.integrity.passed(),
        "a member whose digest drifted must fail integrity"
    );
}

#[test]
fn a_proof_moved_to_another_leaf_fails_inclusion_with_integrity_intact() {
    // The property the verifier module calls out: `verify_membership` attests
    // that a leaf is in the tree, and says nothing about *which* leaf the
    // proof was built for. A proof standing in for another leaf verifies
    // perfectly as a Merkle proof while attesting the wrong entry.
    //
    // Swapping the bodies alone would break their digests and integrity would
    // fail first, so the leaf_index cross-check would never run and this test
    // would pass without testing anything. So the manifest is repaired and
    // re-signed under the vector key: integrity passes, and inclusion is the
    // only thing left that can catch it.
    let prefix = proof_prefix();
    let mut members = explode(&archive_bytes());
    let idx: Vec<usize> = members
        .iter()
        .enumerate()
        .filter(|(_, (n, _))| n.starts_with(&prefix))
        .map(|(i, _)| i)
        .collect();
    assert!(
        idx.len() >= 2,
        "the fixture needs at least two proofs to swap; found {}",
        idx.len()
    );
    let (a, b) = (idx[0], idx[1]);
    members.swap_bodies(a, b);

    // Repair the manifest so integrity has nothing to complain about.
    let key = SigningKey::from_bytes(&VECTOR_KEY_SEED);
    let manifest_idx = members
        .iter()
        .position(|(n, _)| n == "manifest.json")
        .expect("manifest member");
    let signed: SignedEvidenceManifest =
        serde_json::from_slice(&members[manifest_idx].1).expect("manifest json");
    let mut manifest = signed.manifest;
    for i in [a, b] {
        let (name, body) = &members[i];
        manifest.members.insert(
            name.clone(),
            format!("sha256:{}", hex::encode(Sha256::digest(body))),
        );
    }
    let resigned = SignedEvidenceManifest::sign(manifest, &key, signed.signed_at)
        .expect("re-sign the repaired manifest");
    members[manifest_idx].1 = serde_json::to_vec_pretty(&resigned).expect("serialize");
    let sig_idx = members
        .iter()
        .position(|(n, _)| n == "manifest.sig")
        .expect("signature member");
    members[sig_idx].1 = resigned.signature.as_bytes().to_vec();

    let report = verify_archive(&implode(&members)).expect("parses");
    assert!(
        report.integrity.passed(),
        "the repair must leave integrity clean, or this proves nothing: {:?}",
        report.integrity
    );
    assert!(
        !report.inclusion.passed(),
        "a proof standing in for another leaf must fail inclusion"
    );
    assert_ne!(report.exit_code() & 2, 0, "inclusion bit must be set");
}
