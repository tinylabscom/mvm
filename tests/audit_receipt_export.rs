//! End-to-end test of the read-only receipt exporter.
//!
//! Builds a synthetic chain-signed audit log directly, then drives the
//! real `mvmctl trust audit receipts export` binary and asserts the
//! exported receipts verify offline.

use std::collections::BTreeMap;
use std::path::PathBuf;

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use mvm_core::plan::{PlanId, TenantId};
use mvm_core::receipt::{ReceiptOutcome, receipt_type};
use mvm_hostd::supervisor::audit::PlanAuditEntry;
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

struct ExportSandbox {
    home: TempDir,
}

impl ExportSandbox {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn home_path(&self) -> &std::path::Path {
        self.home.path()
    }

    fn mvm_root(&self) -> PathBuf {
        self.home_path().join("mvm-home")
    }

    fn audit_dir(&self) -> PathBuf {
        self.mvm_root().join("audit")
    }

    fn keys_dir(&self) -> PathBuf {
        self.mvm_root().join("keys")
    }

    fn mvmctl(&self) -> Command {
        let mut c = Command::cargo_bin("mvmctl").expect("cargo_bin mvmctl");
        c.env("HOME", self.home_path())
            .env("MVM_HOME", self.mvm_root());
        c
    }
}

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

fn set_secret_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

fn write_test_chain(sandbox: &ExportSandbox) -> SigningKey {
    let keys_dir = sandbox.keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    let audit_dir = sandbox.audit_dir();
    std::fs::create_dir_all(&audit_dir).unwrap();

    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let signer = FileAuditSigner::open(signing_key.clone(), &audit_dir).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let entries = vec![
        sample_audit_entry("plan.admitted", BTreeMap::new()),
        {
            let mut labels = BTreeMap::new();
            labels.insert("backend".into(), "mock".into());
            sample_audit_entry("plan.launched", labels)
        },
        {
            let mut labels = BTreeMap::new();
            labels.insert("backend".into(), "mock".into());
            labels.insert("exit_code".into(), "0".into());
            sample_audit_entry("plan.exited", labels)
        },
    ];

    for entry in &entries {
        rt.block_on(signer.sign_and_emit(entry)).unwrap();
    }

    // Copy the signer pubkey to where `mvmctl` expects it.
    std::fs::write(
        keys_dir.join("host-signer.pub"),
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    std::fs::write(keys_dir.join("host-signer.ed25519"), signing_key.to_bytes()).unwrap();
    set_secret_permissions(&keys_dir.join("host-signer.ed25519"));

    signing_key
}

#[test]
fn receipts_export_json_verifies_offline() {
    let sandbox = ExportSandbox::new();
    let signing_key = write_test_chain(&sandbox);

    let mut cmd = sandbox.mvmctl();
    cmd.args([
        "trust", "audit", "receipts", "export", "--tenant", "local", "--json",
    ]);
    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    let receipts: Vec<mvm_core::receipt::SignedExecutionReceipt> =
        serde_json::from_str(&stdout).expect("parsing exported receipts");
    assert_eq!(receipts.len(), 3);

    let expected_types = [
        receipt_type::PLAN_ADMITTED,
        receipt_type::PLAN_LAUNCHED,
        receipt_type::PLAN_EXITED,
    ];
    for (i, signed) in receipts.iter().enumerate() {
        signed
            .verify()
            .expect("exported receipt signature must verify");
        assert_eq!(signed.payload.receipt_type, expected_types[i]);
        assert_eq!(
            signed.payload.host_did,
            mvm_core::did_key::DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key()
        );
    }
    assert_eq!(receipts[0].payload.outcome, ReceiptOutcome::Authorized);
    assert_eq!(receipts[1].payload.outcome, ReceiptOutcome::Running);
    assert_eq!(receipts[2].payload.outcome, ReceiptOutcome::Succeeded);
}

#[test]
fn receipts_export_with_plan_id_filter() {
    let sandbox = ExportSandbox::new();
    let keys_dir = sandbox.keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    let audit_dir = sandbox.audit_dir();
    std::fs::create_dir_all(&audit_dir).unwrap();

    let signing_key = SigningKey::from_bytes(&[10u8; 32]);
    let signer = FileAuditSigner::open(signing_key.clone(), &audit_dir).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let plan_a = sample_plan_id();
    let plan_b =
        PlanId("sha256:0000000000000000000000000000000000000000000000000000000000000002".into());

    let mut entry_a = sample_audit_entry("plan.admitted", BTreeMap::new());
    entry_a.plan_id = plan_a.clone();
    let mut entry_b = sample_audit_entry("plan.admitted", BTreeMap::new());
    entry_b.plan_id = plan_b.clone();

    rt.block_on(signer.sign_and_emit(&entry_a)).unwrap();
    rt.block_on(signer.sign_and_emit(&entry_b)).unwrap();

    std::fs::write(
        keys_dir.join("host-signer.pub"),
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    std::fs::write(keys_dir.join("host-signer.ed25519"), signing_key.to_bytes()).unwrap();
    set_secret_permissions(&keys_dir.join("host-signer.ed25519"));

    let mut cmd = sandbox.mvmctl();
    cmd.args([
        "trust",
        "audit",
        "receipts",
        "export",
        "--tenant",
        "local",
        "--plan-id",
        &plan_a.0,
        "--json",
    ]);
    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    let receipts: Vec<mvm_core::receipt::SignedExecutionReceipt> =
        serde_json::from_str(&stdout).expect("parsing filtered receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].payload.plan_id, plan_a.0);
}

#[test]
fn receipts_export_empty_chain_reports_no_receipts() {
    let sandbox = ExportSandbox::new();
    let keys_dir = sandbox.keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    let audit_dir = sandbox.audit_dir();
    std::fs::create_dir_all(&audit_dir).unwrap();

    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    std::fs::write(
        keys_dir.join("host-signer.pub"),
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    std::fs::write(keys_dir.join("host-signer.ed25519"), signing_key.to_bytes()).unwrap();
    set_secret_permissions(&keys_dir.join("host-signer.ed25519"));

    let mut cmd = sandbox.mvmctl();
    cmd.args([
        "trust", "audit", "receipts", "export", "--tenant", "local", "--json",
    ]);
    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    let receipts: Vec<mvm_core::receipt::SignedExecutionReceipt> =
        serde_json::from_str(&stdout).expect("parsing empty receipt array");
    assert!(receipts.is_empty());
}

// ─────────────────────────────────────────────────────────────────
// Completeness: every in-scope entry is accounted for
// ─────────────────────────────────────────────────────────────────

/// A chain carrying the event families a real run emits — including the ones
/// that have no receipt mapping and used to fall out of an export silently.
fn write_chain_with_egress_and_input(sandbox: &ExportSandbox) -> SigningKey {
    let keys_dir = sandbox.keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    let audit_dir = sandbox.audit_dir();
    std::fs::create_dir_all(&audit_dir).unwrap();

    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let signer = FileAuditSigner::open(signing_key.clone(), &audit_dir).unwrap();
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
            labels.insert("stream_input_holder".into(), "writer-1".into());
            sample_audit_entry("stream.input_granted", labels)
        },
        sample_audit_entry("plan.exited", BTreeMap::new()),
    ];

    for entry in &entries {
        rt.block_on(signer.sign_and_emit(entry)).unwrap();
    }

    std::fs::write(
        keys_dir.join("host-signer.pub"),
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    std::fs::write(keys_dir.join("host-signer.ed25519"), signing_key.to_bytes()).unwrap();
    set_secret_permissions(&keys_dir.join("host-signer.ed25519"));

    signing_key
}

#[test]
fn every_in_scope_entry_is_either_a_receipt_or_a_citation() {
    let sandbox = ExportSandbox::new();
    let key = write_chain_with_egress_and_input(&sandbox);
    let plan_id = sample_plan_id().0;

    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        &sandbox.audit_dir(),
        "local",
        Some(&plan_id),
        &key,
    )
    .expect("export");

    let path = mvm_hostd::audit::emitter::audit_path_for_tenant(&sandbox.audit_dir(), "local");
    let chain =
        mvm_hostd::supervisor::audit_file::verify_audit_chain_entries(&path, &key.verifying_key())
            .expect("chain");
    let in_scope = chain.iter().filter(|e| e.plan_id.0 == plan_id).count();

    assert_eq!(
        evidence.receipts.len() + evidence.cited.len(),
        in_scope,
        "every in-scope entry must be accounted for exactly once: {} receipts + {} cited != {} entries",
        evidence.receipts.len(),
        evidence.cited.len(),
        in_scope,
    );
}

#[test]
fn egress_decisions_are_cited_rather_than_dropped() {
    let sandbox = ExportSandbox::new();
    let key = write_chain_with_egress_and_input(&sandbox);
    let plan_id = sample_plan_id().0;

    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        &sandbox.audit_dir(),
        "local",
        Some(&plan_id),
        &key,
    )
    .expect("export");

    assert!(
        evidence
            .cited
            .iter()
            .any(|c| c.event == "flow.egress.denied"),
        "an egress denial must appear as a citation; cited events were {:?}",
        evidence.cited.iter().map(|c| &c.event).collect::<Vec<_>>(),
    );
}

#[test]
fn a_citation_carries_the_leaf_index_that_addresses_the_real_tree() {
    let sandbox = ExportSandbox::new();
    let key = write_chain_with_egress_and_input(&sandbox);
    let plan_id = sample_plan_id().0;

    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        &sandbox.audit_dir(),
        "local",
        Some(&plan_id),
        &key,
    )
    .expect("export");

    // The egress denial is the third entry written, so leaf index 2. An index
    // counted within the filtered set would not build a verifying proof.
    let egress = evidence
        .cited
        .iter()
        .find(|c| c.event == "flow.egress.denied")
        .expect("egress citation");
    assert_eq!(
        egress.leaf_index, 2,
        "leaf index must address the full chain"
    );
}

#[test]
fn an_exported_receipt_names_the_chain_position_it_came_from() {
    let sandbox = ExportSandbox::new();
    let key = write_chain_with_egress_and_input(&sandbox);
    let plan_id = sample_plan_id().0;

    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        &sandbox.audit_dir(),
        "local",
        Some(&plan_id),
        &key,
    )
    .expect("export");

    let first = evidence.receipts.first().expect("at least one receipt");
    let ext = &first.payload.extensions;
    for k in [
        mvm_core::receipt::extension_key::AUDIT_DIGEST,
        mvm_core::receipt::extension_key::AUDIT_ROOT,
        mvm_core::receipt::extension_key::TREE_SIZE,
    ] {
        assert!(ext.contains_key(k), "missing extension {k}; had {ext:?}");
    }

    // The extensions are inside the signed payload, so a receipt carrying them
    // still verifies and its content address still matches.
    first
        .verify()
        .expect("receipt still verifies with extensions present");
}

#[test]
fn every_exported_receipt_shares_one_audit_root() {
    // Proofs in an archive all bind to a single root; receipts exported in the
    // same pass must therefore name that same root, not one root each.
    let sandbox = ExportSandbox::new();
    let key = write_chain_with_egress_and_input(&sandbox);
    let plan_id = sample_plan_id().0;

    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        &sandbox.audit_dir(),
        "local",
        Some(&plan_id),
        &key,
    )
    .expect("export");

    let roots: std::collections::BTreeSet<String> = evidence
        .receipts
        .iter()
        .map(|r| {
            r.payload
                .extensions
                .get(mvm_core::receipt::extension_key::AUDIT_ROOT)
                .and_then(|v| v.as_str())
                .expect("audit root extension")
                .to_string()
        })
        .collect();
    assert_eq!(
        roots.len(),
        1,
        "all receipts must cite one root, got {roots:?}"
    );
}

#[test]
fn the_audit_digest_extension_resolves_to_the_entry_it_came_from() {
    let sandbox = ExportSandbox::new();
    let key = write_chain_with_egress_and_input(&sandbox);
    let plan_id = sample_plan_id().0;

    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        &sandbox.audit_dir(),
        "local",
        Some(&plan_id),
        &key,
    )
    .expect("export");

    let path = mvm_hostd::audit::emitter::audit_path_for_tenant(&sandbox.audit_dir(), "local");
    let chain =
        mvm_hostd::supervisor::audit_file::verify_audit_chain_entries(&path, &key.verifying_key())
            .expect("chain");

    // First receipt is plan.admitted, the first chain entry.
    let want = mvm_hostd::audit::evidence::audit_entry_digest_hex(&chain[0]).expect("digest");
    let got = evidence.receipts[0]
        .payload
        .extensions
        .get(mvm_core::receipt::extension_key::AUDIT_DIGEST)
        .and_then(|v| v.as_str())
        .expect("audit digest extension");
    assert_eq!(
        got, want,
        "the digest must identify the exact signed entry bytes"
    );
}
