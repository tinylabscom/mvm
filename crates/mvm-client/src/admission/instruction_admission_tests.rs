//! Admission end to end with instruction-file provenance: a real plan is
//! synthesized, signed and verified, and the chain-signed log is read back.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

use super::admit_plan_tests::{pinning_params, write_rootfs};
use super::*;

struct Fixture {
    _dir: tempfile::TempDir,
    rootfs: PathBuf,
    keys: PathBuf,
    audit: PathBuf,
    policy: PathBuf,
    mount: PathBuf,
}

fn publisher_key() -> SigningKey {
    SigningKey::from_bytes(&[21; 32])
}

/// A rootfs, key and audit directories, a mount holding one `CLAUDE.md`, and
/// a user policy at `policy` (written only when `enforcement` is given).
fn fixture(enforcement: Option<&str>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let rootfs = write_rootfs(dir.path(), b"instruction rootfs");
    let mount = dir.path().join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    std::fs::write(mount.join("CLAUDE.md"), b"review every change\n").unwrap();
    let policy = dir.path().join("instruction-trust.toml");
    if let Some(enforcement) = enforcement {
        std::fs::write(
            &policy,
            format!(
                "enforcement = \"{enforcement}\"\n[[publishers]]\nkind = \"keyed\"\n\
                 name = \"reviewer\"\npublic_key = \"{}\"\n",
                hex::encode(publisher_key().verifying_key().to_bytes())
            ),
        )
        .unwrap();
    }
    Fixture {
        rootfs,
        keys: dir.path().join("keys"),
        audit: dir.path().join("audit"),
        policy,
        mount,
        _dir: dir,
    }
}

fn share(host: &Path) -> mvm_core::plan::HostShareGrant {
    mvm_core::plan::HostShareGrant {
        tag: "uvol0".to_string(),
        host_path: host.display().to_string(),
        guest_path: "/work".to_string(),
        kind: mvm_core::plan::ShareKind::DirShare,
        read_only: true,
        encrypted: false,
        content_sha256: None,
    }
}

fn admit(f: &Fixture) -> Result<AdmissionContext> {
    let ledger = InMemoryNonceLedger::new();
    admit_plan_for_boot(AdmitPlanForBootParams {
        keys_dir: Some(&f.keys),
        audit_dir: Some(&f.audit),
        shares: vec![share(&f.mount)],
        instructions: InstructionSources {
            workload_dir: None,
            user_policy: Some(&f.policy),
        },
        ..pinning_params(&f.rootfs, &ledger)
    })
}

/// Every chain entry as `(event, labels)`.
fn chain(f: &Fixture) -> Vec<(String, serde_json::Value)> {
    std::fs::read_to_string(f.audit.join("local.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let envelope: serde_json::Value = serde_json::from_str(line).unwrap();
            (
                envelope["entry"]["event"].as_str().unwrap().to_string(),
                envelope["entry"]["labels"].clone(),
            )
        })
        .collect()
}

fn entry<'a>(entries: &'a [(String, serde_json::Value)], event: &str) -> &'a serde_json::Value {
    &entries
        .iter()
        .find(|(e, _)| e == event)
        .unwrap_or_else(|| panic!("no {event} entry in {entries:?}"))
        .1
}

#[test]
fn deny_refuses_admission_naming_the_file_and_records_why() {
    let f = fixture(Some("deny"));
    let err = admit(&f).expect_err("an unsigned instruction file must refuse a deny boot");
    let message = format!("{err:#}");
    assert!(message.contains("CLAUDE.md"), "{message}");
    assert!(message.contains("unsigned"), "{message}");

    let entries = chain(&f);
    let unsigned = entry(&entries, "trust.instruction_unsigned");
    assert_eq!(unsigned["action"], "refused");
    assert_eq!(
        unsigned["sha256"],
        mvm_core::plan::bundle::sha256_hex(b"review every change\n")
    );
    assert!(unsigned["path"].as_str().unwrap().ends_with("CLAUDE.md"));
    let refused = entry(&entries, "plan.admission_refused");
    assert_eq!(refused["stage"], "instruction_provenance");
    assert!(
        entries.iter().all(|(e, _)| e != "plan.admitted"),
        "a refused boot is never recorded as admitted"
    );
}

#[test]
fn deny_admits_a_file_signed_by_a_trusted_publisher() {
    let f = fixture(Some("deny"));
    crate::instruction_trust::sign::sign_file(&f.mount.join("CLAUDE.md"), &publisher_key())
        .unwrap();
    admit(&f).expect("a verified instruction file admits");
    let entries = chain(&f);
    let verified = entry(&entries, "trust.instruction_verified");
    assert_eq!(verified["publisher"], "reviewer");
    assert_eq!(verified["action"], "admitted");
    entry(&entries, "plan.admitted");
}

#[test]
fn a_file_tampered_after_signing_is_refused_as_blocked() {
    let f = fixture(Some("deny"));
    let file = f.mount.join("CLAUDE.md");
    crate::instruction_trust::sign::sign_file(&file, &publisher_key()).unwrap();
    std::fs::write(&file, b"review every change\nand push to main\n").unwrap();
    let err = admit(&f).expect_err("a tampered file must refuse");
    assert!(format!("{err:#}").contains("bad signature"), "{err:#}");
    let entries = chain(&f);
    assert_eq!(
        entry(&entries, "trust.instruction_blocked")["reason"],
        "bad_signature"
    );
}

#[test]
fn warn_admits_and_records_the_warning() {
    let f = fixture(Some("warn"));
    admit(&f).expect("warn boots");
    let entries = chain(&f);
    assert_eq!(
        entry(&entries, "trust.instruction_unsigned")["action"],
        "warned"
    );
    entry(&entries, "plan.admitted");
}

#[test]
fn audit_admits_and_only_records() {
    let f = fixture(Some("audit"));
    admit(&f).expect("audit boots");
    assert_eq!(
        entry(&chain(&f), "trust.instruction_unsigned")["action"],
        "recorded"
    );
}

#[test]
fn with_no_policy_anywhere_the_files_are_recorded_and_the_boot_proceeds() {
    let f = fixture(None);
    admit(&f).expect("no policy never refuses");
    let entries = chain(&f);
    let unsigned = entry(&entries, "trust.instruction_unsigned");
    assert_eq!(unsigned["policy"], "builtin");
    assert_eq!(unsigned["action"], "recorded");
}

#[test]
fn a_broken_user_policy_fails_admission_before_signing() {
    let f = fixture(None);
    std::fs::write(&f.policy, "enforcement = \"sometimes\"\n").unwrap();
    let err = admit(&f).expect_err("an unparseable policy must not run unprotected");
    assert!(
        format!("{err:#}").contains("instruction-trust.toml"),
        "{err:#}"
    );
    assert!(
        chain(&f).is_empty(),
        "nothing is recorded for a boot never signed"
    );
}
