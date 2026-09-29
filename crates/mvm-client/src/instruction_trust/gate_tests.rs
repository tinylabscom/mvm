use std::path::Path;

use ed25519_dalek::SigningKey;

use super::*;
use crate::instruction_trust::policy::PolicyOrigin;
use crate::instruction_trust::sign::sign_file;

struct NoKeys;

impl mvm_core::plan::bundle::TrustStore for NoKeys {
    fn lookup(&self, _: &mvm_core::plan::bundle::KeyId) -> Option<ed25519_dalek::VerifyingKey> {
        None
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

/// Write a user policy trusting [`key`] under `enforcement` into `dir`.
fn user_policy(dir: &Path, enforcement: &str) -> std::path::PathBuf {
    let path = dir.join("instruction-trust.toml");
    std::fs::write(
        &path,
        format!(
            "enforcement = \"{enforcement}\"\n[[publishers]]\nkind = \"keyed\"\nname = \"me\"\n\
             public_key = \"{}\"\n",
            hex::encode(key().verifying_key().to_bytes())
        ),
    )
    .unwrap();
    path
}

/// A mount holding one signed and one unsigned instruction file.
fn mixed_mount(dir: &Path) -> std::path::PathBuf {
    let mount = dir.join("mount");
    std::fs::create_dir_all(mount.join(".claude/commands")).unwrap();
    std::fs::write(mount.join("AGENTS.md"), b"signed\n").unwrap();
    sign_file(&mount.join("AGENTS.md"), &key()).unwrap();
    std::fs::write(mount.join(".claude/commands/deploy.md"), b"unsigned\n").unwrap();
    std::fs::write(mount.join("README.md"), b"not an instruction file\n").unwrap();
    mount
}

fn report_under(enforcement: &str) -> ScanReport {
    let dir = tempfile::tempdir().unwrap();
    let locations = PolicyLocations {
        user: Some(user_policy(dir.path(), enforcement)),
        project_root: None,
    };
    let policy = load_effective_policy(&locations, &NoKeys).unwrap();
    let inputs = BootInputs {
        mounts: vec![mixed_mount(dir.path())],
        ..BootInputs::default()
    };
    scan_roots(&inputs.roots(), &policy).unwrap()
}

#[test]
fn deny_refuses_and_names_each_failing_file_and_why() {
    let report = report_under("deny");
    assert_eq!(report.files.len(), 2);
    match report.decision() {
        Decision::Refuse(message) => {
            assert!(message.contains("deploy.md"), "{message}");
            assert!(message.contains("unsigned"), "{message}");
            assert!(
                !message.contains("AGENTS.md"),
                "a verified file is not a failure"
            );
        }
        other => panic!("deny must refuse, got {other:?}"),
    }
}

#[test]
fn warn_boots_and_reports_each_failure() {
    match report_under("warn").decision() {
        Decision::Warn(lines) => {
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains("deploy.md"));
        }
        other => panic!("warn must warn, got {other:?}"),
    }
}

#[test]
fn audit_only_records() {
    assert_eq!(report_under("audit").decision(), Decision::Admit);
}

#[test]
fn a_clean_scan_admits_under_deny() {
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    std::fs::write(mount.join("CLAUDE.md"), b"signed\n").unwrap();
    sign_file(&mount.join("CLAUDE.md"), &key()).unwrap();
    let policy = load_effective_policy(
        &PolicyLocations {
            user: Some(user_policy(dir.path(), "deny")),
            project_root: None,
        },
        &NoKeys,
    )
    .unwrap();
    let report = scan_roots(
        &[ScanRoot::new(mount, super::super::scan::RootKind::Mount)],
        &policy,
    )
    .unwrap();
    assert_eq!(report.decision(), Decision::Admit);
}

#[test]
fn every_file_gets_one_audit_record_naming_path_digest_and_outcome() {
    let report = report_under("deny");
    let records = report.audit_records();
    assert_eq!(records.len(), 2);
    let label = |labels: &[(String, String)], key: &str| {
        labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("label {key} missing from {labels:?}"))
    };

    let (event, labels) = &records[0];
    assert_eq!(event.as_str(), "trust.instruction_unsigned");
    assert!(label(labels, "path").ends_with(".claude/commands/deploy.md"));
    assert_eq!(
        label(labels, "sha256"),
        mvm_core::plan::bundle::sha256_hex(b"unsigned\n")
    );
    assert_eq!(label(labels, "action"), "refused");
    assert_eq!(label(labels, "enforcement"), "deny");
    assert_eq!(label(labels, "policy"), "user");
    assert_eq!(label(labels, "root_kind"), "mount");

    let (event, labels) = &records[1];
    assert_eq!(event.as_str(), "trust.instruction_verified");
    assert_eq!(label(labels, "publisher"), "me");
    assert_eq!(label(labels, "action"), "admitted");

    for (_, labels) in &records {
        assert!(
            labels.iter().all(|(_, v)| !v.contains("signed\n")),
            "no label carries file content"
        );
    }
}

#[test]
fn a_blocked_file_is_recorded_as_blocked_with_its_reason() {
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    std::fs::write(mount.join("SKILL.md"), b"poison\n").unwrap();
    let policy_path = dir.path().join("p.toml");
    std::fs::write(
        &policy_path,
        format!(
            "enforcement = \"warn\"\n[[blocklist]]\nsha256 = \"{}\"\n",
            mvm_core::plan::bundle::sha256_hex(b"poison\n")
        ),
    )
    .unwrap();
    let policy = load_effective_policy(
        &PolicyLocations {
            user: Some(policy_path),
            project_root: None,
        },
        &NoKeys,
    )
    .unwrap();
    let report = scan_roots(
        &[ScanRoot::new(mount, super::super::scan::RootKind::Asset)],
        &policy,
    )
    .unwrap();
    let (event, labels) = &report.audit_records()[0];
    assert_eq!(event.as_str(), "trust.instruction_blocked");
    assert!(labels.contains(&("reason".to_string(), "digest_blocked".to_string())));
    assert!(labels.contains(&("action".to_string(), "warned".to_string())));
}

#[test]
fn a_project_policy_is_read_from_the_workload_directory_and_only_tightens() {
    let dir = tempfile::tempdir().unwrap();
    let workload = dir.path().join("workload");
    let project_policy = mvm_core::config::project_instruction_trust_policy_path(&workload);
    std::fs::create_dir_all(project_policy.parent().unwrap()).unwrap();
    std::fs::write(
        &project_policy,
        "enforcement = \"audit\"\nincludes = [\"prompts/*.txt\"]\n",
    )
    .unwrap();
    std::fs::create_dir_all(workload.join("prompts")).unwrap();
    std::fs::write(workload.join("prompts/system.txt"), b"obey\n").unwrap();

    let locations = PolicyLocations {
        user: Some(user_policy(dir.path(), "deny")),
        project_root: Some(workload.clone()),
    };
    let policy = load_effective_policy(&locations, &NoKeys).unwrap();
    assert_eq!(policy.origin(), PolicyOrigin::UserAndProject);
    assert_eq!(policy.enforcement(), Enforcement::Deny);
    let inputs = BootInputs {
        workload_dir: Some(workload),
        ..BootInputs::default()
    };
    let report = scan_roots(&inputs.roots(), &policy).unwrap();
    assert_eq!(report.files.len(), 1, "the project's own include applies");
    assert!(matches!(report.decision(), Decision::Refuse(_)));
}

#[test]
fn a_broken_project_policy_fails_closed_only_under_a_user_policy() {
    let dir = tempfile::tempdir().unwrap();
    let workload = dir.path().join("workload");
    let project_policy = mvm_core::config::project_instruction_trust_policy_path(&workload);
    std::fs::create_dir_all(project_policy.parent().unwrap()).unwrap();
    std::fs::write(&project_policy, "enforcement = [").unwrap();

    let with_user = PolicyLocations {
        user: Some(user_policy(dir.path(), "deny")),
        project_root: Some(workload.clone()),
    };
    assert!(load_effective_policy(&with_user, &NoKeys).is_err());

    let alone = PolicyLocations {
        user: Some(dir.path().join("absent.toml")),
        project_root: Some(workload),
    };
    let policy = load_effective_policy(&alone, &NoKeys).unwrap();
    assert_eq!(policy.origin(), PolicyOrigin::Builtin);
    assert!(policy.notes().iter().any(|n| n.contains("ignoring")));
}

#[test]
fn a_broken_user_policy_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("instruction-trust.toml");
    std::fs::write(&path, "publishers = 3\n").unwrap();
    let locations = PolicyLocations {
        user: Some(path),
        project_root: None,
    };
    assert!(load_effective_policy(&locations, &NoKeys).is_err());
}

#[test]
fn a_boot_with_no_host_inputs_reads_no_policy() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.toml");
    std::fs::write(&broken, "not toml [").unwrap();
    assert!(
        evaluate_boot_inputs(&BootInputs::default(), Some(&broken))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_mount_that_vanished_fails_the_scan() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = BootInputs {
        mounts: vec![dir.path().join("gone")],
        ..BootInputs::default()
    };
    let err = evaluate_boot_inputs(&inputs, Some(&dir.path().join("absent.toml"))).unwrap_err();
    assert!(format!("{err:#}").contains("gone"), "{err:#}");
}

#[test]
fn local_workload_dirs_come_from_local_paths_only() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("mvm.toml");
    std::fs::write(&manifest, "").unwrap();
    let d = dir.path().to_str().unwrap();
    assert_eq!(
        local_workload_dir(Some(d), None),
        Some(dir.path().to_path_buf())
    );
    assert_eq!(
        local_workload_dir(Some(&format!("path:{d}")), None),
        Some(dir.path().to_path_buf())
    );
    assert_eq!(
        local_workload_dir(None, Some(manifest.to_str().unwrap())),
        Some(dir.path().to_path_buf())
    );
    assert_eq!(local_workload_dir(Some("github:acme/agents"), None), None);
    assert_eq!(local_workload_dir(None, Some("my-slot")), None);
    assert_eq!(local_workload_dir(None, None), None);
}

#[test]
fn a_scan_report_serializes_for_json_output() {
    let value = serde_json::to_value(report_under("warn")).unwrap();
    assert_eq!(value["enforcement"], "warn");
    assert_eq!(value["origin"], "user");
    assert_eq!(value["files"][0]["verdict"]["status"], "unsigned");
    assert_eq!(value["files"][1]["verdict"]["status"], "verified");
    assert!(value["files"][0]["relative"].is_string());
}
