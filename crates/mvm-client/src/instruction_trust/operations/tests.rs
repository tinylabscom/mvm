use super::*;
use crate::instruction_trust::gate::Decision;

fn signing_request(dir: &Path) -> SignRequest {
    let key = dir.join("key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    let policy = dir.join("user.toml");
    std::fs::write(
        &policy,
        templates::user_policy(
            Enforcement::Deny,
            &hex::encode(
                SigningKey::from_bytes(&[7u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        ),
    )
    .unwrap();
    SignRequest {
        paths: vec![dir.to_path_buf()],
        key: Some(key),
        dry_run: false,
        policy: Some(policy),
    }
}

#[test]
fn signing_verification_tampering_and_public_reports() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("CLAUDE.md");
    std::fs::write(&file, b"original").unwrap();
    let request = signing_request(dir.path());
    let outcome = sign(&request).unwrap();
    assert_eq!(outcome.signed.len(), 1);
    assert!(outcome.key_id.is_some());
    let json = serde_json::to_value(&outcome).unwrap();
    assert!(json["key_id"].is_string());
    assert!(json.get("key").is_none());
    let verify_request = VerifyRequest {
        path: dir.path().to_path_buf(),
        policy: request.policy,
    };
    let report = verify(&verify_request).unwrap();
    assert!(matches!(report.decision(), Decision::Admit));
    assert_eq!(
        serde_json::to_value(&report).unwrap()["files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    std::fs::write(file, b"changed").unwrap();
    assert!(matches!(
        verify(&verify_request).unwrap().decision(),
        Decision::Refuse(_)
    ));
}

#[test]
fn malformed_keys_and_missing_paths_do_not_write_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("CLAUDE.md");
    std::fs::write(&file, b"original").unwrap();
    let mut request = signing_request(dir.path());
    for length in [0, 31, 33, 64] {
        std::fs::write(request.key.as_ref().unwrap(), vec![1u8; length]).unwrap();
        assert!(sign(&request).unwrap_err().to_string().contains("32-byte"));
        assert!(!super::super::sidecar_path(&file, super::super::KEYED_SIDECAR_SUFFIX).exists());
    }
    request.paths.push(dir.path().join("absent"));
    assert!(
        sign(&request)
            .unwrap_err()
            .to_string()
            .contains("not a file or directory")
    );
}

#[test]
fn dry_run_selects_by_policy_but_keeps_explicit_files_and_never_loads_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut request = signing_request(dir.path());
    let selected = dir.path().join("selected.txt");
    let explicit = dir.path().join("other.txt");
    for path in [&selected, &explicit, &dir.path().join("CLAUDE.md")] {
        std::fs::write(path, b"x").unwrap();
    }
    std::fs::write(
        request.policy.as_ref().unwrap(),
        "includes = ['selected.txt']\n",
    )
    .unwrap();
    request.paths.push(explicit.clone());
    request.key = Some(dir.path().join("missing-key"));
    request.dry_run = true;
    let outcome = sign(&request).unwrap();
    assert_eq!(outcome.selected, vec![selected, explicit]);
    assert!(outcome.signed.is_empty());
    assert!(outcome.key_id.is_none());
}

#[test]
fn project_init_preserves_existing_policy_and_project_only_is_advisory() {
    let dir = tempfile::tempdir().unwrap();
    let mut request = InitRequest {
        project: Some(dir.path().to_path_buf()),
        enforcement: Enforcement::Deny,
        force: false,
    };
    let outcome = init(&request).unwrap();
    let before = std::fs::read(&outcome.path).unwrap();
    request.enforcement = Enforcement::Warn;
    assert!(init(&request).unwrap_err().to_string().contains("--force"));
    assert_eq!(std::fs::read(&outcome.path).unwrap(), before);
    request.force = true;
    init(&request).unwrap();
    let locations = PolicyLocations {
        user: Some(dir.path().join("absent-user.toml")),
        project_root: request.project,
    };
    let summary = policy(&locations).unwrap();
    assert_eq!(summary.enforcement, Enforcement::Warn);
    assert!(serde_json::to_value(summary).unwrap().is_object());
    assert!(
        serde_json::to_value(outcome).unwrap()["project"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn wrong_signing_key_is_refused_and_warn_policy_warns() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("CLAUDE.md"), b"x").unwrap();
    let request = signing_request(dir.path());
    std::fs::write(request.key.as_ref().unwrap(), [8u8; 32]).unwrap();
    sign(&request).unwrap();
    let verify_request = VerifyRequest {
        path: dir.path().to_path_buf(),
        policy: request.policy.clone(),
    };
    assert!(matches!(
        verify(&verify_request).unwrap().decision(),
        Decision::Refuse(_)
    ));
    std::fs::write(request.policy.unwrap(), "enforcement = 'warn'\n").unwrap();
    assert!(matches!(
        verify(&verify_request).unwrap().decision(),
        Decision::Warn(_)
    ));
}
