//! Directory ownership policy is separate from audit signing and chain bytes.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::SigningKey;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::audit_checkpoint;
use mvm_hostd::audit::audit_file::{
    FileAuditSigner, verify_audit_chain, verify_audit_chain_incremental,
};
use mvm_hostd::audit::signer::{AuditSigner, for_plan};

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn loose(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn emit(signer: &FileAuditSigner) {
    let plan = mvm_core::plan::test_support::PlanFixture::new().build();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(signer.sign_and_emit(&for_plan(&plan, None, "plan.admitted", [])))
        .unwrap();
}

#[test]
fn bare_relative_fixed_file_preserves_caller_owned_cwd() {
    const CHILD: &str = "MVM_AUDIT_DIRECTORY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert_eq!(mode(Path::new(".")), 0o755);
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&[7; 32]), "audit.jsonl").unwrap();
        emit(&signer);
        assert_eq!(mode(Path::new(".")), 0o755);
        assert_eq!(
            verify_audit_chain(Path::new("audit.jsonl"), &signer.verifying_key()).unwrap(),
            1
        );
        let primary =
            FileAuditSigner::open(SigningKey::from_bytes(&[7; 32]), "missing/x/../dedicated")
                .unwrap();
        emit(&primary);
        assert_eq!(mode(Path::new(".")), 0o755);
        assert_eq!(mode(Path::new("missing/x")), 0o700);
        assert_eq!(mode(Path::new("missing/dedicated")), 0o700);
        return;
    }
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    env.set("MVM_HOME", root.path().join("mvm"));
    let output = root.path().join("operator");
    loose(&output);
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "bare_relative_fixed_file_preserves_caller_owned_cwd",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .current_dir(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(mode(&output), 0o755);
}

#[test]
fn primary_open_and_append_repair_and_recreate_the_owned_chain() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    loose(&home);
    let audit = home.join("audit/nested");
    let signer = FileAuditSigner::open(SigningKey::from_bytes(&[7; 32]), &audit).unwrap();
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(&home.join("audit")), 0o700);
    assert_eq!(mode(&audit), 0o700);
    std::fs::remove_dir_all(&home).unwrap();
    emit(&signer);
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(&home.join("audit")), 0o700);
    assert_eq!(mode(&audit), 0o700);
    assert_eq!(
        verify_audit_chain(&signer.tenant_path("local"), &signer.verifying_key()).unwrap(),
        1
    );
    loose(&home);
    loose(&audit);
    emit(&signer);
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(&audit), 0o700);
}

#[test]
fn primary_parent_escape_keeps_external_ancestors_unchanged_on_open_and_append() {
    use std::os::unix::fs::symlink;

    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    loose(root.path());
    loose(&home);
    let outside = root.path().join("outside");
    loose(&outside);
    loose(&outside.join("branch"));
    symlink(outside.join("branch"), home.join("alias")).unwrap();
    for (spelling, actual) in [
        (home.join("../audit"), root.path().join("audit")),
        (home.join("alias/../audit"), outside.join("audit")),
    ] {
        let signer = FileAuditSigner::open(SigningKey::from_bytes(&[7; 32]), &spelling).unwrap();
        assert_eq!(mode(&actual), 0o700);
        assert_eq!(mode(root.path()), 0o755);
        assert_eq!(mode(&outside), 0o755);
        std::fs::remove_dir_all(&actual).unwrap();
        emit(&signer);
        assert_eq!(mode(&actual), 0o700);
        assert_eq!(mode(root.path()), 0o755);
        assert_eq!(mode(&outside), 0o755);
    }
}

#[test]
fn emitter_with_dir_preserves_external_ancestors() {
    emitter_parent_escapes_preserve_external_ancestors(false);
}

#[test]
fn emitter_with_primary_signer_preserves_external_ancestors() {
    emitter_parent_escapes_preserve_external_ancestors(true);
}

fn emitter_parent_escapes_preserve_external_ancestors(shared_signer: bool) {
    use mvm_hostd::audit::emitter::AuditEmitter;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;

    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    loose(&home);
    let outside = root.path().join("outside");
    loose(&outside.join("branch"));
    symlink(outside.join("branch"), home.join("alias")).unwrap();
    for (spelling, actual) in [
        (home.join("../audit"), root.path().join("audit")),
        (home.join("alias/../audit"), outside.join("audit")),
    ] {
        loose(root.path());
        loose(&outside);
        loose(&outside.join("branch"));
        let key = SigningKey::from_bytes(&[7; 32]);
        let emitter = if shared_signer {
            let signer = Arc::new(FileAuditSigner::open(key.clone(), &spelling).unwrap());
            AuditEmitter::with_primary_signer(key, &spelling, signer).unwrap()
        } else {
            AuditEmitter::with_dir(key, &spelling).unwrap()
        };
        assert_eq!(mode(&actual), 0o700);
        assert_eq!(mode(root.path()), 0o755);
        assert_eq!(mode(&outside), 0o755);
        assert_eq!(mode(&outside.join("branch")), 0o755);
        drop(emitter);
    }
}

#[test]
fn dedicated_external_root_is_private_but_its_existing_parent_is_not_chmodded() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    env.set("MVM_HOME", root.path().join("mvm"));
    let parent = root.path().join("operator");
    loose(&parent);
    let audit = parent.join("dedicated");
    loose(&audit);
    let signer = FileAuditSigner::open(SigningKey::from_bytes(&[7; 32]), &audit).unwrap();
    emit(&signer);
    assert_eq!(mode(&parent), 0o755);
    assert_eq!(mode(&audit), 0o700);
}

#[test]
fn fixed_files_preserve_external_modes_and_repair_owned_parents_on_each_append() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    let external = root.path().join("operator");
    for (parent, expected) in [(external, 0o755), (home.join("output"), 0o700)] {
        loose(&parent);
        let signer = FileAuditSigner::open_file(
            SigningKey::from_bytes(&[7; 32]),
            parent.join("replica.jsonl"),
        )
        .unwrap();
        assert_eq!(mode(&parent), expected);
        emit(&signer);
        assert_eq!(mode(&parent), expected);
        // Removal before another append exercises the same constructor policy.
        std::fs::remove_dir_all(&parent).unwrap();
        emit(&signer);
        assert!(parent.is_dir());
        if parent.starts_with(&home) {
            assert_eq!(mode(&home), 0o700);
            assert_eq!(mode(&parent), 0o700);
        } else {
            loose(&parent);
            emit(&signer);
            assert_eq!(mode(&parent), 0o755);
        }
    }
}

#[test]
fn checkpoint_store_repairs_the_mvm_cache_chain() {
    let mut env = TestEnv::new();
    let root = tempfile::tempdir().unwrap();
    env.set("HOME", root.path());
    let home = root.path().join("mvm");
    env.set("MVM_HOME", &home);
    let signer =
        FileAuditSigner::open(SigningKey::from_bytes(&[7; 32]), home.join("audit")).unwrap();
    emit(&signer);
    let path = signer.tenant_path("local");
    let verified = verify_audit_chain_incremental(&path, &signer.verifying_key(), None).unwrap();
    loose(&home);
    loose(&home.join("cache"));
    audit_checkpoint::store(&path, &verified.checkpoint);
    assert!(audit_checkpoint::load(&path).is_some());
    for path in [&home, &home.join("cache"), &home.join("cache/audit-verify")] {
        assert_eq!(mode(path), 0o700);
    }
}
