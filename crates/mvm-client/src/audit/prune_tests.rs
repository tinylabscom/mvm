use super::*;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::supervisor::audit::{AuditSigner, for_plan};
use mvm_hostd::supervisor::audit_file::RotationPolicy;
use std::path::PathBuf;

struct Fixture {
    root: tempfile::TempDir,
    _env: TestEnv,
}

impl Fixture {
    fn new(pinned: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(root.path());
        let key = host_keypair::load_or_init_at(&root.path().join("keys")).unwrap();
        let signer = FileAuditSigner::open(key.signing, root.path().join("audit"))
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(1));
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .build();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for n in 0..3 {
            let kind = if pinned && n == 0 {
                "transcript.opened"
            } else {
                "plan.launched"
            };
            runtime
                .block_on(signer.sign_and_emit(&for_plan(
                    &plan,
                    None,
                    kind,
                    [("capture_id".into(), "synthetic-capture".into())],
                )))
                .unwrap();
        }
        Self { root, _env: env }
    }

    fn audit(&self) -> PathBuf {
        self.root.path().join("audit")
    }

    fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(self.audit())
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "jsonl")
            })
            .map(|entry| (entry.path(), std::fs::read(entry.path()).unwrap()))
            .collect();
        files.sort();
        files
    }
}

#[test]
fn public_facade_previews_commits_and_reports_noop_without_creating_authority() {
    let fixture = Fixture::new(false);
    let before = fixture.snapshot();
    assert_eq!(AuditPruneMode::default(), AuditPruneMode::Preview);
    let AuditPruneOutcome::WouldPrune {
        floor,
        through,
        segments,
        entries,
    } = prune_audit("local", 1, AuditPruneMode::default()).unwrap()
    else {
        panic!("expected a preview")
    };
    assert_eq!((floor, through, segments), (1, 1, 1));
    assert!(entries > 0);
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        prune_audit("local", 1, AuditPruneMode::Commit).unwrap(),
        AuditPruneOutcome::Pruned {
            through: 1,
            entries: entries as u64
        },
    );
    assert!(!fixture.audit().join("local.seg-000001.jsonl").exists());
    let after = fixture.snapshot();
    for mode in [AuditPruneMode::Preview, AuditPruneMode::Commit] {
        assert_eq!(
            prune_audit("local", 1, mode).unwrap(),
            AuditPruneOutcome::NothingToPrune {
                floor: 2,
                through: 1
            },
        );
        assert_eq!(fixture.snapshot(), after);
    }
}

#[test]
fn public_facade_validates_before_io_and_never_initializes_missing_keys() {
    let root = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(root.path());
    for mode in [AuditPruneMode::Preview, AuditPruneMode::Commit] {
        for tenant in ["", "/", "../outside", "/outside", "a/b"] {
            assert_eq!(
                prune_audit(tenant, 1, mode).unwrap_err().to_string(),
                "invalid prune tenant component",
            );
        }
        assert!(
            prune_audit("local", 1, mode)
                .unwrap_err()
                .to_string()
                .contains("authority")
        );
    }
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn public_facade_preserves_pins_in_both_modes() {
    let fixture = Fixture::new(true);
    let before = fixture.snapshot();
    for mode in [AuditPruneMode::Preview, AuditPruneMode::Commit] {
        let error = format!("{:#}", prune_audit("local", 1, mode).unwrap_err());
        assert!(error.contains("pins segment 1"));
        assert!(!error.contains("synthetic-capture"));
        assert!(!error.contains(&fixture.root.path().display().to_string()));
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn public_commit_rechecks_admission_after_a_successful_preview() {
    let fixture = Fixture::new(false);
    assert!(matches!(
        prune_audit("local", 1, AuditPruneMode::Preview).unwrap(),
        AuditPruneOutcome::WouldPrune { .. },
    ));
    let family = fixture
        .audit()
        .join("workload-output")
        .join(hex::encode("vm"));
    mvm_core::config::create_private_dir(&family).unwrap();
    let lease =
        mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(&family).unwrap();
    let before = fixture.snapshot();
    assert!(
        format!(
            "{:#}",
            prune_audit("local", 1, AuditPruneMode::Commit).unwrap_err()
        )
        .contains("busy")
    );
    assert_eq!(fixture.snapshot(), before);
    drop(lease);
    assert!(matches!(
        prune_audit("local", 1, AuditPruneMode::Commit).unwrap(),
        AuditPruneOutcome::Pruned { .. },
    ));
}

#[test]
fn public_facade_refuses_a_broken_chain_without_mutation() {
    let fixture = Fixture::new(false);
    std::fs::write(fixture.audit().join("local.seg-000001.jsonl"), b"invalid").unwrap();
    let before = fixture.snapshot();
    for mode in [AuditPruneMode::Preview, AuditPruneMode::Commit] {
        assert!(
            prune_audit("local", 1, mode)
                .unwrap_err()
                .to_string()
                .contains("does not verify")
        );
        assert_eq!(fixture.snapshot(), before);
    }
}
