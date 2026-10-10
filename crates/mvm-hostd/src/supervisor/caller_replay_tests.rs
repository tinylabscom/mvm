use super::*;
use mvm_core::crypto::entrypoint_delegation::test_support;
use mvm_core::plan::test_support::PlanFixture;
use mvm_core::util::test_env::TestEnv;
use mvm_core::vm_backend::caller_registration::CallerRegistration;

fn isolate() -> (TestEnv, tempfile::TempDir) {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    (env, home)
}

fn challenge(expires: u64) -> RegistrationChallenge {
    let mut plan = PlanFixture::new().build();
    plan.valid_from = chrono::DateTime::from_timestamp(1, 0).unwrap();
    plan.valid_until =
        chrono::DateTime::from_timestamp(i64::try_from(expires).unwrap(), 0).unwrap();
    let installation = serde_json::from_str("\"bdf189ab-9a9a-440b-a266-e95b19e58a5e\"").unwrap();
    CallerRegistration::challenge_for_plan(
        "replay-ledger",
        &plan,
        test_support::identity([7; 32], installation),
        50,
    )
    .unwrap()
}

fn root() -> std::path::PathBuf {
    config::mvm_home_strict()
        .unwrap()
        .join("caller-registration")
}

fn contents() -> Vec<u8> {
    std::fs::read(root().join("ledger.json")).unwrap()
}

#[test]
fn pruning_and_high_water_are_one_commit_and_rollback_cannot_revive_a_record() {
    let (_env, _home) = isolate();
    let old = challenge(200);
    consume_challenge(&old, 100).unwrap();
    assert!(consume_challenge(&old, 200).is_err(), "expiry is exclusive");
    let fresh = challenge(400);
    consume_challenge(&fresh, 200).unwrap();
    let bytes = contents();
    let ledger: Ledger = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ledger.high_water, 200);
    assert_eq!(
        ledger.entries.len(),
        1,
        "expired entry pruned during the commit"
    );
    assert!(
        consume_challenge(&old, 199)
            .unwrap_err()
            .to_string()
            .contains("backwards")
    );
    assert!(consume_challenge(&challenge(400), 199).is_err());
    assert_eq!(
        contents(),
        bytes,
        "backward clock must never reset the ledger"
    );
}

#[test]
fn a_full_ledger_refuses_without_evicting_an_unexpired_record() {
    let (_env, _home) = isolate();
    config::create_private_dir(root()).unwrap();
    let ledger = Ledger {
        version: 1,
        high_water: 100,
        entries: (0..MAX_ENTRIES)
            .map(|index| {
                let mut commitment = [0; 32];
                commitment[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
                Entry {
                    commitment,
                    not_after: 500,
                }
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&ledger).unwrap();
    atomic_io::write_private(&root().join("ledger.json"), &bytes).unwrap();
    assert!(
        consume_challenge(&challenge(500), 101)
            .unwrap_err()
            .to_string()
            .contains("full")
    );
    assert_eq!(contents(), bytes);
}

#[test]
fn corrupt_missing_initialized_or_oversized_storage_never_resets() {
    let (_env, _home) = isolate();
    consume_challenge(&challenge(500), 100).unwrap();
    let path = root().join("ledger.json");
    std::fs::remove_file(&path).unwrap();
    assert!(consume_challenge(&challenge(500), 101).is_err());
    assert!(
        !path.exists(),
        "initialized missing storage is not first use"
    );
    for malformed in [b"{".as_slice(), b"{}".as_slice()] {
        atomic_io::write_private(&path, malformed).unwrap();
        assert!(consume_challenge(&challenge(500), 101).is_err());
        assert_eq!(contents(), malformed);
    }
    atomic_io::write_private(&path, &vec![b' '; MAX_BYTES + 1]).unwrap();
    assert!(consume_challenge(&challenge(500), 101).is_err());
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        (MAX_BYTES + 1) as u64
    );
}

#[test]
fn duplicate_entries_and_unknown_versions_are_refused_without_repair() {
    let (_env, _home) = isolate();
    consume_challenge(&challenge(500), 100).unwrap();
    let path = root().join("ledger.json");
    let original: serde_json::Value = serde_json::from_slice(&contents()).unwrap();
    for unknown_version in [false, true] {
        let mut bad = original.clone();
        if unknown_version {
            bad["version"] = serde_json::json!(99);
        } else {
            let duplicate = bad["entries"][0].clone();
            bad["entries"].as_array_mut().unwrap().push(duplicate);
        }
        let bytes = serde_json::to_vec(&bad).unwrap();
        atomic_io::write_private(&path, &bytes).unwrap();
        assert!(consume_challenge(&challenge(500), 101).is_err());
        assert_eq!(contents(), bytes);
    }
}

#[cfg(unix)]
#[test]
fn storage_links_and_directory_contention_refuse_without_activation() {
    let (_env, _home) = isolate();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root()).unwrap();
    assert!(consume_challenge(&challenge(500), 100).is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    std::fs::remove_file(root()).unwrap();
    config::create_private_dir(root()).unwrap();
    let target = outside.path().join("unchanged");
    atomic_io::write_private(&target, b"unchanged").unwrap();
    let ledger = root().join("ledger.json");
    std::os::unix::fs::symlink(&target, &ledger).unwrap();
    assert!(consume_challenge(&challenge(500), 100).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    std::fs::remove_file(&ledger).unwrap();
    std::fs::hard_link(&target, &ledger).unwrap();
    assert!(consume_challenge(&challenge(500), 100).is_err());
    std::fs::remove_file(ledger).unwrap();
    let lease = CaptureDirectory::for_writer(&root()).unwrap();
    assert!(consume_challenge(&challenge(500), 100).is_err());
    assert!(
        lease
            .read_private_member("../unchanged", MAX_BYTES)
            .is_err()
    );
    drop(lease);
    consume_challenge(&challenge(500), 100).unwrap();
}

#[test]
fn abrupt_subprocess_exit_before_commit_can_retry_but_after_commit_stays_spent() {
    let (mut env, home) = isolate();
    for phase in ["before", "after-ledger", "after"] {
        let phase_home = home.path().join(phase);
        env.isolate_mvm_home(&phase_home);
        let challenge = challenge(500);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "supervisor::caller_registration::replay::tests::crash_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("MVM_HOME", &phase_home)
            .env("MVM_CALLER_REPLAY_CHILD", phase)
            .env(
                "MVM_CALLER_REPLAY_CHALLENGE",
                serde_json::to_string(&challenge).unwrap(),
            )
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(67),
            "child must exit at the selected commit boundary"
        );
        let retried = consume_challenge(&challenge, 100);
        assert_eq!(retried.is_ok(), phase == "before");
        consume_challenge(&self::challenge(500), 100).unwrap();
        assert_eq!(
            std::fs::read_dir(root()).unwrap().count(),
            2,
            "no leftover temporary files"
        );
    }
}

#[test]
#[ignore = "subprocess-only deterministic ledger commit-boundary witness"]
fn crash_child() {
    let phase = std::env::var("MVM_CALLER_REPLAY_CHILD").expect("subprocess phase");
    let challenge = serde_json::from_str(
        &std::env::var("MVM_CALLER_REPLAY_CHALLENGE").expect("subprocess public challenge"),
    )
    .unwrap();
    CRASH.with(|selected| {
        selected.set(Some(match phase.as_str() {
            "before" => Phase::BeforeCommit,
            "after-ledger" => Phase::AfterLedger,
            "after" => Phase::AfterCommit,
            _ => panic!("unknown crash phase"),
        }))
    });
    consume_challenge(&challenge, 100).unwrap();
    panic!("child did not exit at the requested boundary");
}
