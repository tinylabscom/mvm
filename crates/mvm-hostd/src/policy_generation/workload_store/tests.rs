use std::{collections::BTreeMap, path::Path};

use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::workload::{
    CanonicalLedger, LEDGER_FILE, PENDING_FILE, WorkloadChange, WorkloadLedger, archive_path_at,
    canonical_dir_at, legacy_path_at,
};

use super::*;

const LEGACY: &str = r#"{"a":{"epoch":3,"quarantined":true},"b":{"epoch":1,"quarantined":false}}"#;

fn quarantine(name: &str) -> WorkloadChange {
    WorkloadChange::Quarantine {
        workload: name.to_owned(),
    }
}

fn replace(name: &str, from: u64) -> WorkloadChange {
    WorkloadChange::Replace {
        workload: name.to_owned(),
        from_epoch: ExecutionEpoch::new(from).unwrap(),
    }
}

fn home_with_legacy(json: &str) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(legacy_path_at(home.path()).parent().unwrap()).unwrap();
    std::fs::write(legacy_path_at(home.path()), json).unwrap();
    home
}

/// What an older binary did to save the ledger.
fn legacy_write(home: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let legacy = legacy_path_at(home);
    let tmp = legacy.with_file_name("workloads.json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, legacy)
}

fn ledger_bytes(home: &Path) -> Vec<u8> {
    std::fs::read(canonical_dir_at(home).join(LEDGER_FILE)).unwrap()
}

fn sequence(home: &Path) -> u64 {
    serde_json::from_slice::<CanonicalLedger>(&ledger_bytes(home))
        .unwrap()
        .sequence
}

fn is_unresolved(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CommitUnresolved>().is_some()
}

fn tree(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.strip_prefix(root).unwrap().display().to_string();
            if path.is_dir() {
                out.insert(name, None);
                walk(&path, root, out);
            } else {
                out.insert(name, Some(std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn legacy_ledger() -> WorkloadLedger {
    serde_json::from_str(LEGACY).unwrap()
}

#[test]
fn migration_preserves_every_flag_and_epoch_and_archives_the_original() {
    let home = home_with_legacy(LEGACY);
    let store = WorkloadStore::open(home.path()).unwrap();
    store.migrate().unwrap();

    assert!(legacy_path_at(home.path()).is_dir());
    assert_eq!(
        std::fs::read(archive_path_at(home.path())).unwrap(),
        LEGACY.as_bytes()
    );
    assert!(legacy_path_at(home.path()).join("MOVED").is_file());
    assert_eq!(sequence(home.path()), 0);
    assert_eq!(
        WorkloadLedger::load_at(home.path()).unwrap(),
        legacy_ledger()
    );
    assert!(!canonical_dir_at(home.path()).join(PENDING_FILE).exists());
}

#[test]
fn after_migration_an_older_binary_can_neither_write_nor_read_the_legacy_path() {
    let home = home_with_legacy(LEGACY);
    let store = WorkloadStore::open(home.path()).unwrap();
    store.commit(&quarantine("b")).unwrap();
    let before = ledger_bytes(home.path());

    assert!(legacy_write(home.path(), b"{}").is_err());
    assert!(std::fs::read(legacy_path_at(home.path())).is_err());
    assert_eq!(ledger_bytes(home.path()), before);
    assert!(
        WorkloadLedger::load_at(home.path())
            .unwrap()
            .entry("b")
            .quarantined
    );
}

#[test]
fn a_legacy_write_before_the_exchange_is_what_the_canonical_ledger_holds() {
    let home = home_with_legacy(LEGACY);
    let store = WorkloadStore::open(home.path()).unwrap();
    store.fail_after(Step::MigrateObligation);
    assert!(is_unresolved(&store.migrate().unwrap_err()));
    assert!(legacy_path_at(home.path()).is_file());

    let late = r#"{"late":{"epoch":9,"quarantined":true}}"#;
    legacy_write(home.path(), late.as_bytes()).unwrap();
    store.recover().unwrap();

    let ledger = WorkloadLedger::load_at(home.path()).unwrap();
    assert!(ledger.entry("late").quarantined && !ledger.knows("a"));
    assert_eq!(
        std::fs::read(archive_path_at(home.path())).unwrap(),
        late.as_bytes()
    );
}

#[test]
fn an_interrupted_migration_is_refused_until_a_fresh_store_recovers_it() {
    for step in [
        Step::MigrateObligation,
        Step::MigrateArchiveDir,
        Step::MigrateExchanged,
        Step::MigrateCanonical,
    ] {
        let home = home_with_legacy(LEGACY);
        let store = WorkloadStore::open(home.path()).unwrap();
        store.fail_after(step);
        let error = store.commit(&quarantine("x")).unwrap_err();
        assert!(is_unresolved(&error), "{step:?}: {error:#}");
        assert!(WorkloadLedger::load_at(home.path()).is_err(), "{step:?}");

        drop(store);
        let fresh = WorkloadStore::open(home.path()).unwrap();
        fresh.recover().unwrap();
        assert_eq!(
            WorkloadLedger::load_at(home.path()).unwrap(),
            legacy_ledger(),
            "{step:?}"
        );
        assert_eq!(fresh.commit(&quarantine("x")).unwrap().sequence, 1);
    }
}

#[test]
fn a_malformed_legacy_ledger_refuses_migration_and_changes_nothing() {
    for bad in ["[", r#"{"a":{"epoch":1,"quarantined":false,"x":1}}"#] {
        let home = home_with_legacy(bad);
        let store = WorkloadStore::open(home.path()).unwrap();
        let before = tree(home.path());
        let error = store.commit(&quarantine("x")).unwrap_err();
        assert!(!is_unresolved(&error), "{error:#}");
        assert_eq!(tree(home.path()), before);
        assert!(legacy_path_at(home.path()).is_file());
    }
}

#[test]
fn the_first_commit_on_a_fresh_host_creates_the_ledger_and_fences_the_path() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    let commit = store.commit(&quarantine("a")).unwrap();
    assert_eq!(commit.sequence, 1);
    assert!(legacy_path_at(home.path()).is_dir());
    assert!(!archive_path_at(home.path()).exists());
    assert!(legacy_write(home.path(), b"{}").is_err());
    assert!(
        WorkloadLedger::load_at(home.path())
            .unwrap()
            .entry("a")
            .quarantined
    );
}

#[test]
fn a_commit_interrupted_after_its_obligation_rolls_back() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    store.commit(&quarantine("a")).unwrap();
    store.fail_after(Step::CommitObligation);
    assert!(is_unresolved(&store.commit(&quarantine("b")).unwrap_err()));
    assert!(WorkloadLedger::load_at(home.path()).is_err());

    drop(store);
    WorkloadStore::open(home.path()).unwrap().recover().unwrap();
    let ledger = WorkloadLedger::load_at(home.path()).unwrap();
    assert!(ledger.knows("a") && !ledger.knows("b"));
    assert_eq!(sequence(home.path()), 1);
}

#[test]
fn a_commit_interrupted_after_the_ledger_write_keeps_the_new_state() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    store.commit(&quarantine("a")).unwrap();
    store.fail_after(Step::CommitLedger);
    assert!(is_unresolved(&store.commit(&quarantine("b")).unwrap_err()));
    assert!(WorkloadLedger::load_at(home.path()).is_err());

    drop(store);
    WorkloadStore::open(home.path()).unwrap().recover().unwrap();
    assert!(
        WorkloadLedger::load_at(home.path())
            .unwrap()
            .entry("b")
            .quarantined
    );
    assert_eq!(sequence(home.path()), 2);
}

#[test]
fn an_obligation_matching_neither_side_stays_unresolved() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    store.commit(&quarantine("a")).unwrap();
    store
        .write_obligation(&Obligation::Commit {
            sequence: 99,
            sha256: "0".repeat(64),
        })
        .unwrap();

    assert!(is_unresolved(&store.recover().unwrap_err()));
    assert!(is_unresolved(&store.commit(&quarantine("b")).unwrap_err()));
    assert!(canonical_dir_at(home.path()).join(PENDING_FILE).exists());
    assert!(WorkloadLedger::load_at(home.path()).is_err());
}

#[test]
fn quarantine_is_idempotent_and_a_stale_replace_changes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    let first = store.commit(&quarantine("a")).unwrap();
    let before = ledger_bytes(home.path());
    let again = store.commit(&quarantine("a")).unwrap();
    assert_eq!(first, again);
    assert_eq!(ledger_bytes(home.path()), before);

    let error = store.commit(&replace("a", 7)).unwrap_err();
    assert!(!is_unresolved(&error));
    assert!(
        error.to_string().contains("expected 7, current 1"),
        "{error:#}"
    );
    assert_eq!(ledger_bytes(home.path()), before);

    let replaced = store.commit(&replace("a", 1)).unwrap();
    assert_eq!(
        (replaced.sequence, replaced.entry.epoch),
        (2, ExecutionEpoch::new(2).unwrap())
    );
    assert!(!replaced.entry.quarantined);
    assert_eq!(store.commit(&replace("a", 2)).unwrap().sequence, 3);

    drop(store);
    let reopened = WorkloadStore::open(home.path()).unwrap();
    assert_eq!(reopened.commit(&quarantine("b")).unwrap().sequence, 4);
    let ledger = WorkloadLedger::load_at(home.path()).unwrap();
    assert_eq!(ledger.entry("a").epoch, ExecutionEpoch::new(3).unwrap());
}

fn seed(home: &Path, count: usize) {
    let mut workloads = WorkloadLedger::default();
    for n in 0..count {
        workloads.replace(&format!("w{n}"));
    }
    let dir = canonical_dir_at(home);
    std::fs::create_dir_all(&dir).unwrap();
    let bytes = serde_json::to_vec(&CanonicalLedger {
        sequence: 5,
        workloads,
    })
    .unwrap();
    std::fs::write(dir.join(LEDGER_FILE), bytes).unwrap();
}

#[test]
fn replacements_cannot_use_the_room_containment_needs() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    seed(home.path(), MAX_WORKLOADS - QUARANTINE_RESERVE);

    assert!(store.commit(&replace("fresh", 1)).is_err());
    assert!(
        store.commit(&replace("w0", 2)).is_ok(),
        "a known entry is not new"
    );
    assert!(store.commit(&quarantine("fresh")).is_ok());
}

#[test]
fn a_full_ledger_refuses_new_entries_but_still_quarantines_known_ones() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    seed(home.path(), MAX_WORKLOADS);

    assert!(store.commit(&quarantine("fresh")).is_err());
    assert!(store.commit(&quarantine("w0")).is_ok());
}

#[test]
fn names_must_be_non_empty_and_bounded() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    assert!(store.commit(&quarantine("")).is_err());
    assert!(
        store
            .commit(&quarantine(&"n".repeat(MAX_NAME_BYTES + 1)))
            .is_err()
    );
    assert!(
        store
            .commit(&quarantine(&"n".repeat(MAX_NAME_BYTES)))
            .is_ok()
    );
}

#[test]
fn a_second_owner_of_one_home_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let first = OwnedWorkloadStore::open(home.path()).unwrap();
    let error = OwnedWorkloadStore::open(home.path())
        .err()
        .expect("refused");
    assert!(
        error.to_string().contains("already has an owner"),
        "{error:#}"
    );
    assert_eq!(first.commit(&quarantine("a")).unwrap().sequence, 1);
}

#[test]
fn a_store_opened_through_a_symlink_to_the_same_home_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("parent");
    std::fs::create_dir_all(parent.join("home")).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&parent, &alias).unwrap();
    let _first = WorkloadStore::open(&parent.join("home")).unwrap();
    let error = WorkloadStore::open(&alias.join("home"))
        .err()
        .expect("refused");
    assert!(
        error.to_string().contains("already has an owner"),
        "{error:#}"
    );
}

#[test]
fn a_replace_that_would_eat_the_byte_reserve_is_refused_while_a_quarantine_commits() {
    let home = tempfile::tempdir().unwrap();
    let store = WorkloadStore::open(home.path()).unwrap();
    let mut workloads = WorkloadLedger::default();
    let mut n = 0;
    // Measure in chunks: serializing after every entry would be quadratic.
    while serde_json::to_vec(&workloads).unwrap().len() as u64
        <= MAX_LEDGER_BYTES - QUARANTINE_RESERVE_BYTES
    {
        for _ in 0..500 {
            workloads.replace(&format!("{n:0>256}"));
            n += 1;
        }
    }
    assert!(
        n < MAX_WORKLOADS - QUARANTINE_RESERVE,
        "bytes bind before the count"
    );
    let dir = canonical_dir_at(home.path());
    std::fs::write(
        dir.join(LEDGER_FILE),
        serde_json::to_vec(&CanonicalLedger {
            sequence: 1,
            workloads,
        })
        .unwrap(),
    )
    .unwrap();

    let error = store.commit(&replace("fresh", 1)).unwrap_err();
    assert!(error.to_string().contains("size limit"), "{error:#}");
    assert!(store.commit(&quarantine("fresh")).is_ok());
}

#[test]
fn a_lost_canonical_ledger_is_never_rebuilt_from_the_archive() {
    let home = home_with_legacy(LEGACY);
    let store = WorkloadStore::open(home.path()).unwrap();
    store.commit(&quarantine("later")).unwrap();
    let ledger = canonical_dir_at(home.path()).join(LEDGER_FILE);
    std::fs::remove_file(&ledger).unwrap();

    let error = store.commit(&quarantine("other")).unwrap_err();
    assert!(!is_unresolved(&error), "{error:#}");
    assert!(error.to_string().contains("already migrated"), "{error:#}");
    assert!(!ledger.exists());
    assert!(!canonical_dir_at(home.path()).join(PENDING_FILE).exists());
    assert!(WorkloadLedger::load_at(home.path()).is_err());
}
