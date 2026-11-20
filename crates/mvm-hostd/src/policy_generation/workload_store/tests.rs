use std::{collections::BTreeMap, path::Path};

use mvm_core::host_interface::{
    ExecutionEpoch,
    workload::{
        CanonicalLedger, LEDGER_FILE, PENDING_FILE, WorkloadChange, WorkloadLedger,
        archive_path_at, canonical_dir_at, legacy_path_at,
    },
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
        from_epoch: ExecutionEpoch(from),
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
        (2, ExecutionEpoch(2))
    );
    assert!(!replaced.entry.quarantined);
    assert_eq!(store.commit(&replace("a", 2)).unwrap().sequence, 3);

    drop(store);
    let reopened = WorkloadStore::open(home.path()).unwrap();
    assert_eq!(reopened.commit(&quarantine("b")).unwrap().sequence, 4);
    let ledger = WorkloadLedger::load_at(home.path()).unwrap();
    assert_eq!(ledger.entry("a").epoch, ExecutionEpoch(3));
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
        ..Default::default()
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
            ..Default::default()
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

mod destinations {
    use ed25519_dalek::SigningKey;
    use mvm_core::host_interface::workload::{
        DestinationEnrollment, DestinationEntry, DestinationTip, MAX_DESTINATIONS, PreparedHead,
        SignedPreparedHead,
    };

    use super::*;

    const DESTINATION: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn key_hex(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    fn tip(cursor: u64) -> DestinationTip {
        DestinationTip {
            cursor,
            head: format!("{cursor:064x}"),
        }
    }

    fn enrollment(workload: &str, epoch: u64) -> DestinationEnrollment {
        DestinationEnrollment {
            destination: DESTINATION.into(),
            workload: workload.into(),
            epoch: ExecutionEpoch(epoch),
            key: key_hex(&key()),
            tip: tip(0),
        }
    }

    fn prepared(workload: &str, epoch: u64, from: u64, signer: &SigningKey) -> SignedPreparedHead {
        PreparedHead {
            destination: DESTINATION.into(),
            workload: workload.into(),
            epoch: ExecutionEpoch(epoch),
            expected: tip(from),
            next: tip(from + 1),
        }
        .sign(signer)
        .unwrap()
    }

    fn ledger(home: &Path) -> CanonicalLedger {
        serde_json::from_slice(&ledger_bytes(home)).unwrap()
    }

    fn disk_tip(home: &Path) -> DestinationTip {
        ledger(home).destinations[DESTINATION].tip.clone()
    }

    fn enrolled() -> (tempfile::TempDir, WorkloadStore) {
        let home = tempfile::tempdir().unwrap();
        let store = WorkloadStore::open(home.path()).unwrap();
        store.enroll_destination(&enrollment("w", 1)).unwrap();
        (home, store)
    }

    #[test]
    fn a_commit_moves_the_tip_and_the_sequence() {
        let (home, store) = enrolled();
        assert_eq!(sequence(home.path()), 1);
        let commit = store
            .commit_destination(&prepared("w", 1, 0, &key()))
            .unwrap();
        assert_eq!((commit.sequence, commit.tip), (2, tip(1)));
        assert_eq!(disk_tip(home.path()), tip(1));
    }

    #[test]
    fn a_quarantine_committed_first_refuses_the_prepared_commit() {
        let (home, store) = enrolled();
        store.commit(&quarantine("w")).unwrap();
        let before = ledger_bytes(home.path());
        let error = store
            .commit_destination(&prepared("w", 1, 0, &key()))
            .unwrap_err();
        assert!(!is_unresolved(&error), "{error:#}");
        assert_eq!(ledger_bytes(home.path()), before);
        assert_eq!(disk_tip(home.path()), tip(0));
    }

    #[test]
    fn a_destination_commit_first_survives_a_later_quarantine_and_resubmission() {
        let (home, store) = enrolled();
        let head = prepared("w", 1, 0, &key());
        store.commit_destination(&head).unwrap();
        store.commit(&quarantine("w")).unwrap();
        assert_eq!(disk_tip(home.path()), tip(1));
        let before = ledger_bytes(home.path());
        assert_eq!(store.commit_destination(&head).unwrap().tip, tip(1));
        assert_eq!(ledger_bytes(home.path()), before, "no write");
        store.commit(&replace("w", 1)).unwrap();
        assert_eq!(store.commit_destination(&head).unwrap().tip, tip(1));
    }

    #[test]
    fn a_replacement_refuses_an_old_epoch_prepared_commit() {
        let (home, store) = enrolled();
        store.commit(&replace("w", 1)).unwrap();
        let error = store
            .commit_destination(&prepared("w", 1, 0, &key()))
            .unwrap_err();
        assert!(!is_unresolved(&error), "{error:#}");
        assert_eq!(disk_tip(home.path()), tip(0));
        let mut other = enrollment("w", 1);
        other.destination = "e".repeat(64);
        assert!(
            store
                .enroll_destination(&other)
                .unwrap_err()
                .to_string()
                .contains("epoch changed"),
            "a new destination cannot enroll under a replaced epoch"
        );
    }

    #[test]
    fn a_divergent_head_a_bad_signature_and_an_unknown_destination_are_refused() {
        let (home, store) = enrolled();
        let before = ledger_bytes(home.path());
        let skipped = PreparedHead {
            next: tip(2),
            ..prepared("w", 1, 0, &key()).head
        }
        .sign(&key())
        .unwrap();
        for refused in [
            prepared("w", 1, 5, &key()),
            skipped,
            prepared("w", 1, 0, &SigningKey::from_bytes(&[8; 32])),
            prepared("other", 1, 0, &key()),
            prepared("w", 2, 0, &key()),
            SignedPreparedHead {
                head: PreparedHead {
                    destination: "e".repeat(64),
                    ..prepared("w", 1, 0, &key()).head
                },
                signature: prepared("w", 1, 0, &key()).signature,
            },
        ] {
            let error = store.commit_destination(&refused).unwrap_err();
            assert!(!is_unresolved(&error), "{error:#}");
        }
        assert_eq!(ledger_bytes(home.path()), before);
    }

    #[test]
    fn enrollment_is_idempotent_and_never_rebinds() {
        let (home, store) = enrolled();
        store
            .commit_destination(&prepared("w", 1, 0, &key()))
            .unwrap();
        let before = ledger_bytes(home.path());
        let again = store.enroll_destination(&enrollment("w", 1)).unwrap();
        assert_eq!((again.sequence, again.tip), (2, tip(1)));
        assert_eq!(ledger_bytes(home.path()), before, "no write");
        assert_eq!(sequence(home.path()), 2);

        let mut rekeyed = enrollment("w", 1);
        rekeyed.key = key_hex(&SigningKey::from_bytes(&[8; 32]));
        assert!(store.enroll_destination(&rekeyed).is_err());
        assert!(store.enroll_destination(&enrollment("other", 1)).is_err());
        assert_eq!(ledger_bytes(home.path()), before);
    }

    #[test]
    fn a_quarantined_workload_cannot_enroll_and_malformed_enrollments_are_refused() {
        let home = tempfile::tempdir().unwrap();
        let store = WorkloadStore::open(home.path()).unwrap();
        store.commit(&quarantine("w")).unwrap();
        assert!(store.enroll_destination(&enrollment("w", 1)).is_err());
        for bad in [
            DestinationEnrollment {
                destination: "short".into(),
                ..enrollment("v", 1)
            },
            DestinationEnrollment {
                key: "zz".into(),
                ..enrollment("v", 1)
            },
            DestinationEnrollment {
                tip: DestinationTip {
                    cursor: 0,
                    head: "x".into(),
                },
                ..enrollment("v", 1)
            },
            enrollment("", 1),
        ] {
            assert!(store.enroll_destination(&bad).is_err());
        }
        assert_eq!(sequence(home.path()), 1);
    }

    fn destination_entry(workload: &str, changed: u64) -> DestinationEntry {
        DestinationEntry {
            workload: workload.into(),
            epoch: ExecutionEpoch(1),
            key: "a".repeat(64),
            tip: tip(0),
            changed,
        }
    }

    fn write_destinations(home: &Path, destinations: BTreeMap<String, DestinationEntry>) {
        let mut workloads = WorkloadLedger::default();
        workloads.replace("old");
        let dir = canonical_dir_at(home);
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = serde_json::to_vec(&CanonicalLedger {
            sequence: 5_000_000,
            workloads,
            destinations,
        })
        .unwrap();
        std::fs::write(dir.join(LEDGER_FILE), bytes).unwrap();
    }

    fn id(n: usize) -> String {
        format!("{n:064x}")
    }

    fn is_not_enrolled(error: &anyhow::Error) -> bool {
        error
            .downcast_ref::<DestinationRefusal>()
            .is_some_and(DestinationRefusal::is_not_enrolled)
    }

    fn is_refusal(error: &anyhow::Error) -> bool {
        error.downcast_ref::<DestinationRefusal>().is_some()
    }

    #[test]
    fn a_full_table_with_nothing_stale_evicts_the_least_recently_changed_entry() {
        let home = tempfile::tempdir().unwrap();
        let store = WorkloadStore::open(home.path()).unwrap();
        let table = (0..MAX_DESTINATIONS)
            .map(|n| (id(n), destination_entry("live", n as u64 + 1)))
            .collect();
        write_destinations(home.path(), table);
        store.enroll_destination(&enrollment("live", 1)).unwrap();
        let after = ledger(home.path());
        assert_eq!(after.destinations.len(), MAX_DESTINATIONS);
        assert!(
            !after.destinations.contains_key(&id(0)),
            "smallest changed went"
        );
        assert!(after.destinations.contains_key(&id(1)));
        assert_eq!(after.destinations[DESTINATION].changed, after.sequence);

        let evicted = PreparedHead {
            destination: id(0),
            workload: "live".into(),
            epoch: ExecutionEpoch(1),
            expected: tip(0),
            next: tip(1),
        }
        .sign(&key())
        .unwrap();
        let error = store.commit_destination(&evicted).unwrap_err();
        assert!(is_not_enrolled(&error), "{error:#}");
    }

    #[test]
    fn a_full_table_drops_stale_epoch_entries_before_any_live_one() {
        let home = tempfile::tempdir().unwrap();
        let store = WorkloadStore::open(home.path()).unwrap();
        let table = (0..MAX_DESTINATIONS)
            .map(|n| {
                let stale = n < 10;
                // Stale entries are the most recently changed, so a plain
                // oldest-first rule would keep them and drop live ones.
                let (workload, changed) = if stale {
                    ("old", 10_000 + n as u64)
                } else {
                    ("live", n as u64)
                };
                (id(n), destination_entry(workload, changed))
            })
            .collect();
        write_destinations(home.path(), table);
        store.enroll_destination(&enrollment("live", 1)).unwrap();
        let after = ledger(home.path());
        assert_eq!(after.destinations.len(), MAX_DESTINATIONS - 10 + 1);
        assert!(after.destinations.values().all(|d| d.workload != "old"));
        assert!(after.destinations.contains_key(&id(10)));
    }

    #[test]
    fn the_byte_bound_evicts_the_least_recently_changed_entries_with_long_names() {
        let home = tempfile::tempdir().unwrap();
        let store = WorkloadStore::open(home.path()).unwrap();
        // A control character escapes to six bytes, so these names fill the
        // byte bound long before the count bound.
        let name = "\u{1}".repeat(MAX_NAME_BYTES);
        let mut table = BTreeMap::new();
        let mut n = 0;
        loop {
            table.insert(id(n), destination_entry(&name, n as u64 + 1));
            n += 1;
            if n % 50 == 0 {
                let probe = serde_json::to_vec(&table).unwrap().len() as u64;
                if probe + 1_000 > MAX_LEDGER_BYTES - QUARANTINE_RESERVE_BYTES {
                    break;
                }
            }
        }
        assert!(n < MAX_DESTINATIONS, "bytes bind before the count");
        write_destinations(home.path(), table);
        let mut fresh = enrollment(&name, 1);
        fresh.destination = id(n + 1);
        store.enroll_destination(&fresh).unwrap();
        let bytes = ledger_bytes(home.path());
        assert!(bytes.len() as u64 <= MAX_LEDGER_BYTES - QUARANTINE_RESERVE_BYTES);
        let after = ledger(home.path());
        assert!(!after.destinations.contains_key(&id(0)));
        assert!(after.destinations.contains_key(&fresh.destination));
        assert!(after.destinations.len() < n + 1, "something was evicted");
    }

    #[test]
    fn a_same_binding_re_enrollment_of_a_quarantined_workload_returns_its_tip() {
        let (home, store) = enrolled();
        store
            .commit_destination(&prepared("w", 1, 0, &key()))
            .unwrap();
        store.commit(&quarantine("w")).unwrap();
        let before = ledger_bytes(home.path());
        let again = store.enroll_destination(&enrollment("w", 1)).unwrap();
        assert_eq!(again.tip, tip(1));
        assert_eq!(
            again.sequence, 2,
            "the sequence the destination last changed at"
        );
        assert_eq!(ledger_bytes(home.path()), before);
    }

    #[test]
    fn a_new_enrollment_for_a_quarantined_workload_is_refused() {
        let (_home, store) = enrolled();
        store.commit(&quarantine("w")).unwrap();
        let mut other = enrollment("w", 1);
        other.destination = "e".repeat(64);
        let error = store.enroll_destination(&other).unwrap_err();
        assert!(is_refusal(&error), "{error:#}");
    }

    #[test]
    fn a_commit_that_landed_before_a_quarantine_is_returned_by_re_enrollment_but_no_further_head_commits()
     {
        let (_home, store) = enrolled();
        let first = prepared("w", 1, 0, &key());
        store.commit_destination(&first).unwrap();
        store.commit(&quarantine("w")).unwrap();
        assert_eq!(
            store.enroll_destination(&enrollment("w", 1)).unwrap().tip,
            tip(1)
        );
        assert_eq!(store.commit_destination(&first).unwrap().tip, tip(1));
        let further = prepared("w", 1, 1, &key());
        assert!(is_refusal(&store.commit_destination(&further).unwrap_err()));
    }

    #[test]
    fn an_unreadable_ledger_makes_a_destination_request_unresolved_not_refused() {
        let (home, store) = enrolled();
        std::fs::write(canonical_dir_at(home.path()).join(LEDGER_FILE), b"{").unwrap();
        for error in [
            store.enroll_destination(&enrollment("w", 1)).unwrap_err(),
            store
                .commit_destination(&prepared("w", 1, 0, &key()))
                .unwrap_err(),
        ] {
            assert!(!is_refusal(&error), "{error:#}");
        }
    }

    #[test]
    fn a_fault_at_each_step_is_unresolved_and_recovery_reports_the_outcome() {
        for (step, landed) in [(Step::CommitObligation, false), (Step::CommitLedger, true)] {
            let (home, store) = enrolled();
            let head = prepared("w", 1, 0, &key());
            store.fail_after(step);
            let error = store.commit_destination(&head).unwrap_err();
            assert!(is_unresolved(&error), "{step:?}: {error:#}");
            assert!(WorkloadLedger::load_at(home.path()).is_err());

            drop(store);
            let fresh = WorkloadStore::open(home.path()).unwrap();
            fresh.recover().unwrap();
            let expected = if landed { tip(1) } else { tip(0) };
            assert_eq!(disk_tip(home.path()), expected, "{step:?}");
            let sequence_before = sequence(home.path());
            let answer = fresh.commit_destination(&head).unwrap();
            assert_eq!(answer.tip, tip(1), "{step:?}");
            let wrote = u64::from(!landed);
            assert_eq!(sequence(home.path()), sequence_before + wrote, "{step:?}");
        }
    }

    #[test]
    fn a_migration_fault_during_enrollment_is_unresolved_and_recoverable() {
        for step in [
            Step::MigrateObligation,
            Step::MigrateArchiveDir,
            Step::MigrateExchanged,
            Step::MigrateCanonical,
        ] {
            let home = home_with_legacy(LEGACY);
            let store = WorkloadStore::open(home.path()).unwrap();
            store.fail_after(step);
            let error = store.enroll_destination(&enrollment("x", 1)).unwrap_err();
            assert!(is_unresolved(&error), "{step:?}: {error:#}");
            drop(store);
            let fresh = WorkloadStore::open(home.path()).unwrap();
            fresh.recover().unwrap();
            assert_eq!(
                fresh.enroll_destination(&enrollment("x", 1)).unwrap().tip,
                tip(0)
            );
        }
    }

    #[test]
    fn the_owned_store_exposes_both_operations() {
        let home = tempfile::tempdir().unwrap();
        let owned = OwnedWorkloadStore::open(home.path()).unwrap();
        owned.enroll_destination(&enrollment("w", 1)).unwrap();
        let commit = owned
            .commit_destination(&prepared("w", 1, 0, &key()))
            .unwrap();
        assert_eq!(commit.tip, tip(1));
    }
}
