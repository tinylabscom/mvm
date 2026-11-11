use super::*;
use std::{
    cell::RefCell,
    fs::OpenOptions,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    sync::atomic::AtomicU64,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    HoldersAba,
    StateDirectorySyncFailure,
    IntentFileSyncFailure,
    IntentDirectorySyncFailure,
    IntentCleanupDirectorySyncFailure,
}
struct Fault {
    root: PathBuf,
    saved_a: PathBuf,
    saved_b: PathBuf,
    mode: Mode,
    before: usize,
    after: usize,
    sync_failures: usize,
    original: Option<ObjectId>,
    replacement: Option<ObjectId>,
}
thread_local! { static FAULT: RefCell<Option<Fault>> = const { RefCell::new(None) }; }

struct Scope;
impl Scope {
    fn arm(root: &Path, mode: Mode) -> Self {
        FAULT.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(
                slot.is_none(),
                "fault scopes must not overlap on one thread"
            );
            let parent = root.parent().unwrap();
            *slot = Some(Fault {
                root: root.to_path_buf(),
                saved_a: parent.join("holders-original-A"),
                saved_b: parent.join("holders-replacement-B"),
                mode,
                before: 0,
                after: 0,
                sync_failures: 0,
                original: None,
                replacement: None,
            });
        });
        Self
    }
    fn counts(&self) -> (usize, usize, usize) {
        FAULT.with(|slot| {
            let slot = slot.borrow();
            let fault = slot.as_ref().unwrap();
            (fault.before, fault.after, fault.sync_failures)
        })
    }
    fn different_objects(&self) -> bool {
        FAULT.with(|slot| {
            let slot = slot.borrow();
            let fault = slot.as_ref().unwrap();
            fault.original.is_some()
                && fault.replacement.is_some()
                && fault.original != fault.replacement
        })
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        FAULT.with(|slot| {
            if let Some(fault) = slot.borrow_mut().take() {
                // Restore A even when source validation returns early or a test
                // assertion unwinds before the after-open hook is reached.
                if fault.saved_a.exists() {
                    let _ = fs::remove_file(fault.root.join(HOLDERS));
                    let _ = fs::rename(&fault.saved_a, fault.root.join(HOLDERS));
                }
                let _ = fs::remove_file(fault.saved_b);
            }
        });
    }
}

pub(super) fn before_holders_open(storage: &Storage) -> Result<()> {
    FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(fault) = slot.as_mut() else {
            return Ok(());
        };
        if fault.root != storage.root || !matches!(fault.mode, Mode::HoldersAba) {
            return Ok(());
        }
        fault.before += 1;
        if fault.before != 1 {
            return Err(OwnerError::Io(io::Error::other(
                "unexpected second ABA open",
            )));
        }
        let original = OpenOptions::new()
            .read(true)
            .write(true)
            .open(storage.root.join(HOLDERS))?;
        fault.original = Some(object_id(&original)?);
        fs::rename(storage.root.join(HOLDERS), &fault.saved_a)?;
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(storage.root.join(HOLDERS))?;
        fault.replacement = Some(object_id(&replacement)?);
        Ok(())
    })
}

pub(super) fn after_holders_open(storage: &Storage) -> Result<()> {
    FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(fault) = slot.as_mut() else {
            return Ok(());
        };
        if fault.root != storage.root || !matches!(fault.mode, Mode::HoldersAba) {
            return Ok(());
        }
        fault.after += 1;
        // The actual intervening open obtained B. Restore the pathname to A so
        // a later pathname-only validation cannot discover that wrong FD.
        fs::rename(storage.root.join(HOLDERS), &fault.saved_b)?;
        fs::rename(&fault.saved_a, storage.root.join(HOLDERS))?;
        Ok(())
    })
}

pub(super) fn before_state_directory_sync(storage: &Storage) -> Result<()> {
    FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(fault) = slot.as_mut() else {
            return Ok(());
        };
        if fault.root != storage.root || !matches!(fault.mode, Mode::StateDirectorySyncFailure) {
            return Ok(());
        }
        fault.sync_failures += 1;
        Err(OwnerError::Io(io::Error::from_raw_os_error(libc::EIO)))
    })
}

fn fail_at_intent_barrier(storage: &Storage, mode: Mode) -> Result<()> {
    FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(fault) = slot.as_mut() else {
            return Ok(());
        };
        if fault.root != storage.root || fault.mode != mode {
            return Ok(());
        }
        fault.sync_failures += 1;
        Err(OwnerError::Io(io::Error::from_raw_os_error(libc::EIO)))
    })
}

pub(super) fn before_intent_file_sync(storage: &Storage) -> Result<()> {
    fail_at_intent_barrier(storage, Mode::IntentFileSyncFailure)
}

pub(super) fn before_intent_directory_sync(storage: &Storage) -> Result<()> {
    fail_at_intent_barrier(storage, Mode::IntentDirectorySyncFailure)
}

pub(super) fn before_intent_cleanup_directory_sync(storage: &Storage) -> Result<()> {
    fail_at_intent_barrier(storage, Mode::IntentCleanupDirectorySyncFailure)
}

struct Fixture {
    base: PathBuf,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "spiral-owner-unit-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        Self {
            root: base.join("installation"),
            base,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn key() -> InstallationKey {
    InstallationKey {
        installation: [0x51; 32],
        profile: [0x63; 32],
    }
}

#[derive(Debug)]
struct AbaObservation {
    operation: &'static str,
    accepted: bool,
    state_unchanged: bool,
}

#[test]
fn holders_aba_must_reject_the_actual_wrong_fd_and_never_retire_live_original_holders() {
    let mut observations = Vec::new();
    for operation in ["acquire-sh", "finish-ex", "reconcile-ex"] {
        let fixture = Fixture::new();
        let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
        let epoch = owner.begin().unwrap();
        // Independently opened A remains SH-held throughout every ABA action.
        let actual_holder = HolderLease::acquire(&fixture.root, key(), epoch.generation()).unwrap();
        if operation == "reconcile-ex" {
            drop(owner);
            owner = InstallationOwner::open(&fixture.root, key()).unwrap();
        }
        let before = fs::read(fixture.root.join(STATE)).unwrap();
        let scope = Scope::arm(&fixture.root, Mode::HoldersAba);
        let accepted = match operation {
            "acquire-sh" => {
                let result = HolderLease::acquire(&fixture.root, key(), epoch.generation());
                let accepted = result.is_ok();
                drop(result);
                accepted
            }
            "finish-ex" => owner.finish(epoch).is_ok(),
            "reconcile-ex" => owner.reconcile().is_ok(),
            _ => unreachable!(),
        };
        assert_eq!(scope.counts(), (1, 1, 0));
        assert!(
            scope.different_objects(),
            "fixture must open a genuinely different B inode"
        );
        let state_unchanged = fs::read(fixture.root.join(STATE)).unwrap() == before;
        observations.push(AbaObservation {
            operation,
            accepted,
            state_unchanged,
        });
        drop(scope);
        drop(actual_holder);
        drop(owner);
    }
    // Evaluate only after all three actual opens: one failing SH regression
    // cannot hide evidence that finish/reconcile also bypassed the real A lock.
    for observation in &observations {
        assert!(
            !observation.accepted && observation.state_unchanged,
            "{} accepted the ABA FD or published over an actual live holder: {observations:?}",
            observation.operation
        );
    }
}

#[derive(Debug)]
struct SyncObservation {
    operation: &'static str,
    reopened_fenced: bool,
}

#[test]
fn postrename_directory_sync_failure_must_survive_owner_drop_as_a_durable_fence() {
    let mut observations = Vec::new();
    for operation in ["finish", "reconcile"] {
        let fixture = Fixture::new();
        let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
        let epoch = owner.begin().unwrap();
        if operation == "reconcile" {
            drop(owner);
            owner = InstallationOwner::open(&fixture.root, key()).unwrap();
        }
        let scope = Scope::arm(&fixture.root, Mode::StateDirectorySyncFailure);
        let result = if operation == "finish" {
            owner.finish(epoch).map(|_| ())
        } else {
            owner.reconcile().map(|_| ())
        };
        assert!(
            matches!(result, Err(OwnerError::Io(ref error)) if error.raw_os_error()==Some(libc::EIO)),
            "{operation}"
        );
        assert_eq!(scope.counts(), (0, 0, 1));
        let visible = Record::decode(&fs::read(fixture.root.join(STATE)).unwrap()).unwrap();
        assert_eq!(
            visible.phase,
            Phase::Clean,
            "fault must occur after the actual rename"
        );
        assert_eq!(visible.generation, epoch.generation());
        assert!(matches!(owner.snapshot(), Err(OwnerError::Fenced)));
        drop(scope);
        drop(owner);
        let reopened_fenced = matches!(
            InstallationOwner::open(&fixture.root, key()),
            Err(OwnerError::Fenced)
        );
        observations.push(SyncObservation {
            operation,
            reopened_fenced,
        });
    }
    for observation in &observations {
        assert!(
            observation.reopened_fenced,
            "{} allowed a visible but unconfirmed Clean to regain admission after owner Drop: {observations:?}",
            observation.operation
        );
    }
}

#[test]
fn failed_initial_intent_barriers_preserve_original_state_and_fence_reopen() {
    for mode in [
        Mode::IntentFileSyncFailure,
        Mode::IntentDirectorySyncFailure,
    ] {
        for operation in ["begin", "finish", "reconcile"] {
            let fixture = Fixture::new();
            let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
            let epoch = if operation == "begin" {
                None
            } else {
                Some(owner.begin().unwrap())
            };
            if operation == "reconcile" {
                drop(owner);
                owner = InstallationOwner::open(&fixture.root, key()).unwrap();
            }
            let original = fs::read(fixture.root.join(STATE)).unwrap();
            let scope = Scope::arm(&fixture.root, mode);
            let result = match operation {
                "begin" => owner.begin().map(|_| ()),
                "finish" => owner.finish(epoch.unwrap()),
                "reconcile" => owner.reconcile().map(|_| ()),
                _ => unreachable!(),
            };
            assert!(
                matches!(result, Err(OwnerError::Io(ref error)) if error.raw_os_error() == Some(libc::EIO)),
                "{operation}/{mode:?}"
            );
            assert_eq!(scope.counts(), (0, 0, 1), "{operation}/{mode:?}");
            // These faults precede every STATE write, not merely its rename.
            assert_eq!(fs::read(fixture.root.join(STATE)).unwrap(), original);
            assert!(fixture.root.join(INTENT).is_file());
            assert!(!fixture.root.join(NEXT).exists());
            assert!(matches!(owner.snapshot(), Err(OwnerError::Fenced)));
            drop(scope);
            drop(owner);
            assert!(
                matches!(
                    InstallationOwner::open(&fixture.root, key()),
                    Err(OwnerError::Fenced)
                ),
                "{operation}/{mode:?}"
            );
        }
    }
}

#[test]
fn failed_postcommit_cleanup_sync_fences_owner_but_absent_marker_allows_durable_successor() {
    for operation in ["finish", "reconcile"] {
        let fixture = Fixture::new();
        let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
        let epoch = owner.begin().unwrap();
        if operation == "reconcile" {
            drop(owner);
            owner = InstallationOwner::open(&fixture.root, key()).unwrap();
        }
        let scope = Scope::arm(&fixture.root, Mode::IntentCleanupDirectorySyncFailure);
        let result = if operation == "finish" {
            owner.finish(epoch)
        } else {
            owner.reconcile().map(|_| ())
        };
        assert!(
            matches!(result, Err(OwnerError::Io(ref error)) if error.raw_os_error() == Some(libc::EIO)),
            "{operation}"
        );
        assert_eq!(scope.counts(), (0, 0, 1));
        // The hook is after the confirmed STATE barrier and actual unlink.
        assert!(!fixture.root.join(INTENT).exists());
        assert!(!fixture.root.join(NEXT).exists());
        let visible = Record::decode(&fs::read(fixture.root.join(STATE)).unwrap()).unwrap();
        assert_eq!(visible.phase, Phase::Clean);
        assert_eq!(visible.generation, epoch.generation());
        assert!(matches!(owner.snapshot(), Err(OwnerError::Fenced)));
        drop(scope);
        drop(owner);
        let mut successor = InstallationOwner::open(&fixture.root, key()).unwrap();
        let snapshot = successor.snapshot().unwrap();
        assert_eq!(snapshot.phase, Phase::Clean);
        assert_eq!(snapshot.epoch, epoch.generation());
        assert_eq!(
            successor.begin().unwrap().generation(),
            epoch.generation() + 1
        );
    }
}
