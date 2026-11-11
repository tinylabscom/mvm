#![cfg(unix)]

use mvm_vmm::host::installed_owner::{
    HolderLease, InstallationKey, InstallationOwner, OwnerError, Phase, Recovery,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn key() -> InstallationKey {
    InstallationKey {
        installation: [0x31; 32],
        profile: [0x47; 32],
    }
}
struct Fixture {
    base: PathBuf,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "spiral-installed-owner-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let root = base.join("installation");
        Self { base, root }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}
fn identity(path: &std::path::Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[test]
fn handoff_exports_exact_current_state_and_pins_original_holder_until_final_close() {
    let fixture = Fixture::new();
    let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
    let epoch = owner.begin().unwrap();
    let lease = HolderLease::acquire(&fixture.root, key(), epoch.generation()).unwrap();
    let record = fs::read(fixture.root.join("state.bin")).unwrap();
    assert_eq!(record.len(), 176);
    let handoff = lease.prepare_handoff().unwrap();
    let directory = handoff.directory.metadata().unwrap();
    let holder = handoff.holder.metadata().unwrap();
    assert_eq!((directory.dev(), directory.ino()), identity(&fixture.root));
    assert_eq!(
        (holder.dev(), holder.ino()),
        identity(&fixture.root.join("holders.lock"))
    );
    assert_eq!(usize::from(handoff.state_bytes), record.len());
    let digest: [u8; 32] = Sha256::digest(&record).into();
    assert_eq!(handoff.state_sha256, digest);
    for file in [&handoff.directory, &handoff.holder] {
        // SAFETY: inspect only each live, borrowed exported descriptor.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    drop(lease);
    assert!(matches!(owner.finish(epoch), Err(OwnerError::Busy)));
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Active);
    drop(handoff);
    owner.finish(epoch).unwrap();
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Clean);
    assert_eq!(owner.snapshot().unwrap().epoch, epoch.generation());
}

#[test]
fn handoff_freshly_refuses_changed_generation_phase_corruption_and_replaced_root() {
    for fault in ["generation", "phase", "checksum", "root"] {
        let fixture = Fixture::new();
        let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
        let epoch = owner.begin().unwrap();
        let lease = HolderLease::acquire(&fixture.root, key(), epoch.generation()).unwrap();
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.root.join("holders.lock"))
            .unwrap();
        // Only the acquired guard retains SH during the refusal checks.
        drop(owner);
        let mut state = fixture.root.join("state.bin");
        let mut record = fs::read(&state).unwrap();
        match fault {
            "generation" => {
                record[16..24]
                    .copy_from_slice(&epoch.generation().checked_add(1).unwrap().to_be_bytes());
                checksum(&mut record);
                fs::write(&state, &record).unwrap();
            }
            "phase" => {
                record[8] = 0;
                checksum(&mut record);
                fs::write(&state, &record).unwrap();
            }
            "checksum" => {
                record[175] ^= 1;
                fs::write(&state, &record).unwrap();
            }
            "root" => {
                let saved = fixture.base.join("saved-installation");
                fs::rename(&fixture.root, &saved).unwrap();
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&fixture.root)
                    .unwrap();
                state = saved.join("state.bin");
            }
            _ => unreachable!(),
        }
        assert!(lease.prepare_handoff().is_err(), "{fault}");
        assert_eq!(fs::read(state).unwrap(), record, "{fault}");
        // SAFETY: independent original holder FD; refusal must not drop SH.
        let blocked = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(blocked, -1, "{fault}");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK),
            "{fault}"
        );
        drop(lease);
        // SAFETY: the same nonblocking probe after the last guard closes.
        assert_eq!(
            unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "{fault}"
        );
    }
}

#[test]
fn exclusive_owner_issues_one_epoch_and_finishes_after_last_holder_exits() {
    let fixture = Fixture::new();
    let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
    assert!(matches!(owner.snapshot().unwrap().phase, Phase::Clean));
    assert_eq!(owner.snapshot().unwrap().epoch, 0);
    let locks = [
        identity(&fixture.root.join("owner.lock")),
        identity(&fixture.root.join("holders.lock")),
    ];
    assert!(matches!(
        InstallationOwner::open(&fixture.root, key()),
        Err(OwnerError::Busy)
    ));
    let epoch = owner.begin().unwrap();
    assert_eq!(epoch.generation(), 1);
    assert!(matches!(owner.snapshot().unwrap().phase, Phase::Active));
    let holder = HolderLease::acquire(&fixture.root, key(), epoch.generation()).unwrap();
    drop(holder);
    owner.finish(epoch).unwrap();
    assert!(matches!(owner.snapshot().unwrap().phase, Phase::Clean));
    assert_eq!(owner.snapshot().unwrap().epoch, 1);
    assert_eq!(
        locks,
        [
            identity(&fixture.root.join("owner.lock")),
            identity(&fixture.root.join("holders.lock"))
        ]
    );
}

const WATCHDOG: Duration = Duration::from_secs(5);
const CHILD_MODE: &str = "SPIRAL_OWNER_TEST_CHILD_MODE";

struct Process {
    child: Child,
    input: ChildStdin,
    events: mpsc::Receiver<String>,
    reader: Option<JoinHandle<()>>,
    reaped: bool,
}
impl Process {
    fn spawn(mode: &str, root: &Path, generation: u64) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "child_process_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_MODE, mode)
            .env("SPIRAL_OWNER_TEST_ROOT", root)
            .env("SPIRAL_OWNER_TEST_GENERATION", generation.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (send, events) = mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else {
                    break;
                };
                // libtest can prefix the first captured line with its test
                // name. Only our explicit protocol suffix enters the channel.
                if let Some(start) = line.find("EVENT ")
                    && send.try_send(line[start..].to_owned()).is_err()
                {
                    return;
                }
            }
            let _ = send.try_send("EVENT EOF".into());
        });
        Self {
            child,
            input,
            events,
            reader: Some(reader),
            reaped: false,
        }
    }
    fn event(&self, prefix: &str) -> String {
        let event = self
            .events
            .recv_timeout(WATCHDOG)
            .expect("child readiness watchdog");
        assert!(event.starts_with(prefix), "expected {prefix}, got {event}");
        event
    }
    fn kill(mut self) {
        self.child.kill().unwrap();
        let status = self.child.wait().unwrap();
        self.reaped = true;
        assert!(
            !status.success(),
            "SIGKILL must not look like orderly shutdown"
        );
        self.reader.take().unwrap().join().unwrap();
    }
    fn finish(mut self, orderly_exit: bool) {
        if orderly_exit {
            self.input.write_all(b"exit\n").unwrap();
            self.input.flush().unwrap();
            self.event("EVENT RELEASED");
        }
        let deadline = Instant::now() + WATCHDOG;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.reaped = true;
                assert!(status.success(), "owned child failed: {status}");
                break;
            }
            assert!(Instant::now() < deadline, "child exit watchdog");
            std::thread::yield_now();
        }
        self.reader.take().unwrap().join().unwrap();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn ready(message: &str) {
    println!("EVENT {message}");
    std::io::stdout().flush().unwrap();
}
fn release_command() {
    let mut command = String::new();
    std::io::stdin().read_line(&mut command).unwrap();
    assert_eq!(command, "exit\n");
}

// This helper is selected with --exact only by this test binary's trusted
// parent. No mode creates a VM, grants authority or accepts a network key.
#[test]
fn child_process_entry() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("SPIRAL_OWNER_TEST_ROOT").unwrap());
    let generation = std::env::var("SPIRAL_OWNER_TEST_GENERATION")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    match mode.as_str() {
        "owner" => {
            let mut owner = InstallationOwner::open(&root, key()).unwrap();
            let epoch = owner.begin().unwrap();
            let (dev, inode) = identity(&root.join("owner.lock"));
            ready(&format!("ACTIVE {} {dev} {inode}", epoch.generation()));
            release_command();
            drop(owner);
        }
        "holder" => {
            let holder = HolderLease::acquire(&root, key(), generation).unwrap();
            ready(&format!("HELD {generation}"));
            release_command();
            drop(holder);
        }
        "contender" => {
            assert!(matches!(
                InstallationOwner::open(&root, key()),
                Err(OwnerError::Busy)
            ));
            let (dev, inode) = identity(&root.join("owner.lock"));
            ready(&format!("BUSY {dev} {inode}"));
            return;
        }
        "raw-clean-holder" => {
            // Negative kernel-lock fixture only, not an authorized resource.
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join("holders.lock"))
                .unwrap();
            // SAFETY: this owned descriptor is open for the duration of SH.
            assert_eq!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
                0
            );
            ready("RAW_HELD");
            release_command();
            drop(lock); // close only; no explicit unlock operation.
        }
        _ => panic!("unknown owned test mode"),
    }
    ready("RELEASED");
}

#[test]
fn owner_death_does_not_retire_an_epoch_while_an_independent_process_holds_sh() {
    let fixture = Fixture::new();
    drop(InstallationOwner::initialize(&fixture.root, key()).unwrap());
    let lock = identity(&fixture.root.join("owner.lock"));
    let owner = Process::spawn("owner", &fixture.root, 0);
    assert_eq!(
        owner.event("EVENT ACTIVE"),
        format!("EVENT ACTIVE 1 {} {}", lock.0, lock.1)
    );
    let contender = Process::spawn("contender", &fixture.root, 0);
    assert_eq!(
        contender.event("EVENT BUSY"),
        format!("EVENT BUSY {} {}", lock.0, lock.1)
    );
    contender.finish(false);
    let holder = Process::spawn("holder", &fixture.root, 1);
    holder.event("EVENT HELD 1");
    owner.kill();
    let mut replacement = InstallationOwner::open(&fixture.root, key()).unwrap();
    assert_eq!(replacement.snapshot().unwrap().phase, Phase::Active);
    assert_eq!(replacement.snapshot().unwrap().epoch, 1);
    assert!(matches!(
        replacement.begin(),
        Err(OwnerError::RecoveryRequired)
    ));
    let state = fs::read(fixture.root.join("state.bin")).unwrap();
    assert!(matches!(replacement.reconcile(), Err(OwnerError::Busy)));
    assert_eq!(fs::read(fixture.root.join("state.bin")).unwrap(), state);
    holder.finish(true);
    assert_eq!(
        replacement.reconcile().unwrap(),
        Recovery::Retired { epoch: 1 }
    );
    let epoch = replacement.begin().unwrap();
    assert_eq!(epoch.generation(), 2);
    assert!(matches!(
        HolderLease::acquire(&fixture.root, key(), 1),
        Err(OwnerError::StaleEpoch)
    ));
    let current = HolderLease::acquire(&fixture.root, key(), 2).unwrap();
    drop(current);
    replacement.finish(epoch).unwrap();
    assert_eq!(identity(&fixture.root.join("owner.lock")), lock);
}

#[test]
fn finish_busy_retains_active_until_actual_holder_exit_and_can_retry_same_epoch() {
    let fixture = Fixture::new();
    let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
    let epoch = owner.begin().unwrap();
    let holder = Process::spawn("holder", &fixture.root, epoch.generation());
    holder.event("EVENT HELD 1");
    let state = fs::read(fixture.root.join("state.bin")).unwrap();
    assert!(matches!(owner.finish(epoch), Err(OwnerError::Busy)));
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Active);
    assert_eq!(fs::read(fixture.root.join("state.bin")).unwrap(), state);
    holder.finish(true);
    owner.finish(epoch).unwrap();
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Clean);
    assert_eq!(owner.snapshot().unwrap().epoch, 1);
}

fn checksum(record: &mut [u8]) {
    assert_eq!(record.len(), 176);
    let mut hash = Sha256::new();
    hash.update(b"spiralcore/installed-owner/v1\0");
    hash.update(&record[..144]);
    let digest: [u8; 32] = hash.finalize().into();
    record[144..].copy_from_slice(&digest);
}
fn invalid(root: &Path) {
    assert!(matches!(
        InstallationOwner::open(root, key()),
        Err(OwnerError::InvalidStorage)
    ));
}

#[test]
fn fixed_record_detects_torn_oversized_reserved_and_checksummed_semantic_corruption() {
    for mode in [
        "missing", "empty", "torn", "trailing", "checksum", "phase", "reserved", "magic",
        "trailer", "identity",
    ] {
        let fixture = Fixture::new();
        drop(InstallationOwner::initialize(&fixture.root, key()).unwrap());
        let path = fixture.root.join("state.bin");
        let mut record = fs::read(&path).unwrap();
        assert_eq!(record.len(), 176);
        assert_eq!(&record[..8], b"SCOWNER1");
        assert_eq!(&record[136..144], b"ENDOWN01");
        assert_eq!(&record[24..56], &key().installation);
        assert_eq!(&record[56..88], &key().profile);
        let mut recomputed = record.clone();
        checksum(&mut recomputed);
        assert_eq!(record, recomputed);
        match mode {
            "missing" => {
                fs::remove_file(&path).unwrap();
                invalid(&fixture.root);
                continue;
            }
            "empty" => record.clear(),
            "torn" => {
                record.pop();
            }
            "trailing" => record.push(0),
            "checksum" => record[175] ^= 1,
            "phase" => {
                record[8] = 2;
                checksum(&mut record);
            }
            "reserved" => {
                record[9] = 1;
                checksum(&mut record);
            }
            "magic" => {
                record[0] ^= 1;
                checksum(&mut record);
            }
            "trailer" => {
                record[136] ^= 1;
                checksum(&mut record);
            }
            "identity" => {
                record[112] ^= 1;
                checksum(&mut record);
            }
            _ => unreachable!(),
        }
        fs::write(&path, &record).unwrap();
        invalid(&fixture.root);
        assert_eq!(
            fs::read(&path).unwrap(),
            record,
            "refusal must not repair/reset {mode}"
        );
    }
    let fixture = Fixture::new();
    drop(InstallationOwner::initialize(&fixture.root, key()).unwrap());
    let path = fixture.root.join("state.bin");
    let mut record = fs::read(&path).unwrap();
    record[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    checksum(&mut record);
    fs::write(&path, &record).unwrap();
    let mut owner = InstallationOwner::open(&fixture.root, key()).unwrap();
    assert!(matches!(owner.begin(), Err(OwnerError::EpochExhausted)));
    assert_eq!(owner.snapshot().unwrap().epoch, u64::MAX);
    assert_eq!(fs::read(path).unwrap(), record);
}

#[test]
fn key_profile_modes_symlinks_hardlinks_and_nonregular_objects_refuse_without_reset() {
    for mode in [
        "wrong-key",
        "wrong-profile",
        "root-mode",
        "root-symlink",
        "owner-mode",
        "holders-mode",
        "state-mode",
        "owner-symlink",
        "holders-symlink",
        "state-symlink",
        "owner-hardlink",
        "holders-hardlink",
        "state-hardlink",
        "owner-directory",
        "holders-directory",
        "state-directory",
    ] {
        let fixture = Fixture::new();
        drop(InstallationOwner::initialize(&fixture.root, key()).unwrap());
        let original = fs::read(fixture.root.join("state.bin")).unwrap();
        let mut target = fixture.root.clone();
        let mut supplied = key();
        match mode {
            "wrong-key" => supplied.installation[0] ^= 1,
            "wrong-profile" => supplied.profile[0] ^= 1,
            "root-mode" => fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap(),
            "root-symlink" => {
                target = fixture.base.join("alias");
                symlink(&fixture.root, &target).unwrap();
            }
            _ => {
                let object = if mode.starts_with("owner-") {
                    "owner.lock"
                } else if mode.starts_with("holders-") {
                    "holders.lock"
                } else {
                    "state.bin"
                };
                let path = fixture.root.join(object);
                if mode.ends_with("-mode") {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
                } else if mode.ends_with("-hardlink") {
                    fs::hard_link(path, fixture.base.join("extra-link")).unwrap();
                } else {
                    let saved = fixture.base.join("saved-object");
                    fs::rename(&path, &saved).unwrap();
                    if mode.ends_with("-symlink") {
                        symlink(saved, path).unwrap();
                    } else {
                        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
                    }
                }
            }
        }
        assert!(
            matches!(
                InstallationOwner::open(&target, supplied),
                Err(OwnerError::InvalidStorage)
            ),
            "{mode}"
        );
        if !mode.starts_with("state-") {
            assert_eq!(
                fs::read(fixture.root.join("state.bin")).unwrap(),
                original,
                "{mode}"
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn extended_acl_access_refuses_even_when_posix_modes_remain_private() {
    // A component privacy gate, not a foreign-UID access or VM-launch witness.
    // chmod mutates only this test's private fixtures; no ACL is repaired/reset.
    let mut observations = Vec::new();
    for object in ["parent", "root", "owner.lock", "holders.lock", "state.bin"] {
        let fixture = Fixture::new();
        let original = if object == "parent" {
            None
        } else {
            drop(InstallationOwner::initialize(&fixture.root, key()).unwrap());
            Some(fs::read(fixture.root.join("state.bin")).unwrap())
        };
        let target = match object {
            "parent" => fixture.base.clone(),
            "root" => fixture.root.clone(),
            name => fixture.root.join(name),
        };
        let original_mode = fs::symlink_metadata(&target).unwrap().mode() & 0o7777;
        assert_eq!(
            original_mode,
            if object == "parent" || object == "root" {
                0o700
            } else {
                0o600
            }
        );
        let ace = if object == "parent" {
            "everyone allow read,write,execute,file_inherit,directory_inherit"
        } else if object == "root" {
            "everyone allow read,write,execute"
        } else {
            "everyone allow read,write"
        };
        let chmod = Command::new("/bin/chmod")
            .args(["+a", ace])
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            chmod.status.success(),
            "{object}: {}",
            String::from_utf8_lossy(&chmod.stderr)
        );
        assert_eq!(
            fs::symlink_metadata(&target).unwrap().mode() & 0o7777,
            original_mode,
            "ACL setup must leave the private POSIX bits unchanged"
        );
        let listing = Command::new("/bin/ls")
            .arg("-lde")
            .arg(&target)
            .output()
            .unwrap();
        assert!(listing.status.success());
        let listing = String::from_utf8(listing.stdout).unwrap();
        assert!(listing.contains("group:everyone allow"), "{listing}");
        if object == "parent" {
            assert!(listing.contains("file_inherit,directory_inherit"));
        }
        let result = if object == "parent" {
            InstallationOwner::initialize(&fixture.root, key())
        } else {
            InstallationOwner::open(&fixture.root, key())
        }
        .map(|_| ());
        observations.push((
            object,
            matches!(&result, Err(OwnerError::InvalidStorage)),
            format!("{result:?}"),
        ));
        if let Some(original) = original {
            assert_eq!(fs::read(fixture.root.join("state.bin")).unwrap(), original);
        }
        // The ACL itself is retained until owned-fixture removal, including
        // when initialization/open erroneously succeeds on the baseline.
        let after = Command::new("/bin/ls")
            .arg("-lde")
            .arg(&target)
            .output()
            .unwrap();
        assert!(after.status.success());
        let after = String::from_utf8(after.stdout).unwrap();
        assert_eq!(
            after.lines().skip(1).collect::<Vec<_>>(),
            listing.lines().skip(1).collect::<Vec<_>>()
        );
    }
    for (object, refused, _) in &observations {
        assert!(
            refused,
            "{object} accepted an ACL privacy violation: {observations:?}"
        );
    }
}

#[test]
fn live_directory_or_lock_replacement_fences_before_any_new_epoch_publication() {
    for object in ["directory", "owner.lock", "holders.lock"] {
        let fixture = Fixture::new();
        let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
        let state = fs::read(fixture.root.join("state.bin")).unwrap();
        let state_path = if object == "directory" {
            let saved = fixture.base.join("original-directory");
            fs::rename(&fixture.root, &saved).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&fixture.root)
                .unwrap();
            saved.join("state.bin")
        } else {
            let path = fixture.root.join(object);
            fs::rename(&path, fixture.base.join("original-lock")).unwrap();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            fixture.root.join("state.bin")
        };
        assert!(matches!(owner.begin(), Err(OwnerError::Fenced)), "{object}");
        assert!(matches!(owner.begin(), Err(OwnerError::Fenced)), "{object}");
        assert_eq!(fs::read(state_path).unwrap(), state);
    }
}

#[test]
fn drop_never_cleans_and_retirement_preserves_history_and_rejects_late_old_token() {
    let fixture = Fixture::new();
    let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
    let old = owner.begin().unwrap();
    drop(owner);
    let mut owner = InstallationOwner::open(&fixture.root, key()).unwrap();
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Active);
    assert!(matches!(owner.begin(), Err(OwnerError::RecoveryRequired)));
    assert_eq!(owner.reconcile().unwrap(), Recovery::Retired { epoch: 1 });
    assert_eq!(owner.reconcile().unwrap(), Recovery::AlreadyClean);
    assert!(matches!(
        HolderLease::acquire(&fixture.root, key(), 1),
        Err(OwnerError::StaleEpoch)
    ));
    let current = owner.begin().unwrap();
    assert_eq!(current.generation(), 2);
    assert!(matches!(owner.finish(old), Err(OwnerError::StaleEpoch)));
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Active);
    owner.finish(current).unwrap();
    drop(owner);
    let owner = InstallationOwner::open(&fixture.root, key()).unwrap();
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Clean);
    assert_eq!(owner.snapshot().unwrap().epoch, 2);
}

#[test]
fn occupied_clean_holder_blocks_activation_and_uncertain_temp_and_zero_keys_refuse() {
    let fixture = Fixture::new();
    let mut owner = InstallationOwner::initialize(&fixture.root, key()).unwrap();
    let holder = Process::spawn("raw-clean-holder", &fixture.root, 0);
    holder.event("EVENT RAW_HELD");
    let state = fs::read(fixture.root.join("state.bin")).unwrap();
    assert!(matches!(owner.begin(), Err(OwnerError::Busy)));
    assert_eq!(owner.snapshot().unwrap().phase, Phase::Clean);
    assert_eq!(fs::read(fixture.root.join("state.bin")).unwrap(), state);
    holder.finish(true);
    let epoch = owner.begin().unwrap();
    assert_eq!(epoch.generation(), 1);
    owner.finish(epoch).unwrap();
    let finished = fs::read(fixture.root.join("state.bin")).unwrap();
    assert!(InstallationOwner::initialize(&fixture.root, key()).is_err());
    assert_eq!(fs::read(fixture.root.join("state.bin")).unwrap(), finished);
    drop(owner);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fixture.root.join(".state.next"))
        .unwrap();
    assert!(matches!(
        InstallationOwner::open(&fixture.root, key()),
        Err(OwnerError::Fenced)
    ));
    assert!(fixture.root.join(".state.next").exists());
    for zero_installation in [true, false] {
        let fresh = Fixture::new();
        let mut invalid = key();
        if zero_installation {
            invalid.installation = [0; 32];
        } else {
            invalid.profile = [0; 32];
        }
        assert!(matches!(
            InstallationOwner::initialize(&fresh.root, invalid),
            Err(OwnerError::InvalidStorage)
        ));
    }
}
