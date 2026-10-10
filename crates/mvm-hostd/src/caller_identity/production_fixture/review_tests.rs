use std::ffi::OsString;
use std::fs;
use std::io::{BufRead as _, Read as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

use super::*;
use mvm_core::config::default_mvm_home_at;

const LOCK_CHILD: &str = "caller_identity::production_fixture::review_tests::record_lock_child";
const GATE_CHILD: &str = "caller_identity::production_fixture::review_tests::gated_child";

pub(super) struct Inputs {
    _base: tempfile::TempDir,
    home: PathBuf,
    root: PathBuf,
    program: PathBuf,
    values: Vec<(OsString, OsString)>,
}

impl Inputs {
    pub(super) fn new() -> Self {
        let base = tempfile::Builder::new()
            .prefix("mvm-fixture-test.")
            .tempdir_in("/tmp")
            .unwrap();
        let home = base.path().join("home");
        let root = base.path().join("mvm-caller-native.case");
        for path in [
            home.clone(),
            default_mvm_home_at(&home),
            root.clone(),
            root.join("mvm"),
            root.join("tmp"),
            root.join("cargo"),
            root.join("target"),
        ] {
            mvm_core::private_fs::ensure_private_dir(path).unwrap();
        }
        atomic_io::write_private(
            &root.join("caller-witness-owned"),
            b"native-cold-registration-v1\n",
        )
        .unwrap();
        atomic_io::write_private(&default_mvm_home_at(&home).join("untouched"), b"user-state")
            .unwrap();
        let program = base.path().join("prepared-program");
        atomic_io::write_new_with_mode(&program, b"prepared", 0o700).unwrap();
        let values = [
            ("HOME", home.clone().into_os_string()),
            ("PATH", OsString::from("/usr/bin:/bin")),
            ("MVM_CALLER_WITNESS_ROOT", root.clone().into_os_string()),
            ("MVM_HOME", root.join("mvm").into_os_string()),
            ("TMPDIR", root.join("tmp").into_os_string()),
            ("CARGO_HOME", root.join("cargo").into_os_string()),
            ("CARGO_TARGET_DIR", root.join("target").into_os_string()),
            (
                "MVM_CALLER_WITNESS_SOURCE",
                program.clone().into_os_string(),
            ),
            (
                "MVM_CALLER_WITNESS_KERNEL",
                program.clone().into_os_string(),
            ),
            ("MVM_HVF_SUPERVISOR_PATH", program.clone().into_os_string()),
            ("MVM_RESIDENCY", OsString::from("cold")),
            ("MVM_KERNEL_SOURCE", OsString::from("download")),
            (
                "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE",
                OsString::from("download"),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (OsString::from(name), value))
        .collect();
        Self {
            _base: base,
            home,
            root,
            program,
            values,
        }
    }

    fn snapshot(&self) -> Result<Snapshot> {
        Snapshot::validate(
            self.values.clone(),
            self.program.clone().into_os_string(),
            self.root.join(environment::RECORD_NAME).into_os_string(),
        )
    }

    fn set(&mut self, name: &str, value: OsString) {
        self.values
            .iter_mut()
            .find(|(key, _)| key == name)
            .unwrap()
            .1 = value;
    }

    pub(super) fn fixture(&self) -> Fixture {
        let environment = self.snapshot().unwrap();
        let lock = RecordLock::acquire(&environment).unwrap();
        Fixture {
            path: environment.record().to_path_buf(),
            record: Record {
                installation: INSTALLATION.into(),
                service: SERVICE.into(),
                account: account(INSTALLATION.parse().unwrap()).unwrap(),
                state: "unit-test-no-enrollment".into(),
                public_pin: None,
                controller_pid: std::process::id(),
                child_pid: None,
                witness_program: environment.program().to_path_buf(),
                witness_environment: environment.values().to_vec(),
                cleanup_program: std::env::current_exe().unwrap(),
                cleanup_arguments: Vec::new(),
                cleanup_environment: Vec::new(),
                interruption_guidance: "unit fixture has no OS credential".into(),
            },
            environment,
            child: None,
            cleanup_attempted: true,
            _lock: lock,
        }
    }
}

fn refuses_before_effects(inputs: &Inputs) {
    let store = AtomicUsize::new(0);
    let spawn = AtomicUsize::new(0);
    let result = inputs.snapshot().map(|_| {
        store.fetch_add(1, Ordering::SeqCst);
        spawn.fetch_add(1, Ordering::SeqCst);
    });
    assert!(result.is_err());
    assert_eq!(store.load(Ordering::SeqCst), 0);
    assert_eq!(spawn.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(default_mvm_home_at(&inputs.home).join("untouched")).unwrap(),
        b"user-state"
    );
}

#[test]
fn invalid_writable_paths_refuse_before_store_or_child_seams() {
    for name in ["TMPDIR", "CARGO_HOME", "CARGO_TARGET_DIR"] {
        let mut inputs = Inputs::new();
        inputs.set(name, OsString::new());
        refuses_before_effects(&inputs);
    }
    for bad in [
        OsString::new(),
        OsString::from(" "),
        OsString::from("relative"),
        OsString::from_vec(vec![b'/', 0xff]),
    ] {
        let mut inputs = Inputs::new();
        inputs.set("MVM_HOME", bad);
        refuses_before_effects(&inputs);
    }
    let mut inputs = Inputs::new();
    inputs.values.retain(|(name, _)| name != "MVM_HOME");
    refuses_before_effects(&inputs);
    let mut inputs = Inputs::new();
    inputs.set("MVM_HOME", inputs.root.join("tmp/../mvm").into_os_string());
    refuses_before_effects(&inputs);
    let mut inputs = Inputs::new();
    inputs.set(
        "MVM_HOME",
        default_mvm_home_at(&inputs.home).into_os_string(),
    );
    refuses_before_effects(&inputs);
}

#[test]
fn default_home_descendants_and_symlink_aliases_never_become_fixture_state() {
    let mut inputs = Inputs::new();
    mvm_core::private_fs::ensure_private_dir(default_mvm_home_at(&inputs.home).join("descendant"))
        .unwrap();
    inputs.set(
        "MVM_HOME",
        default_mvm_home_at(&inputs.home)
            .join("descendant")
            .into_os_string(),
    );
    refuses_before_effects(&inputs);
    let inputs = Inputs::new();
    fs::remove_dir(inputs.root.join("mvm")).unwrap();
    symlink(default_mvm_home_at(&inputs.home), inputs.root.join("mvm")).unwrap();
    refuses_before_effects(&inputs);
    let inputs = Inputs::new();
    fs::remove_dir(inputs.root.join("tmp")).unwrap();
    symlink(default_mvm_home_at(&inputs.home), inputs.root.join("tmp")).unwrap();
    refuses_before_effects(&inputs);
    let mut inputs = Inputs::new();
    let alias = inputs.root.join("alias");
    symlink(inputs.root.join("mvm"), &alias).unwrap();
    inputs.set("MVM_HOME", alias.into_os_string());
    refuses_before_effects(&inputs);
}

#[test]
fn a_default_home_symlink_into_the_fixture_is_still_default_user_state() {
    let inputs = Inputs::new();
    fs::rename(
        default_mvm_home_at(&inputs.home),
        inputs.home.join("original-state"),
    )
    .unwrap();
    symlink(inputs.root.join("mvm"), default_mvm_home_at(&inputs.home)).unwrap();
    assert!(inputs.snapshot().is_err());
    assert_eq!(
        fs::read(inputs.home.join("original-state/untouched")).unwrap(),
        b"user-state"
    );
}

#[test]
fn fixture_child_command_carries_only_the_validated_snapshot() {
    let inputs = Inputs::new();
    let snapshot = inputs.snapshot().unwrap();
    let command = snapshot.command(snapshot.program()).unwrap();
    let actual: std::collections::BTreeMap<_, _> = command.get_envs().collect();
    assert_eq!(actual.len(), snapshot.values().len() + 2);
    for (name, value) in snapshot.values() {
        assert_eq!(
            actual[std::ffi::OsStr::new(name)],
            Some(std::ffi::OsStr::new(value))
        );
    }
    for (name, value) in [
        ("MVM_CALLER_WITNESS_BIN", snapshot.program()),
        ("MVM_CALLER_FIXTURE_RECORD", snapshot.record()),
    ] {
        assert_eq!(actual[std::ffi::OsStr::new(name)], Some(value.as_os_str()));
    }
}

#[test]
fn canonical_snapshot_revalidates_records_instead_of_trusting_record_strings() {
    let inputs = Inputs::new();
    let snapshot = inputs.snapshot().unwrap();
    snapshot.revalidate().unwrap();
    snapshot
        .validate_record(snapshot.program(), snapshot.values())
        .unwrap();
    let mut poisoned = snapshot.values().to_vec();
    poisoned.retain(|(name, _)| name != "MVM_HOME");
    let effects = AtomicUsize::new(0);
    assert!(
        snapshot
            .validate_record(snapshot.program(), &poisoned)
            .map(|_| {
                effects.fetch_add(1, Ordering::SeqCst);
            })
            .is_err()
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let mut poisoned = snapshot.values().to_vec();
    poisoned
        .iter_mut()
        .find(|(name, _)| name == "MVM_HOME")
        .unwrap()
        .1
        .clear();
    assert!(
        snapshot
            .validate_record(snapshot.program(), &poisoned)
            .is_err()
    );
    fs::remove_dir(inputs.root.join("mvm")).unwrap();
    symlink(default_mvm_home_at(&inputs.home), inputs.root.join("mvm")).unwrap();
    assert!(snapshot.command(snapshot.program()).is_err());
}

#[test]
fn competing_recoverer_cannot_read_or_claim_before_exclusive_lock() {
    let inputs = Inputs::new();
    let fixture = inputs.fixture();
    fixture.persist().unwrap();
    let snapshot = fixture.environment.clone();
    let entered = Arc::new(AtomicUsize::new(0));
    let other_entered = Arc::clone(&entered);
    let second = std::thread::spawn(move || {
        RecordLock::acquire(&snapshot).map(|lock| {
            other_entered.fetch_add(1, Ordering::SeqCst);
            lock.read(snapshot.record()).unwrap();
        })
    });
    assert!(second.join().unwrap().is_err());
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    let snapshot = fixture.environment.clone();
    drop(fixture);
    let lock = RecordLock::acquire(&snapshot).unwrap();
    lock.read(snapshot.record()).unwrap();
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = stop_owned_child(&mut self.0);
    }
}

#[test]
fn record_lock_is_released_when_its_holder_process_crashes() {
    let inputs = Inputs::new();
    let snapshot = inputs.snapshot().unwrap();
    let mut command = snapshot.command(&std::env::current_exe().unwrap()).unwrap();
    command
        .args(["--ignored", "--exact", LOCK_CHILD, "--nocapture"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = ChildGuard(command.spawn().unwrap());
    let output = child.0.stdout.take().unwrap();
    let (ready, observed) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let found = std::io::BufReader::new(output)
            .lines()
            .any(|line| line.is_ok_and(|line| line.contains("FIXTURE_LOCK_HELD")));
        let _ = ready.send(found);
    });
    assert!(observed.recv_timeout(Duration::from_secs(5)).unwrap());
    assert!(RecordLock::acquire(&snapshot).is_err());
    stop_owned_child(&mut child.0).unwrap();
    reader.join().unwrap();
    let _released = RecordLock::acquire(&snapshot).unwrap();
}

#[test]
#[ignore = "non-credential child of the record-lock crash regression"]
fn record_lock_child() -> Result<()> {
    let snapshot = Snapshot::from_process()?;
    let _lock = RecordLock::acquire(&snapshot)?;
    println!("FIXTURE_LOCK_HELD");
    std::io::stdout().flush()?;
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte)?;
    Ok(())
}

fn gate_command(fixture: &Fixture) -> Command {
    let mut command = fixture
        .environment
        .command(&std::env::current_exe().unwrap())
        .unwrap();
    command.args(["--ignored", "--exact", GATE_CHILD, "--nocapture"]);
    command
}

#[test]
fn a_cleanup_child_cannot_act_in_the_unpublished_pid_crash_gap() {
    let inputs = Inputs::new();
    let mut fixture = inputs.fixture();
    fixture.spawn_gated(gate_command(&fixture)).unwrap();
    // Controller crash before persist closes the pipe; the child must not act.
    drop(fixture.child.as_mut().unwrap().stdin.take());
    let status = wait_child(fixture.child.as_mut().unwrap(), Duration::from_secs(5)).unwrap();
    assert!(!status.success());
    assert!(!fixture.path.exists());
    assert!(!fixture.path.with_extension("effect").exists());
}

#[test]
fn witness_and_cleanup_release_only_after_exact_child_pid_is_durable() {
    for state in ["witness-running", "owned-vm-cleanup-running"] {
        let inputs = Inputs::new();
        let mut fixture = inputs.fixture();
        fixture
            .spawn_recorded(gate_command(&fixture), state)
            .unwrap();
        let status = wait_child(fixture.child.as_mut().unwrap(), Duration::from_secs(5)).unwrap();
        assert!(status.success());
        assert!(fixture.path.with_extension("effect").exists());
        let record = fixture._lock.read(&fixture.path).unwrap();
        assert_eq!(record.state, state);
    }
}

#[test]
#[ignore = "non-credential child of the recorded-start-gate regression"]
fn gated_child() -> Result<()> {
    ensure!(
        std::env::var("MVM_CALLER_WITNESS_START_GATE")?.as_str() == "stdin-v1",
        "gate missing"
    );
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte)?;
    ensure!(byte == *b"1", "unreleased gate");
    let snapshot = Snapshot::from_process()?;
    let record: Record = serde_json::from_slice(&fs::read(snapshot.record())?)?;
    ensure!(
        record.child_pid == Some(std::process::id()),
        "child ran before its PID was published"
    );
    atomic_io::write_private(
        &snapshot.record().with_extension("effect"),
        b"acted-after-record",
    )?;
    Ok(())
}
