//! Explicit operator-only fixture around one real client witness.
//! No enrollment occurs in ordinary tests. Production service/account selection
//! and the public native enrollment/load API are used without a store override.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use mvm_core::atomic_io;
use mvm_vmm::host::process_exit::{ProcessExitObserver, ProcessExitWait};
use serde::{Deserialize, Serialize};

use super::{EnrolledIdentity, IdentityClient, IdentityError, SERVICE, account, macos};

mod environment;
mod record_lock;
mod review_tests;
use environment::Snapshot;
use record_lock::RecordLock;

pub(super) const INSTALLATION: &str = "d3676c8c-8f2e-4d2b-b70b-d23ccb8c4018";
const PIN_ENV: &str = "MVM_CALLER_WITNESS_PIN_JSON";
const PROBE: &str = "caller_identity::production_fixture::production_fixture_missing";
const RECOVER: &str = "caller_identity::production_fixture::recover_production_fixture";
const CHILD_TEST: &str = "native_cold_entrypoint_registration_and_replay";
const CHILD_CLEANUP: &str = "native_caller_registration_cleanup";
const STORE_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_TIMEOUT: Duration = Duration::from_secs(300);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    installation: String,
    service: String,
    account: String,
    state: String,
    public_pin: Option<EnrolledIdentity>,
    controller_pid: u32,
    child_pid: Option<u32>,
    witness_program: PathBuf,
    witness_environment: Vec<(String, String)>,
    cleanup_program: PathBuf,
    cleanup_arguments: Vec<String>,
    cleanup_environment: Vec<(String, String)>,
    interruption_guidance: String,
}

struct Fixture {
    path: PathBuf,
    record: Record,
    environment: Snapshot,
    child: Option<Child>,
    cleanup_attempted: bool,
    _lock: RecordLock,
}

fn enabled() -> Result<()> {
    ensure!(
        std::env::var("MVM_CALLER_FIXTURE_ENABLE").as_deref() == Ok(INSTALLATION),
        "explicit approval for the reserved native fixture is required"
    );
    Ok(())
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    let pid = i32::try_from(child.id()).context("invalid witness PID")?;
    let observer = ProcessExitObserver::arm(pid)?;
    ensure!(
        observer.wait_event(Instant::now() + timeout)? == ProcessExitWait::Exited,
        "witness child deadline expired"
    );
    child.wait().context("reap witness child")
}

fn stop_owned_child(child: &mut Child) -> Result<()> {
    if child.try_wait()?.is_none() {
        let pid = i32::try_from(child.id()).context("invalid owned child PID")?;
        let observer = ProcessExitObserver::arm(pid)?;
        child.kill().context("terminate owned witness child")?;
        ensure!(
            observer.wait_event(Instant::now() + STOP_TIMEOUT)? == ProcessExitWait::Exited,
            "owned witness child exit is unverified; credential retained"
        );
        child.wait().context("reap terminated witness child")?;
    }
    Ok(())
}

fn preflight_test_names(command: &mut Command) -> Result<()> {
    command.args(["--list", "--ignored"]).stdout(Stdio::piped());
    let mut child = command.spawn().context("list prepared witness tests")?;
    let waited = wait_child(&mut child, STOP_TIMEOUT);
    if let Err(error) = waited {
        stop_owned_child(&mut child)?;
        return Err(error);
    }
    let output = child.wait_with_output()?;
    ensure!(output.status.success(), "witness test listing failed");
    let listing = std::str::from_utf8(&output.stdout)?;
    for name in [CHILD_TEST, CHILD_CLEANUP] {
        let expected = format!("{name}: test");
        ensure!(
            listing.lines().filter(|line| *line == expected).count() == 1,
            "prepared binary lacks the exact ignored witness/cleanup test"
        );
    }
    Ok(())
}

fn release_gate(child: &mut Child) -> Result<()> {
    child
        .stdin
        .take()
        .context("recorded child start gate missing")?
        .write_all(b"1")
        .context("release durably recorded child")
}

impl Fixture {
    fn persist(&self) -> Result<()> {
        self.environment.revalidate()?;
        atomic_io::atomic_write_durable(&self.path, &serde_json::to_vec_pretty(&self.record)?)
    }

    fn stop_child(&mut self) -> Result<()> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        stop_owned_child(child)?;
        self.child = None;
        Ok(())
    }

    fn clean_owned_vms(&mut self) -> Result<()> {
        let mut command = self.environment.command(self.environment.program())?;
        command.args([
            "--ignored",
            "--exact",
            CHILD_CLEANUP,
            "--nocapture",
            "--test-threads=1",
        ]);
        self.spawn_recorded(command, "owned-vm-cleanup-running")?;
        let status = wait_child(
            self.child.as_mut().context("cleanup companion missing")?,
            CHILD_TIMEOUT,
        )?;
        ensure!(
            status.success(),
            "owned VMs are not confirmed cleaned; credential retained"
        );
        self.child = None;
        self.record.child_pid = None;
        Ok(())
    }

    /// Both launching and cleanup children remain blocked until ownership is durable.
    fn spawn_gated(&mut self, mut command: Command) -> Result<()> {
        self.environment.revalidate()?;
        command
            .env("MVM_CALLER_WITNESS_START_GATE", "stdin-v1")
            .stdin(Stdio::piped());
        self.child = Some(command.spawn().context("spawn gated owned child")?);
        Ok(())
    }

    fn spawn_recorded(&mut self, command: Command, state: &str) -> Result<()> {
        self.spawn_gated(command)?;
        self.record.child_pid = self.child.as_ref().map(Child::id);
        self.record.state = state.into();
        self.persist()?;
        release_gate(self.child.as_mut().context("gated child missing")?)
    }

    fn finish(&mut self) -> Result<()> {
        self.cleanup_attempted = true;
        self.stop_child()?;
        let pin = self.record.public_pin.clone().context(
            "enrollment outcome has no recorded public pin; do not adopt/delete an unknown item",
        )?;
        ensure!(
            pin.installation.to_string() == INSTALLATION,
            "cleanup pin is not the reserved fixture"
        );
        self.environment.validate_record(
            &self.record.witness_program,
            &self.record.witness_environment,
        )?;
        self.environment.check_native_home()?;
        self.clean_owned_vms()?;
        self.environment.check_native_home()?;
        match IdentityClient::native()?
            .load(&pin, Instant::now() + STORE_TIMEOUT)?
            .wait()
        {
            Ok(credential) => ensure!(credential.identity() == pin, "fixture pin mismatch"),
            Err(IdentityError::Missing) => {}
            Err(error) => return Err(error.into()),
        }
        let (reply, result) = mpsc::sync_channel(1);
        let delete_pin = pin.clone();
        std::thread::spawn(move || {
            let _ = reply.send(macos::delete_production_fixture(&delete_pin));
        });
        result
            .recv_timeout(STORE_TIMEOUT)
            .context("native fixture deletion deadline")??;
        let mut probe = self.environment.command(&std::env::current_exe()?)?;
        probe
            .args([
                "--ignored",
                "--exact",
                PROBE,
                "--nocapture",
                "--test-threads=1",
            ])
            .env("MVM_CALLER_FIXTURE_ENABLE", INSTALLATION)
            .env(PIN_ENV, serde_json::to_string(&pin)?);
        self.child = Some(
            probe
                .spawn()
                .context("spawn separate-process absence probe")?,
        );
        let status = wait_child(
            self.child.as_mut().context("absence probe missing")?,
            STORE_TIMEOUT,
        )?;
        ensure!(
            status.success(),
            "native absence must be Missing, never Unavailable"
        );
        self.child = None;
        self.record.state = "deleted-and-separate-process-missing-verified".into();
        self.record.child_pid = None;
        self.persist()?;
        println!(
            "PRODUCTION_FIXTURE_CLEANUP_VERIFIED service={} account={}",
            SERVICE, self.record.account
        );
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.cleanup_attempted {
            if let Err(error) = self.stop_child() {
                eprintln!(
                    "NATIVE FIXTURE CHILD CLEANUP FAILED: record={} reason={error}",
                    self.path.display()
                );
            }
            return;
        }
        if let Err(error) = self.finish() {
            eprintln!(
                "NATIVE FIXTURE CLEANUP FAILED: record={} service={} account={} reason={error}",
                self.path.display(),
                SERVICE,
                self.record.account
            );
        }
    }
}

fn require_native_lifecycle_ready() -> Result<()> {
    // The current companion cannot prove lifetime-safe HVF teardown.
    // Test-name discovery or an environment override must not release this hold.
    anyhow::bail!(
        "NativeLifecycleUnsupported: lifetime-safe HVF teardown is not available; fixture enrollment is held"
    )
}

#[test]
fn unsupported_lifecycle_refuses_before_environment_store_or_child_access() {
    assert!(
        production_fixture_brackets_cold_witness()
            .unwrap_err()
            .to_string()
            .starts_with("NativeLifecycleUnsupported:")
    );
}

#[test]
#[ignore = "held: NativeLifecycleUnsupported until lifetime-safe HVF teardown is reviewed"]
fn production_fixture_brackets_cold_witness() -> Result<()> {
    require_native_lifecycle_ready()?;
    enabled()?;
    let environment = Snapshot::from_process()?;
    let lock = RecordLock::acquire(&environment)?;
    preflight_test_names(&mut environment.command(environment.program())?)?;
    let mut child = environment.command(environment.program())?;
    child
        .args([
            "--ignored",
            "--exact",
            CHILD_TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MVM_CALLER_WITNESS_START_GATE", "stdin-v1")
        .stdin(Stdio::piped());
    let installation = INSTALLATION.parse()?;
    let account = account(installation)?;
    environment.check_native_home()?;
    match macos::read_at(SERVICE, &account) {
        Err(IdentityError::Missing) => {}
        Ok(_) => bail!("reserved fixture already exists; refuse adoption/overwrite/deletion"),
        Err(error) => return Err(error.into()),
    }
    let path = environment.record().to_path_buf();
    let parent = path.parent().context("cleanup record parent missing")?;
    let record = Record {
        installation: INSTALLATION.into(),
        service: SERVICE.into(),
        account,
        state: "absence-verified-before-enrollment".into(),
        public_pin: None,
        controller_pid: std::process::id(),
        child_pid: None,
        witness_program: environment.program().to_path_buf(),
        witness_environment: environment.values().to_vec(),
        cleanup_program: std::env::current_exe()?,
        cleanup_arguments: ["--ignored", "--exact", RECOVER, "--nocapture", "--test-threads=1"]
            .into_iter().map(String::from).collect(),
        cleanup_environment: environment.values().iter().cloned().chain([
            ("MVM_CALLER_FIXTURE_ENABLE".into(), INSTALLATION.into()),
            ("MVM_CALLER_FIXTURE_RECORD".into(), path.to_str().context("record encoding")?.to_owned()),
            ("MVM_CALLER_WITNESS_BIN".into(), environment.program().to_str().context("program encoding")?.to_owned()),
        ]).collect(),
        interruption_guidance: "Retain real HOME only for native custody, with isolated MVM_HOME/cache/TMPDIR. Stop the recorded child before cleanup. If public_pin is absent or differs, refuse automatic adoption/deletion and report the exact reserved item for operator recovery.".into(),
    };
    atomic_io::atomic_write_new(&path, &serde_json::to_vec_pretty(&record)?)?;
    atomic_io::sync_dir(parent)?;
    let mut fixture = Fixture {
        path,
        record,
        environment,
        child: None,
        cleanup_attempted: false,
        _lock: lock,
    };
    fixture.environment.check_native_home()?;
    let credential = IdentityClient::native()?
        .enroll(installation, Instant::now() + STORE_TIMEOUT)?
        .wait()?;
    let pin = credential.identity();
    drop(credential);
    fixture.record.public_pin = Some(pin.clone());
    fixture.record.state = "enrolled".into();
    fixture.persist()?;
    println!(
        "PRODUCTION_FIXTURE_PUBLIC_PIN={}",
        serde_json::to_string(&pin)?
    );
    child.env(PIN_ENV, serde_json::to_string(&pin)?);
    fixture.spawn_recorded(child, "witness-running")?;
    let result = wait_child(
        fixture.child.as_mut().context("witness missing")?,
        CHILD_TIMEOUT,
    );
    if let Err(error) = fixture.finish() {
        eprintln!(
            "NATIVE FIXTURE CLEANUP FAILED: record={} reason={error}",
            fixture.path.display()
        );
        return Err(error);
    }
    ensure!(
        result?.success(),
        "cold witness failed; exact fixture cleanup still verified"
    );
    Ok(())
}

#[test]
#[ignore = "read-only subprocess of the approved production fixture controller"]
fn production_fixture_missing() -> Result<()> {
    enabled()?;
    let environment = Snapshot::from_process()?;
    environment.check_native_home()?;
    let pin: EnrolledIdentity = serde_json::from_str(&std::env::var(PIN_ENV)?)?;
    ensure!(
        pin.installation.to_string() == INSTALLATION,
        "wrong fixture namespace"
    );
    let result = IdentityClient::native()?
        .load(&pin, Instant::now() + STORE_TIMEOUT)?
        .wait();
    ensure!(
        matches!(result, Err(IdentityError::Missing)),
        "fixture is not confirmed Missing"
    );
    Ok(())
}

#[test]
#[ignore = "explicit exact-pinned cleanup after an interrupted approved fixture"]
fn recover_production_fixture() -> Result<()> {
    enabled()?;
    let environment = Snapshot::from_process()?;
    let lock = RecordLock::acquire(&environment)?;
    let path = environment.record().to_path_buf();
    let record = lock.read(&path)?;
    environment.validate_record(&record.witness_program, &record.witness_environment)?;
    ensure!(
        record.installation == INSTALLATION
            && record.service == SERVICE
            && record.account == account(INSTALLATION.parse()?)?,
        "record does not identify reserved fixture"
    );
    ensure!(record.controller_pid > 1, "invalid recorded controller PID");
    ensure!(
        !mvm_vmm::host::process_liveness::pid_is_alive(i32::try_from(record.controller_pid)?),
        "fixture controller may still be alive; refuse concurrent recovery"
    );
    if let Some(pid) = record.child_pid {
        ensure!(pid > 1, "invalid recorded witness PID");
        if mvm_vmm::host::process_liveness::pid_is_alive(i32::try_from(pid)?) {
            bail!(
                "recorded child may still be alive; refuse credential cleanup until it is stopped"
            );
        }
    }
    let mut fixture = Fixture {
        path,
        record,
        environment,
        child: None,
        cleanup_attempted: false,
        _lock: lock,
    };
    fixture.record.controller_pid = std::process::id();
    fixture.record.state = "recovery-running".into();
    fixture.persist()?;
    let result = fixture.finish();
    if let Err(error) = &result {
        eprintln!(
            "NATIVE FIXTURE CLEANUP FAILED: record={} reason={error}",
            fixture.path.display()
        );
    }
    result
}

#[test]
fn production_cleanup_refuses_any_other_installation_without_store_access() {
    let identity = EnrolledIdentity {
        installation: uuid::Uuid::new_v4(),
        public_key: [0; 32],
    };
    assert_eq!(
        macos::delete_production_fixture(&identity),
        Err(IdentityError::Conflict)
    );
}

#[test]
fn fixture_timeout_reaps_owned_child_before_refusing_unpinned_cleanup() {
    let inputs = review_tests::Inputs::new();
    let child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let mut fixture = inputs.fixture();
    fixture.child = Some(child);
    assert!(wait_child(fixture.child.as_mut().unwrap(), Duration::ZERO).is_err());
    let error = fixture.finish().unwrap_err();
    assert!(error.to_string().contains("no recorded public pin"));
    assert!(fixture.child.is_none());
    assert!(!mvm_vmm::host::process_liveness::pid_is_alive(pid));
}
