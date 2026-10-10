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

pub(super) const INSTALLATION: &str = "d3676c8c-8f2e-4d2b-b70b-d23ccb8c4018";
const PIN_ENV: &str = "MVM_CALLER_WITNESS_PIN_JSON";
const PROBE: &str = "caller_identity::production_fixture::production_fixture_missing";
const RECOVER: &str = "caller_identity::production_fixture::recover_production_fixture";
const CHILD_TEST: &str = "native_cold_entrypoint_registration_and_replay";
const CHILD_CLEANUP: &str = "native_caller_registration_cleanup";
const STORE_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_TIMEOUT: Duration = Duration::from_secs(300);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const SAFE_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "TMPDIR",
    "MVM_HOME",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "RUSTUP_HOME",
    "MVM_CALLER_WITNESS_ROOT",
    "MVM_CALLER_WITNESS_SOURCE",
    "MVM_CALLER_WITNESS_KERNEL",
    "MVM_HVF_SUPERVISOR_PATH",
    "MVM_RESIDENCY",
    "MVM_HOST_AGENT_PATH",
    "MVM_SIGNER_HELPER_PATH",
    "MVM_SUBSTITUTION_ENDPOINT_PATH",
    "MVM_KERNEL_SOURCE",
    "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE",
    "MVM_NO_LEGACY_BANNER",
];

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
    child: Option<Child>,
    cleanup_attempted: bool,
}

fn enabled() -> Result<()> {
    ensure!(
        std::env::var("MVM_CALLER_FIXTURE_ENABLE").as_deref() == Ok(INSTALLATION),
        "explicit approval for the reserved native fixture is required"
    );
    Ok(())
}

fn safe_command(program: impl AsRef<std::ffi::OsStr>) -> Result<Command> {
    let mut command = Command::new(program);
    command.env_clear().stdin(Stdio::null());
    for name in SAFE_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for name in [
        "HOME",
        "TMPDIR",
        "MVM_HOME",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
    ] {
        ensure!(
            std::env::var_os(name).is_some(),
            "isolated runtime paths must be explicit"
        );
    }
    let mvm_home = std::env::var_os("MVM_HOME").context("MVM_HOME missing")?;
    let user_mvm = PathBuf::from(std::env::var_os("HOME").context("HOME missing")?).join(".mvm");
    ensure!(
        std::path::Path::new(&mvm_home) != user_mvm.as_path(),
        "fixture refuses the user's ordinary MVM_HOME"
    );
    Ok(command)
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

impl Fixture {
    fn persist(&self) -> Result<()> {
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
        let mut command = Command::new(&self.record.witness_program);
        command.env_clear();
        for (name, value) in &self.record.witness_environment {
            ensure!(
                SAFE_ENV.contains(&name.as_str()),
                "cleanup record contains an unapproved environment name"
            );
            command.env(name, value);
        }
        command.args([
            "--ignored",
            "--exact",
            CHILD_CLEANUP,
            "--nocapture",
            "--test-threads=1",
        ]);
        self.child = Some(
            command
                .spawn()
                .context("spawn exact owned-VM cleanup companion")?,
        );
        self.record.child_pid = self.child.as_ref().map(Child::id);
        self.record.state = "owned-vm-cleanup-running".into();
        self.persist()?;
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
        let original_home = self
            .record
            .witness_environment
            .iter()
            .find_map(|(name, value)| (name == "HOME").then_some(value));
        ensure!(
            original_home.is_some() && std::env::var("HOME").ok().as_ref() == original_home,
            "native cleanup requires the recorded real HOME; refuse another custody context"
        );
        self.clean_owned_vms()?;
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
        let mut probe = safe_command(std::env::current_exe()?)?;
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

#[test]
#[ignore = "requires explicit approval and a fully prepared real cold witness binary"]
fn production_fixture_brackets_cold_witness() -> Result<()> {
    enabled()?;
    for name in [
        "MVM_SKIP_HASH_VERIFY",
        "MVM_SKIP_COSIGN_VERIFY",
        "MVM_HVF_BOOTARGS",
        "MVM_IMAGES_DIR",
        "MVM_ALLOW_LOCAL_BUILDER_BUILD",
    ] {
        ensure!(
            std::env::var_os(name).is_none(),
            "verification bypass environment is forbidden"
        );
    }
    for name in [
        "MVM_CALLER_WITNESS_ROOT",
        "MVM_CALLER_WITNESS_SOURCE",
        "MVM_CALLER_WITNESS_KERNEL",
        "MVM_HVF_SUPERVISOR_PATH",
    ] {
        let path = PathBuf::from(std::env::var_os(name).context("prepared witness path missing")?);
        ensure!(
            path.is_absolute() && path.exists(),
            "witness artifacts must already be prepared"
        );
    }
    ensure!(
        std::env::var("MVM_RESIDENCY").as_deref() == Ok("cold"),
        "fixture requires explicit cold residency"
    );
    for name in ["MVM_KERNEL_SOURCE", "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE"] {
        ensure!(
            std::env::var(name).as_deref() == Ok("download"),
            "fixture must not enable source builds"
        );
    }
    let binary = PathBuf::from(
        std::env::var_os("MVM_CALLER_WITNESS_BIN").context("ready witness binary missing")?,
    );
    ensure!(
        binary.is_absolute() && binary.is_file(),
        "witness binary must already exist"
    );
    preflight_test_names(&mut safe_command(&binary)?)?;
    let mut child = safe_command(&binary)?;
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
    match macos::read_at(SERVICE, &account) {
        Err(IdentityError::Missing) => {}
        Ok(_) => bail!("reserved fixture already exists; refuse adoption/overwrite/deletion"),
        Err(error) => return Err(error.into()),
    }
    let path = PathBuf::from(
        std::env::var_os("MVM_CALLER_FIXTURE_RECORD")
            .context("durable cleanup record path missing")?,
    );
    ensure!(path.is_absolute(), "cleanup record path must be absolute");
    let parent = path.parent().context("cleanup record parent missing")?;
    mvm_core::config::create_private_dir(parent)?;
    let record = Record {
        installation: INSTALLATION.into(),
        service: SERVICE.into(),
        account,
        state: "absence-verified-before-enrollment".into(),
        public_pin: None,
        controller_pid: std::process::id(),
        child_pid: None,
        witness_program: binary,
        witness_environment: SAFE_ENV.iter().filter_map(|name| {
            std::env::var(name).ok().map(|value| ((*name).to_string(), value))
        }).collect(),
        cleanup_program: std::env::current_exe()?,
        cleanup_arguments: ["--ignored", "--exact", RECOVER, "--nocapture", "--test-threads=1"]
            .into_iter().map(String::from).collect(),
        cleanup_environment: SAFE_ENV.iter().filter_map(|name| {
            std::env::var(name).ok().map(|value| ((*name).to_string(), value))
        }).chain([
            ("MVM_CALLER_FIXTURE_ENABLE".into(), INSTALLATION.into()),
            ("MVM_CALLER_FIXTURE_RECORD".into(), path.to_string_lossy().into_owned()),
        ]).collect(),
        interruption_guidance: "Retain real HOME only for native custody, with isolated MVM_HOME/cache/TMPDIR. Stop the recorded child before cleanup. If public_pin is absent or differs, refuse automatic adoption/deletion and report the exact reserved item for operator recovery.".into(),
    };
    atomic_io::atomic_write_new(&path, &serde_json::to_vec_pretty(&record)?)?;
    atomic_io::sync_dir(parent)?;
    let mut fixture = Fixture {
        path,
        record,
        child: None,
        cleanup_attempted: false,
    };
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
    fixture.child = Some(child.spawn().context("spawn prepared cold witness")?);
    fixture.record.child_pid = fixture.child.as_ref().map(Child::id);
    fixture.record.state = "witness-running".into();
    fixture.persist()?;
    fixture
        .child
        .as_mut()
        .and_then(|child| child.stdin.take())
        .context("witness start gate missing")?
        .write_all(b"1")?;
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
    let path = PathBuf::from(
        std::env::var_os("MVM_CALLER_FIXTURE_RECORD").context("cleanup record missing")?,
    );
    let record: Record = serde_json::from_slice(&std::fs::read(&path)?)?;
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
        child: None,
        cleanup_attempted: false,
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
    let child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    let pid = i32::try_from(child.id()).unwrap();
    let mut fixture = Fixture {
        path: PathBuf::from("no-record-written-in-this-test"),
        record: Record {
            installation: INSTALLATION.into(),
            service: SERVICE.into(),
            account: account(INSTALLATION.parse().unwrap()).unwrap(),
            state: "test-only-no-enrollment".into(),
            public_pin: None,
            controller_pid: std::process::id(),
            child_pid: Some(child.id()),
            witness_program: PathBuf::new(),
            witness_environment: Vec::new(),
            cleanup_program: PathBuf::new(),
            cleanup_arguments: Vec::new(),
            cleanup_environment: Vec::new(),
            interruption_guidance: String::new(),
        },
        child: Some(child),
        cleanup_attempted: false,
    };
    assert!(wait_child(fixture.child.as_mut().unwrap(), Duration::ZERO).is_err());
    let error = fixture.finish().unwrap_err();
    assert!(error.to_string().contains("no recorded public pin"));
    assert!(fixture.child.is_none());
    assert!(!mvm_vmm::host::process_liveness::pid_is_alive(pid));
}
