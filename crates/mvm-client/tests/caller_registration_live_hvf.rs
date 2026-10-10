//! Explicit native cold-registration witness, not producer-ingress readiness.
//!
//! Requires an operator-prepared isolated artifact/slot fixture, freshly built
//! entitled helpers, and a public pin provisioned by the native-custody owner.
//! This test only loads that existing key. Missing inputs fail, never skip.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use mvm_client::entrypoint::{
    AGENT_WAIT_SECS, EntrypointAdmission, EntrypointVm, SessionVmName, WorkloadSource,
    boot_entrypoint_vm, resolve_slot,
};
use mvm_client::{LocalBackend, MvmClient};
use mvm_core::client::dto::MachineId;
use mvm_core::config;
use mvm_core::crypto::entrypoint_identity::EnrolledIdentity;
use mvm_core::stream_client::protected::ProtectedRun;
use mvm_vmm::host::hvf_supervisor::{HvfSupervisorConfig, ProtectedSupervisorStatus};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const REPLAY_LIMIT: Duration = Duration::from_secs(30);

fn path_env(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name).with_context(|| format!("{name} required"))?);
    ensure!(path.is_absolute(), "{name} must be absolute");
    Ok(path)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 1024 * 1024,
        "invalid witness metadata"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "witness metadata exceeds its bound"
    );
    serde_json::from_slice(&bytes).context("decode witness metadata")
}

fn owned_root() -> Result<PathBuf> {
    let root = path_env("MVM_CALLER_WITNESS_ROOT")?.canonicalize()?;
    ensure!(
        root.starts_with("/private/tmp") || root.starts_with("/tmp"),
        "unique isolated /tmp witness root required"
    );
    ensure!(
        fs::read(root.join("caller-witness-owned"))? == b"native-cold-registration-v1\n",
        "owned witness root marker missing"
    );
    ensure!(
        path_env("MVM_HOME")?.canonicalize()? == root.join("mvm"),
        "MVM_HOME must be the owned isolated state"
    );
    ensure!(
        path_env("TMPDIR")?.canonicalize()? == root.join("tmp"),
        "TMPDIR must be the owned isolated temporary directory"
    );
    Ok(root)
}

fn declare_helpers() -> Result<()> {
    let supervisor = path_env("MVM_HVF_SUPERVISOR_PATH")?;
    let directory = supervisor
        .parent()
        .context("supervisor has no binary directory")?
        .canonicalize()?;
    mvm_vmm::host::aux_bin::declare_library_embedder();
    mvm_vmm::host::aux_bin::declare_host_binary_dir(directory)?;
    Ok(())
}

fn await_controller_record() -> Result<()> {
    ensure!(
        std::env::var("MVM_CALLER_WITNESS_START_GATE")?.as_str() == "stdin-v1",
        "custody controller start gate required"
    );
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte)?;
    ensure!(
        byte == *b"1",
        "custody controller did not release the recorded child"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    prefix: String,
    names: [String; 2],
}

impl Ownership {
    fn new() -> Self {
        let nonce: u128 = rand::random();
        let prefix = format!("cr-{:x}-{nonce:032x}", std::process::id());
        let names = [format!("{prefix}-base"), format!("{prefix}-key")];
        Self { prefix, names }
    }

    fn validate(&self) -> Result<()> {
        let (pid, nonce) = self
            .prefix
            .strip_prefix("cr-")
            .and_then(|suffix| suffix.split_once('-'))
            .context("invalid owned-name prefix")?;
        ensure!(
            u32::from_str_radix(pid, 16)? != 0
                && nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid owned-name prefix"
        );
        ensure!(
            self.names
                == [
                    format!("{}-base", self.prefix),
                    format!("{}-key", self.prefix)
                ],
            "cleanup names do not match the recorded unique scope"
        );
        for name in &self.names {
            mvm_core::naming::validate_vm_name(name)?;
        }
        Ok(())
    }
}

struct Inputs {
    root: PathBuf,
    source: String,
    kernel: PathBuf,
    supervisor: PathBuf,
    pin_json: String,
}

impl Inputs {
    fn read() -> Result<Self> {
        ensure!(
            cfg!(feature = "native-caller-identity"),
            "native-caller-identity feature required"
        );
        let root = owned_root()?;
        ensure!(
            std::env::var("MVM_RESIDENCY")?.as_str() == "cold",
            "cold residency required"
        );
        ensure!(
            std::env::var("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE")?.as_str() == "download",
            "native witness may consume prepared caches but must not build guest runtime"
        );
        for forbidden in [
            "MVM_SKIP_HASH_VERIFY",
            "MVM_SKIP_COSIGN_VERIFY",
            "MVM_HVF_BOOTARGS",
            "MVM_IMAGES_DIR",
            "MVM_ALLOW_LOCAL_BUILDER_BUILD",
        ] {
            ensure!(
                std::env::var_os(forbidden).is_none(),
                "verification/boot override is forbidden"
            );
        }
        let source = std::env::var("MVM_CALLER_WITNESS_SOURCE")
            .context("installed workload source required")?;
        ensure!(!source.is_empty(), "installed workload source required");
        let kernel = path_env("MVM_CALLER_WITNESS_KERNEL")?.canonicalize()?;
        ensure!(
            kernel.is_file() && kernel.starts_with(root.join("mvm")),
            "kernel must be isolated"
        );
        let supervisor = path_env("MVM_HVF_SUPERVISOR_PATH")?;
        ensure!(
            supervisor.is_file(),
            "current supervisor executable required"
        );
        let pin_json = std::env::var("MVM_CALLER_WITNESS_PIN_JSON")
            .context("custody controller's public enrollment pin required")?;
        ensure!(
            pin_json.len() <= 4096,
            "public enrollment pin exceeds its bound"
        );
        Ok(Self {
            root,
            source,
            kernel,
            supervisor,
            pin_json,
        })
    }
}

/// Armed before resolution so partial launches use the same public cleanup.
struct OwnedVm {
    client: LocalBackend,
    name: String,
    cleaned: bool,
}

impl OwnedVm {
    fn new(name: String) -> Self {
        Self {
            client: LocalBackend::with_hypervisor("hvf"),
            name,
            cleaned: false,
        }
    }

    fn stop(&mut self) -> Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.client.stop_machine(&MachineId(self.name.clone())))?;
        self.client.cleanup_transient(&self.name)?;
        ensure!(
            !config::vm_state_dir(&self.name).exists(),
            "public teardown retained runtime state"
        );
        ensure!(
            !config::vm_stream_socket(&self.name).exists(),
            "public teardown retained stream socket"
        );
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for OwnedVm {
    fn drop(&mut self) {
        if !self.cleaned && self.client.cleanup_transient(&self.name).is_err() {
            eprintln!("owned caller witness cleanup failed for {}", self.name);
        }
    }
}

struct BootEvidence {
    config: HvfSupervisorConfig,
    run: String,
    timing: serde_json::Value,
}

fn boot(inputs: &Inputs, vm: &OwnedVm, opted_in: bool) -> Result<BootEvidence> {
    // This clock precedes public-pin and workload resolution, native lookup,
    // actual admission, startup verification, replay fsync, and guest readiness.
    let started = Instant::now();
    let pin: Option<EnrolledIdentity> = opted_in
        .then(|| serde_json::from_str(&inputs.pin_json))
        .transpose()?;
    let slot = resolve_slot(WorkloadSource::Manifest(&inputs.source))?;
    let resolved = Instant::now();
    let policy = EntrypointAdmission::builder("hvf");
    let policy = match pin.as_ref() {
        Some(pin) => policy.producer_identity(pin.clone()),
        None => policy,
    }
    .build()?;
    let booted = boot_entrypoint_vm(
        EntrypointVm {
            slot: &slot,
            vm_name: SessionVmName::Exact(&vm.name),
            cpus: 1,
            memory_mib: 256,
            admission: policy,
        },
        None,
    )?;
    let boot_returned = Instant::now();
    booted.await_agent(AGENT_WAIT_SECS)?;
    let guest_ready = Instant::now();

    let state = config::vm_state_dir(&vm.name);
    let cfg: HvfSupervisorConfig = read_json(&state.join("supervisor.json"))?;
    ensure!(cfg.vm_name == vm.name, "supervisor instance mismatch");
    ensure!(
        cfg.kernel.canonicalize()? == inputs.kernel,
        "unexpected workload kernel"
    );
    ensure!(
        cfg.handoff_socket.is_none() && cfg.restore_ram.is_none() && cfg.restore_fds.is_none(),
        "cold witness unexpectedly used handoff/restore"
    );
    let status: ProtectedSupervisorStatus = read_json(&state.join("supervisor-status.json"))?;
    ensure!(
        matches!(status, ProtectedSupervisorStatus::Running),
        "supervisor owner is not running"
    );
    let run = ProtectedRun::read(&config::vm_protected_stream_dir(&vm.name))?
        .context("actual owner did not publish its protected run")?;
    ensure!(
        cfg.plan.as_ref() == Some(&serde_json::to_value(booted.admission.admitted.signed())?),
        "supervisor did not consume the actually admitted plan"
    );
    match (pin.as_ref(), cfg.caller_registration.as_ref()) {
        (Some(pin), Some(registration)) => {
            ensure!(
                &registration.expected.identity == pin,
                "registered native caller pin mismatch"
            );
            mvm_hostd::supervisor::caller_registration::verify_cold_start(
                &vm.name,
                booted.admission.admitted.signed(),
                registration,
            )?;
            ensure!(
                run.run == registration.expected.binding.run.as_u128().to_string(),
                "actual owner did not install the admitted caller-bound run"
            );
            ensure!(
                state.join("caller-registration.used").is_file(),
                "startup was not consumed"
            );
        }
        (None, None) => ensure!(
            !state.join("caller-registration.used").exists(),
            "optout installed a caller"
        ),
        (Some(_), None) | (None, Some(_)) => anyhow::bail!("caller opt-in changed across startup"),
    }
    let timing = serde_json::json!({
        "schema": 1,
        "mode": if opted_in { "cold-optin" } else { "cold-optout" },
        "resolution_ms": resolved.duration_since(started).as_secs_f64() * 1000.0,
        "admission_and_boot_ms": boot_returned.duration_since(resolved).as_secs_f64() * 1000.0,
        "guest_wait_ms": guest_ready.duration_since(boot_returned).as_secs_f64() * 1000.0,
        "resolution_to_guest_ready_ms": guest_ready.duration_since(started).as_secs_f64() * 1000.0,
        "owner_registration_verified": opted_in,
        "producer_ready": false,
        "producer_ready_status": "unimplemented",
        "full_producer_and_guest_ready_ms": null
    });
    Ok(BootEvidence {
        config: cfg,
        run: run.run,
        timing,
    })
}

fn replay_process(supervisor: &Path, cfg: &HvfSupervisorConfig) -> Result<ExitStatus> {
    use tokio::io::AsyncWriteExt as _;
    let bytes = serde_json::to_vec(cfg)?;
    let command = mvm_core::env_hygiene::helper_command(supervisor);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut command = tokio::process::Command::from(command);
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let result = tokio::time::timeout(REPLAY_LIMIT, async {
                let mut stdin = child.stdin.take().context("owned replay stdin missing")?;
                stdin.write_all(&bytes).await?;
                drop(stdin);
                child.wait().await.context("wait for owned replay process")
            })
            .await;
            match result {
                Ok(result) => result,
                Err(_) => {
                    child.kill().await?;
                    anyhow::bail!("owned replay process did not refuse before its deadline")
                }
            }
        })
}

#[test]
#[ignore = "explicit real macOS custody + admitted HVF cold witness; missing inputs FAIL"]
fn native_cold_entrypoint_registration_and_replay() -> Result<()> {
    // Test-only ownership control, not an admission or caller authority.
    await_controller_record()?;
    declare_helpers()?;
    let inputs = Inputs::read()?;
    let owned = Ownership::new();
    owned.validate()?;
    ensure!(
        matches!(
            mvm_core::atomic_io::write_private_new(
                &inputs.root.join("owned-vms.json"),
                &serde_json::to_vec(&owned)?,
            )?,
            mvm_core::atomic_io::NewFile::Created
        ),
        "witness roots are single-use; refusing to overwrite cleanup ownership"
    );
    let mut baseline = OwnedVm::new(owned.names[0].clone());
    let baseline_evidence = boot(&inputs, &baseline, false)?;
    baseline.stop()?;

    let mut registered = OwnedVm::new(owned.names[1].clone());
    let first = boot(&inputs, &registered, true)?;
    let ledger_path = config::mvm_home_strict()?.join("caller-registration/ledger.json");
    let ledger = fs::read(&ledger_path)?;
    registered.stop()?;
    ensure!(
        fs::read(&ledger_path)? == ledger,
        "public teardown changed replay bookkeeping"
    );
    let registration = first
        .config
        .caller_registration
        .as_ref()
        .context("registration missing")?;
    let signed = serde_json::from_value(first.config.plan.clone().context("signed plan missing")?)?;
    // Establish that replay still has valid crypto, context, time, and inputs.
    // Its refusal must not be mistaken for a bad fixture or expired proof.
    mvm_hostd::supervisor::caller_registration::verify_cold_start(
        &registered.name,
        &signed,
        registration,
    )?;
    mvm_hostd::supervisor::caller_registration::load_boot_inputs(&first.config)?;
    registered.cleaned = false;
    let status = replay_process(&inputs.supervisor, &first.config)?;
    ensure!(
        !status.success(),
        "spent native registration replay was accepted"
    );
    let state = config::vm_state_dir(&registered.name);
    for forbidden in [
        "hvf.pid",
        "supervisor-status.json",
        "caller-registration.used",
    ] {
        ensure!(
            !state.join(forbidden).exists(),
            "replay reached a startup effect"
        );
    }
    ensure!(
        !config::vm_stream_socket(&registered.name).exists(),
        "replay published a producer socket"
    );
    ensure!(
        fs::read(&ledger_path)? == ledger,
        "replay mutated consumed bookkeeping"
    );
    registered.client.cleanup_transient(&registered.name)?;

    registered.cleaned = false;
    let fresh = boot(&inputs, &registered, true)?;
    ensure!(
        fresh.run != first.run,
        "fresh admission reused the old capture run"
    );
    ensure!(
        fresh
            .config
            .caller_registration
            .as_ref()
            .context("fresh registration missing")?
            .expected
            .binding
            .instance
            != registration.expected.binding.instance,
        "fresh admission reused the old concrete instance"
    );
    registered.stop()?;
    let report = serde_json::json!({
        "native_cold_registration": "passed",
        "native_vm_boot": true,
        "replay_refused_before_startup_effects": true,
        "public_stop_and_fresh_admission": true,
        "producer_ingress": "unimplemented",
        "full_readiness_target_claim": false,
        "artifact_preparation_and_enrollment_outside_launch_clock": true,
        "sample_order": ["cold-optout", "cold-optin", "fresh-cold-optin-after-replay"],
        "samples": [baseline_evidence.timing, first.timing, fresh.timing]
    });
    mvm_core::atomic_io::write_private(
        &inputs.root.join("native-caller-evidence.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    eprintln!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[test]
#[ignore = "explicit companion cleanup for the native cold witness's exact recorded VM names"]
fn native_caller_registration_cleanup() -> Result<()> {
    declare_helpers()?;
    let root = owned_root()?;
    let path = root.join("owned-vms.json");
    if !path.exists() {
        // The launch test durably records ownership before any boot call.
        return Ok(());
    }
    let owned: Ownership = read_json(&path)?;
    owned.validate()?;
    let client = LocalBackend::with_hypervisor("hvf");
    for name in &owned.names {
        client.cleanup_transient(name)?;
        ensure!(
            !config::vm_state_dir(name).exists(),
            "owned runtime state remains"
        );
        ensure!(
            !config::vm_stream_socket(name).exists(),
            "owned stream socket remains"
        );
    }
    mvm_core::atomic_io::write_private(
        &root.join("guest-cleanup-confirmed"),
        b"owned-vms-stopped-v1\n",
    )?;
    Ok(())
}

#[test]
fn cleanup_ownership_accepts_only_its_exact_generated_names() -> Result<()> {
    let mut owned = Ownership::new();
    owned.validate()?;
    owned.names[1] = "unrelated-vm".into();
    ensure!(owned.validate().is_err(), "unrelated cleanup name accepted");
    Ok(())
}
