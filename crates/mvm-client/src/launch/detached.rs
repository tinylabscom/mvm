//! A detached machine: a persisted definition, booted and left running.
//!
//! This is the front half of `mvmctl machine run -d`, which the CLI and the
//! host library share. A run reconciles the desired definition against the
//! one on disk (reuse, create, or recreate when `force` allows it), records
//! the machine's secret references, boots it through
//! [`start_machine_spec`](super::machine_start::start_machine_spec) — the same
//! admitted start `machine start` uses — and optionally sets a TTL and starts
//! a command in the running guest.
//!
//! Presentation stays with the caller. The CLI prints its banners, receipts
//! and envelopes around these calls and runs a command in the foreground on
//! the terminal; a library caller gets the process token back instead.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use mvm_runtime::machine::persist::{self as mp, MachineSpec, SpecReconcile};

use super::machine_start::{MachineStart, MachineStartParams, StartHost};
use crate::secret::MachineSecretRef;

/// How long a boot command waits for the guest agent to answer before giving
/// up. Matches what `machine run -d -- <argv>` has always waited.
const AGENT_READY_SECS: u64 = 30;

/// Failure to establish detached launch readiness.
#[derive(Debug, thiserror::Error)]
pub enum DetachedReadinessError {
    /// The partial launch was terminated and its registry entry removed.
    #[error(
        "guest control for machine {name:?} did not become ready within {timeout_secs}s; \
         the partial start was rolled back"
    )]
    RolledBack {
        /// Machine name.
        name: String,
        /// Readiness timeout.
        timeout_secs: u64,
    },
    /// The VMM may still own launch resources, so ownership must be retained.
    #[error(
        "guest control for machine {name:?} did not become ready within {timeout_secs}s; \
         aborting the partial start also failed: {source:#}"
    )]
    AbortUnresolved {
        /// Machine name.
        name: String,
        /// Readiness timeout.
        timeout_secs: u64,
        /// Backend abort failure.
        #[source]
        source: anyhow::Error,
    },
}

impl DetachedReadinessError {
    /// Whether the VMM may still own resources from this launch.
    pub fn abort_is_unresolved(&self) -> bool {
        matches!(self, Self::AbortUnresolved { .. })
    }
}

/// A detached persistent launch is accepted only after the authenticated guest
/// control plane completes a Ping/Pong. On failure the backend that performed
/// the start owns rollback, including its VMM and host helpers.
pub fn require_serving_guest(
    name: &str,
    started: &crate::StartedVm,
    timeout: std::time::Duration,
) -> std::result::Result<(), DetachedReadinessError> {
    // The in-memory backend has no guest transport. It is a lifecycle test
    // double, not a production detached lane.
    let ready = started.backend().kind() == mvm_core::vm_backend::BackendKind::Mock
        || crate::readiness::wait_for_guest_agent_for(name, timeout);
    require_serving_guest_result(name, timeout, ready, || {
        started.backend().abort_start(started.vm_id()).map(|_| ())
    })
}

fn require_serving_guest_result(
    name: &str,
    timeout: std::time::Duration,
    ready: bool,
    rollback: impl FnOnce() -> Result<()>,
) -> std::result::Result<(), DetachedReadinessError> {
    if ready {
        return Ok(());
    }
    if let Err(source) = rollback() {
        return Err(DetachedReadinessError::AbortUnresolved {
            name: name.to_string(),
            timeout_secs: timeout.as_secs(),
            source,
        });
    }
    crate::local::deregister_from_name_registry(name);
    Err(DetachedReadinessError::RolledBack {
        name: name.to_string(),
        timeout_secs: timeout.as_secs(),
    })
}

/// Whether `name` is running on the backend this host selects.
pub fn machine_is_running(name: &str) -> bool {
    crate::backend_is_running(
        &super::machine_start::resolve_effective_hypervisor("firecracker"),
        name,
    )
}

/// Stop `name` ahead of recreating its definition, then release the volume
/// leases it held. Best-effort: the recreate proceeds either way, and the boot
/// surfaces anything left behind.
pub fn stop_running_machine(name: &str) {
    let result = (|| {
        let lifecycle = mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(name)?;
        stop_running_machine_in_lifecycle(name, &lifecycle)
    })();
    if let Err(err) = result {
        tracing::warn!(error = %err, machine = name, "stopping machine before recreate failed");
    }
}

/// Stop before recreation without releasing the caller's lifecycle transition.
pub fn stop_running_machine_in_lifecycle(
    name: &str,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> Result<()> {
    crate::local::LocalBackend::new()
        .stop_machine_in_lifecycle(
            &mvm_core::client::dto::MachineId(name.to_owned()),
            lifecycle,
            None,
        )
        .map_err(Into::into)
}

/// Decide what a run does with `name`'s definition.
///
/// `desired` is the definition the caller asked for, or `None` when it named
/// no source and means "boot the machine as it was defined"; `existing` is
/// the one on disk, if any (see [`existing_spec`]). A definition that matches
/// is reused; a different one is refused unless `force`, which recreates it.
pub fn resolve_spec(
    name: &str,
    desired: Option<MachineSpec>,
    existing: Option<MachineSpec>,
    force: bool,
) -> Result<(MachineSpec, SpecReconcile)> {
    let Some(desired) = desired else {
        return match existing {
            Some(spec) => Ok((spec, SpecReconcile::Reuse)),
            None => bail!(
                "machine {name:?} does not exist; name an image, a manifest or a deployment to \
                 create it"
            ),
        };
    };
    let action = mp::reconcile_machine_spec(existing.as_ref(), &desired, force)?;
    let spec = match action {
        SpecReconcile::Reuse => existing.ok_or_else(|| {
            anyhow::anyhow!("machine {name:?} was marked for reuse but has no existing spec")
        })?,
        SpecReconcile::Create | SpecReconcile::Recreate { .. } => desired,
    };
    Ok((spec, action))
}

/// `name`'s definition on disk, if it has one.
pub fn existing_spec(name: &str) -> Option<MachineSpec> {
    mp::load_machine_spec(name).ok()
}

/// A definition to persist and boot.
pub struct DetachedBoot<'a> {
    pub name: &'a str,
    pub spec: &'a MachineSpec,
    pub action: SpecReconcile,
    /// The secret references to record beside the definition. `None` leaves
    /// an existing record untouched; an empty set clears it.
    pub secret_refs: Option<&'a [MachineSecretRef]>,
}

/// Persist `run.spec` as `run.action` says, record its secret references, and
/// boot it with `boot` unless it is already running. Returns whether this call
/// booted it.
///
/// `boot` runs under `lifecycle` and must use the guarded start entry point
/// rather than reacquiring the same lock.
pub fn persist_and_boot(
    run: DetachedBoot<'_>,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
    boot: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    let DetachedBoot {
        name,
        spec,
        action,
        secret_refs,
    } = run;
    lifecycle.require_name(name)?;
    match action {
        SpecReconcile::Reuse => {}
        SpecReconcile::Create => mp::save_machine_spec(spec, false)?,
        SpecReconcile::Recreate { changed } => {
            tracing::info!(machine = name, %changed, "recreating a machine whose config changed");
            stop_running_machine_in_lifecycle(name, lifecycle)?;
            mp::overwrite_machine_spec(spec)?;
        }
    }
    if machine_is_running(name) && secret_refs.is_some() {
        bail!("machine {name:?} is already running; stop it before changing its secret bindings");
    }
    if let Some(references) = secret_refs {
        let service =
            crate::secret::SecretService::local().context("opening the local secret service")?;
        if references.is_empty() {
            service
                .clear_machine_references(name)
                .context("clearing persistent-machine secret references")?;
        } else {
            service
                .record_machine_references(name, references)
                .context("recording persistent-machine secret references")?;
        }
    }
    if machine_is_running(name) {
        return Ok(false);
    }
    boot()?;
    Ok(true)
}

/// Boot a persisted definition through the admitted start, then stamp it
/// started and record the start in the audit chain.
pub fn boot_recorded(
    spec: &mut MachineSpec,
    host: &dyn StartHost,
    params: MachineStartParams<'_>,
) -> Result<MachineStart> {
    let lifecycle = mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire(&spec.name)?;
    boot_recorded_in_lifecycle(spec, host, params, &lifecycle)
}

/// Boot and record metadata without releasing the caller's transition guard.
pub fn boot_recorded_in_lifecycle(
    spec: &mut MachineSpec,
    host: &dyn StartHost,
    params: MachineStartParams<'_>,
    lifecycle: &mvm_runtime::vm::instance_snapshot::MachineLifecycleLock,
) -> Result<MachineStart> {
    let started =
        super::machine_start::start_machine_spec_in_lifecycle(spec, host, params, lifecycle)?;
    super::machine_start::record_machine_started(spec, started.resolved_digest.clone());
    if let Err(err) = mp::overwrite_machine_spec(spec) {
        tracing::warn!(error = %err, machine = %spec.name, "updating machine start metadata failed (non-fatal)");
    }
    mvm_core::audit_emit!(VmStart, vm: &spec.name, "source=machine.run.detached");
    Ok(started)
}

/// Expire `name` `ttl` from now; the TTL reaper stops it then. A machine
/// with no registry entry is `NotFound`.
pub fn apply_ttl(name: &str, ttl: std::time::Duration) -> crate::Result<()> {
    let expires_at = mvm_core::util::time::utc_plus_duration(ttl);
    crate::local::set_machine_expiry(name, Some(expires_at))
}

/// A command to run in a machine once it is up, in place of the image's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootCommand {
    /// The program and its arguments. Must not be empty.
    pub argv: Vec<String>,
    /// Environment for the command, filtered by the host's environment
    /// denylist before it leaves this process. May repeat, but not replace,
    /// runtime-provisioned egress values.
    pub env: BTreeMap<String, String>,
    /// Working directory, or the agent's default.
    pub cwd: Option<String>,
}

/// Start `command` in `name`'s guest and return the process token that names
/// it; the command keeps running after this returns.
///
/// This is the guest agent's process start, a DevOnly verb: a machine booted
/// for a command is admitted without the attenuated ProdSafe grant
/// (`has_ad_hoc_argv`), and a sealed image still refuses it in the guest. A
/// loader, shell or credential variable in `env` is refused, as it is for any
/// guest process.
pub fn start_boot_command(name: &str, command: BootCommand) -> Result<String> {
    if command.argv.is_empty() {
        bail!("a boot command needs a program to run");
    }
    mvm_core::naming::validate_vm_name(name).context("invalid boot-command machine name")?;
    if !crate::readiness::wait_for_guest_agent(name, AGENT_READY_SECS) {
        bail!(
            "the guest agent in machine {name:?} did not answer within {AGENT_READY_SECS}s, so \
             its command could not start"
        );
    }
    crate::guest::start_process(name, boot_command_process(name, command)?)
        .with_context(|| format!("starting the boot command in machine {name:?}"))
}

fn boot_command_process(name: &str, command: BootCommand) -> Result<crate::guest::ProcStart> {
    // These values exist after boot. A caller may repeat a provisioned value,
    // but cannot replace the runtime's routing, trust paths or placeholders.
    let mut env: BTreeMap<_, _> = mvm_hostd::workload_env::workload_egress_env(name)
        .into_iter()
        .collect();
    for (key, value) in command.env {
        match env.get(&key) {
            Some(bound) if bound == &value => {}
            Some(_) => bail!("cannot override host-provisioned egress variable {key:?}"),
            None => {
                env.insert(key, value);
            }
        }
    }
    Ok(crate::guest::ProcStart {
        argv: command.argv,
        env,
        cwd: command.cwd,
        allow_env: mvm_core::env_hygiene::EnvReadmit::none(),
    })
}

#[cfg(test)]
mod boot_command_tests;

/// Starts a launch's command in its machine once the machine is up, and
/// names the process it started.
pub trait CommandStarter: Send + Sync {
    /// Start `command` in machine `name`.
    ///
    /// # Errors
    /// The machine's guest did not take the command.
    fn start(&self, name: &str, command: BootCommand) -> Result<String>;
}

/// Starts the command through the machine's guest agent:
/// [`start_boot_command`].
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestAgentStarter;

impl CommandStarter for GuestAgentStarter {
    fn start(&self, name: &str, command: BootCommand) -> Result<String> {
        start_boot_command(name, command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn spec(name: &str, image: &str, cpus: u32) -> MachineSpec {
        MachineSpec {
            prepared_image: None,
            schema_version: mp::MACHINE_SPEC_SCHEMA_VERSION,
            name: name.to_string(),
            image: Some(image.to_string()),
            manifest: None,
            policy_generation: None,
            deployment: None,
            resolved_digest: None,
            runtime_pack: false,
            registry_pack_image: None,
            net: false,
            allow_host: Vec::new(),
            peer: Vec::new(),
            routes: Vec::new(),
            ai: None,
            ports: Vec::new(),
            cpus,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            agent_verb: Vec::new(),
            caller_commitment: None,
            created_at: None,
            workload_dir: None,
            last_started_at: None,
            health_check: None,
            grants: None,
            gpu: false,
            gpu_device: None,
        }
    }

    fn isolated() -> (TestEnv, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        (env, dir)
    }

    #[test]
    fn a_new_definition_is_created_and_a_matching_one_reused() {
        let (_env, _dir) = isolated();
        let (_, action) = resolve_spec("web", Some(spec("web", "alpine", 1)), None, false).unwrap();
        assert_eq!(action, SpecReconcile::Create);
        mp::save_machine_spec(&spec("web", "alpine", 1), false).unwrap();
        let (_, action) = resolve_spec(
            "web",
            Some(spec("web", "alpine", 1)),
            existing_spec("web"),
            false,
        )
        .unwrap();
        assert_eq!(action, SpecReconcile::Reuse);
    }

    #[test]
    fn a_changed_definition_needs_force_to_recreate() {
        let (_env, _dir) = isolated();
        mp::save_machine_spec(&spec("web", "alpine", 1), false).unwrap();
        let existing = existing_spec("web");
        assert!(
            resolve_spec(
                "web",
                Some(spec("web", "alpine", 2)),
                existing.clone(),
                false
            )
            .is_err()
        );
        let (chosen, action) =
            resolve_spec("web", Some(spec("web", "alpine", 2)), existing, true).unwrap();
        assert!(matches!(action, SpecReconcile::Recreate { .. }));
        assert_eq!(chosen.cpus, 2);
    }

    #[test]
    fn naming_no_source_boots_the_existing_definition_or_refuses() {
        let (_env, _dir) = isolated();
        let err = resolve_spec("ghost", None, existing_spec("ghost"), false).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err:#}");
        mp::save_machine_spec(&spec("web", "alpine", 1), false).unwrap();
        let (chosen, action) = resolve_spec("web", None, existing_spec("web"), false).unwrap();
        assert_eq!(action, SpecReconcile::Reuse);
        assert_eq!(chosen.image.as_deref(), Some("alpine"));
    }

    /// A create persists before booting, and the caller's boot runs once.
    #[test]
    fn persist_and_boot_saves_then_boots() {
        let (_env, _dir) = isolated();
        let desired = spec("web", "alpine", 1);
        let lifecycle =
            mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire("web").unwrap();
        let mut booted = 0;
        let ran = persist_and_boot(
            DetachedBoot {
                name: "web",
                spec: &desired,
                action: SpecReconcile::Create,
                secret_refs: None,
            },
            &lifecycle,
            || {
                booted += 1;
                Ok(())
            },
        )
        .unwrap();
        assert!(ran);
        assert_eq!(booted, 1);
        assert!(mvm_core::config::machine_spec_path("web").exists());
    }

    /// A boot that fails leaves the definition persisted, so the error is
    /// reported against a machine the caller can inspect and start again.
    #[test]
    fn a_failed_boot_is_reported_and_keeps_the_definition() {
        let (_env, _dir) = isolated();
        let desired = spec("web", "alpine", 1);
        let lifecycle =
            mvm_runtime::vm::instance_snapshot::MachineLifecycleLock::acquire("web").unwrap();
        let err = persist_and_boot(
            DetachedBoot {
                name: "web",
                spec: &desired,
                action: SpecReconcile::Create,
                secret_refs: None,
            },
            &lifecycle,
            || bail!("no kernel"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no kernel"));
        assert!(mvm_core::config::machine_spec_path("web").exists());
    }

    #[test]
    fn a_ttl_on_an_unregistered_machine_is_refused() {
        let (_env, _dir) = isolated();
        let err = apply_ttl("ghost", std::time::Duration::from_secs(60)).unwrap_err();
        assert!(matches!(err, crate::MvmError::NotFound { .. }), "{err}");
    }

    #[test]
    fn a_ttl_is_recorded_on_the_registry_entry() {
        let (_env, _dir) = isolated();
        crate::register_machine(&crate::MachineRegistration::minimal("web", "none"));
        apply_ttl("web", std::time::Duration::from_secs(600)).unwrap();
        let registry = mvm_runtime::vm::name_registry::VmNameRegistry::load(
            &mvm_runtime::vm::name_registry::registry_path(),
        )
        .unwrap();
        assert!(
            registry
                .lookup("web")
                .and_then(|record| record.expires_at.clone())
                .is_some()
        );
    }

    #[test]
    fn an_empty_boot_command_is_refused_before_touching_the_guest() {
        let err = start_boot_command("web", BootCommand::default()).unwrap_err();
        assert!(err.to_string().contains("program to run"), "{err:#}");
    }

    #[test]
    fn failed_readiness_rolls_back_without_an_accepted_launch() {
        let (_env, _home) = isolated();
        let name = "not-serving";
        crate::register_machine(&crate::MachineRegistration {
            vm_dir: mvm_core::config::vm_state_dir(name)
                .to_string_lossy()
                .into_owned(),
            ..crate::MachineRegistration::minimal(name, "default")
        });
        crate::record_readiness(
            name,
            mvm_core::domain::instance::InstanceReadiness::LaunchAccepted,
        );
        let rolled_back = std::sync::atomic::AtomicBool::new(false);

        let err =
            require_serving_guest_result(name, std::time::Duration::from_millis(1), false, || {
                rolled_back.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .expect_err("a non-serving guest must fail closed");

        assert!(err.to_string().contains("partial start was rolled back"));
        assert!(
            rolled_back.load(std::sync::atomic::Ordering::SeqCst),
            "the partially started VM is stopped"
        );
        assert_eq!(
            crate::readiness::readiness_of(name),
            None,
            "no LaunchAccepted state survives rollback"
        );
    }

    #[test]
    fn serving_guest_does_not_roll_back() {
        let (_env, _home) = isolated();
        let name = "serving";
        require_serving_guest_result(name, std::time::Duration::from_secs(1), true, || {
            bail!("a serving guest must not be stopped")
        })
        .expect("a serving guest is accepted");
    }

    #[test]
    fn failed_abort_retains_registry_ownership_for_recovery() {
        let (_env, _home) = isolated();
        let name = "abort-unresolved";
        crate::register_machine(&crate::MachineRegistration {
            vm_dir: mvm_core::config::vm_state_dir(name)
                .to_string_lossy()
                .into_owned(),
            ..crate::MachineRegistration::minimal(name, "default")
        });

        let error =
            require_serving_guest_result(name, std::time::Duration::from_millis(1), false, || {
                anyhow::bail!("VMM is still alive")
            })
            .expect_err("failed abort stays unresolved");

        assert!(error.abort_is_unresolved());
        let registry = mvm_runtime::vm::name_registry::VmNameRegistry::load(
            &mvm_runtime::vm::name_registry::registry_path(),
        )
        .expect("load registry");
        assert!(
            registry.lookup(name).is_some(),
            "registry ownership must survive until VMM death is proven"
        );
        assert!(format!("{error:#}").contains("VMM is still alive"));
    }
}
