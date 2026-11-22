//! Independent root custody and private, boot-bound child lifecycle dispatch.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use mvm_contract::plan::Variant;
use mvm_contract::protocol::broker::ServiceId;
use mvm_contract::protocol::broker_control::ServiceProxyBinding;
use mvm_contract::protocol::workload_actor::{
    LifecycleOperation, WorkflowRole, capability_descriptor,
};
use mvm_core::crypto::aead::Key;
use mvm_core::net::actor_session::{
    ActorDeadlineStream, ActorSessionBinding, read_actor_request, write_actor_response,
};
use mvm_runtime::AnyBackend;
use mvm_runtime::actor_teardown::{ActorBootstrapHelper, ActorOwner, supports_actor_backend};
use mvm_vmm::host::aux_bin;

use crate::actor_bootstrap::ActorBootstrap;
use crate::actor_holder::ActorHolderConfig;
use crate::actor_lifecycle::local_mailboxes::LocalActorMailboxes;
use crate::actor_lifecycle::{
    ActorJournal, ActorLifecycle, ActorLifecycleInputs, ExactTemplateCatalog, ParentActivation,
};
use crate::actor_process::{self, ActorLaunch, BootstrapReply};
use crate::actor_reservations::ActorReservations;
use crate::audit::{emitter::AuditEmitter, host_keypair};
use crate::plan_admission::{
    InMemoryNonceLedger, RunPosture, StartAdmittedParams, SystemClock, admit_plan_for_run,
    start_admitted_owned_actor_with_bootstrap,
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

mod root_reservation;
use root_reservation::RootReservation;

#[derive(Debug, thiserror::Error)]
#[error("actor cleanup remains unknown; retained state must be reconciled")]
struct ControllerCleanupUnknown;

/// Run from a private inherited stdin socket, without a pathname control endpoint.
///
/// A ready reply is written only after ordinary admission, native start, holder
/// custody, and exact public-session activation. Errors after native dispatch
/// attempt original-owner teardown; uncertainty never refunds actor budgets.
pub fn run(socket: UnixStream) -> Result<()> {
    let mut bootstrap_stream = ActorDeadlineStream::new(socket, Instant::now() + STARTUP_TIMEOUT)?;
    let result = (|| {
        let bootstrap: ActorBootstrap = actor_process::receive(&mut bootstrap_stream)?;
        bootstrap.validate()?;
        start(bootstrap, &mut bootstrap_stream)
    })();
    if let Err(error) = result.as_ref() {
        let reply = if error.is::<ControllerCleanupUnknown>() {
            BootstrapReply::Unknown
        } else {
            BootstrapReply::Refused
        };
        let _ = actor_process::reply(&mut bootstrap_stream, &reply);
    }
    result
}

fn start(bootstrap: ActorBootstrap, ready: &mut ActorDeadlineStream) -> Result<()> {
    crate::actor_bootstrap::require_host_budget(
        &mvm_core::user_config::load_strict(None)?,
        bootstrap.host_budget,
    )?;
    let backend = AnyBackend::from_hypervisor("hvf");
    supports_actor_backend(&backend)?;
    let deadline = workflow_deadline(&bootstrap)?;
    let holder_binary = aux_bin::resolve_verified(&actor_process::HOLDER_SPEC)?;
    let keys_dir = host_keypair::default_keys_dir()?;
    let signer = host_keypair::load_or_init_at(&keys_dir)?;
    let mailboxes = Arc::new(LocalActorMailboxes::new(
        keys_dir.clone(),
        bootstrap.constraints.mailbox_policy.clone(),
        digest_bytes(bootstrap.constraints.digest()?.as_str())?,
    )?);
    ensure!(
        Some(mailboxes.install_controller(&bootstrap.parent)?) == bootstrap.parent.mailbox,
        "actor parent mailbox must be provisioned before signing"
    );
    let paths = StatePaths::create(&bootstrap)?;
    let journal = ActorJournal::create(&paths.journal, Key::load_or_create(&paths.journal_key)?)?;
    let reservations = if paths.reservations.exists() {
        ActorReservations::open_with_host_budget(&paths.reservations, bootstrap.host_budget)?
    } else {
        ActorReservations::create(&paths.reservations, bootstrap.host_budget)?
    };
    let templates = ExactTemplateCatalog::new(bootstrap.exact_templates()?)?;
    let teardown_emitter = AuditEmitter::new(signer.signing.clone())?;
    let emitter = AuditEmitter::new(signer.signing)?;
    let mut config = bootstrap.launch.config(&bootstrap.parent)?;
    config.mailbox_conversation = Some(mvm_core::mailbox::conversation_wire::ConversationTarget {
        address: crate::mailbox_launch::actor_template::endpoint_material(
            &keys_dir,
            &bootstrap.parent,
        )?
        .context("actor controller mailbox material is unavailable")?
        .address,
        policy_epoch: bootstrap.constraints.mailbox_policy.policy_epoch,
    });
    config
        .service_proxies
        .push(actor_proxy(&bootstrap, &paths.holder_socket)?);
    let admitted = admit_plan_for_run(
        &bootstrap.parent,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(&keys_dir),
        None,
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )?;
    let mut root = RootReservation::reserve(
        &paths.reservations,
        paths.activation.with_file_name("root-terminal.json"),
        &bootstrap,
    )?;
    let vm_name = config.name.clone();
    let host_permit = admitted.host_budget_permit();
    let mut owner = None;
    let mut lifecycle = None;
    let mut dispatched = false;
    let result = (|| {
        root.prepared(admitted.signed())?;
        emitter.emit_admitted(admitted.plan(), admitted.signer_id())?;
        let (controller, holder) = UnixStream::pair()?;
        let binding = Arc::new(Mutex::new(None));
        let hook = holder_bootstrap(
            holder_binary,
            paths.holder_socket.clone(),
            holder,
            Arc::clone(&binding),
        );
        let started = start_admitted_owned_actor_with_bootstrap(
            StartAdmittedParams {
                backend: &backend,
                admitted,
                config,
                policy_bundle: None,
                emitter: Some(&emitter),
                assurance: None,
            },
            &mut owner,
            hook,
            || {
                ensure!(
                    Instant::now() < deadline,
                    "actor workflow expired before dispatch"
                );
                dispatched = true;
                Ok(())
            },
        )?;
        let binding = binding
            .lock()
            .expect("actor bootstrap binding poisoned")
            .take()
            .context("runtime did not provision actor session")?;
        let parent = ParentActivation::activate(&started, binding, &paths.activation)
            .context("actor controller parent activation failed")?;
        let parent_owner = owner
            .as_mut()
            .context("root launch lost original runtime owner")?;
        parent_owner
            .verify_resource_envelope(&bootstrap.constraints.parent_charge)
            .context("actor controller root resource verification failed")?;
        root.running(started.admitted.signed())?;
        lifecycle = Some(
            ActorLifecycle::new(
                ActorLifecycleInputs {
                    parent,
                    templates,
                    journal,
                    reservations,
                    constraints: bootstrap.constraints,
                    backend,
                    mailboxes,
                    emitter,
                    signer_keys_dir: keys_dir,
                    variant: Variant::Dev,
                },
                parent_owner,
            )
            .context("actor controller lifecycle initialization failed")?,
        );
        let launch = ActorLaunch {
            machine: started.vm_id.0,
            plan_id: started.admitted.plan_id().0.clone(),
            controller_pid: std::process::id(),
        };
        let execution_limit = if bootstrap.parent.resources.timeouts.exec_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(u64::from(
                bootstrap.parent.resources.timeouts.exec_secs,
            )))
        };
        let code = serve(
            lifecycle.as_mut().context("actor lifecycle owner absent")?,
            parent_owner,
            controller,
            deadline,
            execution_limit,
            || {
                actor_process::reply(ready, &BootstrapReply::Started { launch })?;
                actor_process::await_commit(ready)
            },
        )
        .context("actor controller lifecycle serving failed")?;
        teardown_emitter.emit(
            &bootstrap.parent,
            "actor.entrypoint.completed",
            [("exit_code".into(), code.to_string())],
        )?;
        ensure!(code == 0, "actor root entrypoint exited unsuccessfully");
        Ok(())
    })();
    let mut cleanup = CleanupCustody {
        lifecycle: &mut lifecycle,
        owner: &mut owner,
        root: &mut root,
        plan: &bootstrap.parent,
        emitter: &teardown_emitter,
        startup_result: &result,
        dispatched,
        vm_name: &vm_name,
        host_permit: &host_permit,
    };
    retry_cleanup(
        || cleanup.attempt(),
        || {
            let _ = actor_process::reply(ready, &BootstrapReply::Unknown);
            tracing::error!("actor cleanup pending; original custody retained");
        },
        std::thread::park_timeout,
    );
    result
}

struct CleanupCustody<'a> {
    lifecycle: &'a mut Option<ActorLifecycle>,
    owner: &'a mut Option<ActorOwner>,
    root: &'a mut RootReservation,
    plan: &'a mvm_contract::plan::ExecutionPlan,
    emitter: &'a AuditEmitter,
    startup_result: &'a Result<()>,
    dispatched: bool,
    vm_name: &'a str,
    host_permit: &'a crate::admission_budget::HostBudgetPermit,
}

impl CleanupCustody<'_> {
    fn attempt(&mut self) -> Result<()> {
        // The typed startup error remains owned until original custody has
        // moved into the owner slot or completed exact rollback.
        if self.owner.is_none()
            && let Err(error) = self.startup_result
            && let Some(failure) =
                error.downcast_ref::<mvm_runtime::actor_teardown::ActorStartFailure>()
        {
            if let Some(proof) = failure.no_dispatch_proof()
                && proof.matches_launch(self.vm_name, self.plan)
            {
                self.host_permit
                    .record_runtime_no_dispatch(proof, self.vm_name, self.plan, self.emitter)
                    .context(ControllerCleanupUnknown)?;
                self.dispatched = false;
            }
            match failure.take_owner() {
                Ok(Some(retained)) => *self.owner = Some(retained),
                Ok(None) => failure.retry_stop().context(ControllerCleanupUnknown)?,
                Err(error) => return Err(error.context(ControllerCleanupUnknown)),
            }
        }
        // A failed descendant cleanup neither keeps the root active nor drops
        // the original descendant owner.
        let children = self
            .lifecycle
            .as_mut()
            .map_or(Ok(()), ActorLifecycle::shutdown_all);
        let parent = if let Some(owner) = self.owner.as_mut() {
            owner.stop_and_reap().and_then(|proof| {
                ensure!(children.is_ok(), ControllerCleanupUnknown);
                self.root.stopped(&proof, self.plan, self.emitter)
            })
        } else if !self.dispatched {
            self.root.never_dispatched(self.plan, self.emitter)
        } else {
            Err(ControllerCleanupUnknown.into())
        };
        children.context(ControllerCleanupUnknown)?;
        parent.context(ControllerCleanupUnknown)
    }
}

fn retry_cleanup(
    mut attempt: impl FnMut() -> Result<()>,
    report_pending: impl FnOnce(),
    mut wait: impl FnMut(Duration),
) {
    if attempt().is_ok() {
        return;
    }
    report_pending();
    let mut delay = Duration::from_secs(1);
    loop {
        // Retry incomplete cleanup transactions, never liveness discovery.
        // No launch or guest operation remains reachable in cleanup-only mode.
        wait(delay);
        if attempt().is_ok() {
            return;
        }
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

fn holder_bootstrap(
    binary: PathBuf,
    socket: PathBuf,
    controller: UnixStream,
    captured: Arc<Mutex<Option<ActorSessionBinding>>>,
) -> mvm_runtime::actor_teardown::ActorBootstrap {
    Box::new(move |material| {
        let (binding, seed) = material.into_host_parts();
        let child = crate::actor_holder::spawn(
            &binary,
            ActorHolderConfig {
                binding: binding.clone(),
                host_seed: *seed,
                listen_socket: socket.clone(),
            },
            controller,
        )?;
        *captured.lock().expect("actor bootstrap binding poisoned") = Some(binding);
        Ok(ActorBootstrapHelper {
            child,
            resources: vec![socket],
        })
    })
}

fn serve(
    lifecycle: &mut ActorLifecycle,
    parent: &mut ActorOwner,
    channel: UnixStream,
    deadline: Instant,
    execution_limit: Option<Duration>,
    ready: impl FnOnce() -> Result<()>,
) -> Result<i32> {
    let observer = parent.exit_observer()?;
    let wake = channel.try_clone()?;
    let watcher = std::thread::spawn(move || {
        let observed = observer.wait_event(deadline);
        let _ = wake.shutdown(Shutdown::Both);
        observed
    });
    let mut application = None;
    let mut application_cancel = None;
    let result: Result<()> = (|| {
        let application_wake = channel.try_clone()?;
        let mut stream = ActorDeadlineStream::new(channel, deadline)?;
        ensure!(parent.is_running()?, "actor parent exited before readiness");
        // The immutable image entrypoint starts only after caller commit; this
        // thread immediately serves lifecycle while a separate reader awaits exit.
        let running = commit_and_dispatch(deadline, execution_limit, ready, |deadline| {
            parent.dispatch_entrypoint(deadline)
        })?;
        application_cancel = Some(running.cancellation_handle()?);
        application = Some(std::thread::spawn(move || {
            #[cfg(feature = "hvf-live-validation")]
            let mut reported = 0u16;
            let terminal = running.wait(|_event| {
                #[cfg(feature = "hvf-live-validation")]
                if let mvm_agentd::vsock::EntrypointEvent::Stderr { chunk } = _event {
                    // Only fixed fixture markers are observable, never guest output or payloads.
                    for (index, stage) in [
                        "ACTOR_LIVE_STAGE_NEGATIVE_CALL",
                        "ACTOR_LIVE_STAGE_CALL",
                        "ACTOR_LIVE_STAGE_RECEIVE_RESULT",
                        "ACTOR_LIVE_STAGE_ACK_RESULT",
                        "ACTOR_LIVE_STAGE_RELEASE_CHILD",
                        "ACTOR_LIVE_REFUSAL_NOT_AUTHORIZED",
                        "ACTOR_LIVE_REFUSAL_UNAVAILABLE",
                        "ACTOR_LIVE_REFUSAL_OVERSIZED",
                        "ACTOR_LIVE_REFUSAL_OTHER",
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        if reported & (1 << index) == 0
                            && chunk
                                .windows(stage.len())
                                .any(|bytes| bytes == stage.as_bytes())
                        {
                            reported |= 1 << index;
                            eprintln!("{stage}");
                        }
                    }
                }
            });
            let _ = application_wake.shutdown(Shutdown::Both);
            terminal
        }));
        loop {
            let request = read_actor_request(&mut stream)?;
            let response = lifecycle.handle(request, parent);
            write_actor_response(&mut stream, &response)?;
        }
    })();
    if let Some(cancel) = application_cancel {
        let _ = cancel.cancel();
    }
    // An IPC error must wake the native observer too; do not join a watcher
    // while the original parent can remain running indefinitely.
    let stopped = parent.stop_and_reap();
    // Do not block joining if native death could not be established.
    let _root_exit_proof = stopped.context(ControllerCleanupUnknown)?;
    let observed = watcher
        .join()
        .map_err(|_| anyhow::anyhow!("actor native observer panicked"))?;
    observed?;
    if let Some(application) = application {
        let terminal = application
            .join()
            .map_err(|_| anyhow::anyhow!("actor entrypoint reader panicked"))??;
        let mvm_agentd::vsock::EntrypointEvent::Exit { code } = terminal else {
            anyhow::bail!("actor entrypoint did not report a terminal exit");
        };
        Ok(code)
    } else {
        result?;
        anyhow::bail!("actor entrypoint was not dispatched")
    }
}

fn commit_and_dispatch<T>(
    admitted_deadline: Instant,
    execution_limit: Option<Duration>,
    commit: impl FnOnce() -> Result<()>,
    dispatch: impl FnOnce(Instant) -> Result<T>,
) -> Result<T> {
    commit()?;
    let deadline = entrypoint_deadline(admitted_deadline, execution_limit, Instant::now())?;
    dispatch(deadline)
}

fn entrypoint_deadline(
    admitted_deadline: Instant,
    execution_limit: Option<Duration>,
    now: Instant,
) -> Result<Instant> {
    ensure!(
        now < admitted_deadline,
        "actor workflow expired before entrypoint dispatch"
    );
    Ok(execution_limit
        .and_then(|limit| now.checked_add(limit))
        .map_or(admitted_deadline, |limit| limit.min(admitted_deadline)))
}

fn actor_proxy(bootstrap: &ActorBootstrap, socket: &Path) -> Result<ServiceProxyBinding> {
    let workflow = bootstrap
        .parent
        .workflow
        .as_ref()
        .context("missing actor workflow")?;
    let WorkflowRole::Controller { grant } = &workflow.role else {
        anyhow::bail!("actor parent is not a controller");
    };
    let capabilities = grant
        .operations
        .iter()
        .map(|operation| {
            capability_descriptor(match operation {
                LifecycleOperation::Launch => "launch_child",
                LifecycleOperation::ObserveChild => "observe_child",
                LifecycleOperation::ReleaseChild => "release_child",
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(ServiceProxyBinding {
        service: ServiceId::parse("host.actor.v1")?,
        endpoint: socket
            .to_str()
            .context("actor socket path is not UTF-8")?
            .into(),
        capabilities,
    })
}

fn workflow_deadline(bootstrap: &ActorBootstrap) -> Result<Instant> {
    let workflow = bootstrap
        .parent
        .workflow
        .as_ref()
        .context("missing actor workflow")?;
    let WorkflowRole::Controller { grant } = &workflow.role else {
        anyhow::bail!("actor parent is not a controller");
    };
    let expires = grant
        .workflow_deadline_unix_ms
        .min(bootstrap.parent.valid_until.unix_millis());
    let remaining = expires
        .checked_sub(chrono::Utc::now().timestamp_millis())
        .filter(|value| *value > 0)
        .context("actor workflow expired")?;
    Instant::now()
        .checked_add(Duration::from_millis(remaining.try_into()?))
        .context("actor workflow deadline overflow")
}

fn digest_bytes(digest: &str) -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(
        digest
            .strip_prefix("sha256:")
            .context("invalid actor digest")?,
        &mut bytes,
    )?;
    Ok(bytes)
}

struct StatePaths {
    journal: PathBuf,
    journal_key: PathBuf,
    activation: PathBuf,
    reservations: PathBuf,
    holder_socket: PathBuf,
}

impl StatePaths {
    fn create(bootstrap: &ActorBootstrap) -> Result<Self> {
        let root = mvm_core::config::mvm_home_strict()?.join("actors");
        mvm_core::config::create_private_dir(&root)?;
        let digest = hex::encode(digest_bytes(&bootstrap.parent.plan_id.0)?);
        let attempt = root.join(&digest);
        // Never resume a submitted boot or erase its unknown effects on retry.
        std::fs::create_dir(&attempt).context("actor boot already exists or cannot be created")?;
        mvm_core::config::create_private_dir(&attempt)?;
        let keys = host_keypair::default_keys_dir()?.join("actor-journals");
        mvm_core::config::create_private_dir(&keys)?;
        mvm_core::config::secure_fallback_socket_dir_at(&attempt)?;
        let holder_socket = mvm_core::config::vm_socket_dir_at(&attempt).join("holder.sock");
        Ok(Self {
            journal: attempt.join("lifecycle.enc"),
            journal_key: keys.join(format!("{digest}.key")),
            activation: attempt.join("activation.json"),
            reservations: root.join("reservations.json"),
            holder_socket,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn root_preboot_refusal_reconciles_only_matching_original_runtime_proof() {
        let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .expect("home lock");
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        mvm_core::private_fs::ensure_private_dir(home.path()).unwrap();
        let bootstrap = crate::actor_bootstrap::tests::authored().bind().unwrap();
        let signed = mvm_core::plan::sign_plan(
            &bootstrap.parent,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            "host:test",
        );
        let config = mvm_core::vm_backend::VmStartConfig {
            name: bootstrap.parent.workload.0.clone(),
            rootfs_path: home.path().join("missing.ext4").display().to_string(),
            plan_json: Some(serde_json::to_string(&signed).unwrap()),
            ..Default::default()
        };
        let refusal = AnyBackend::from_hypervisor("hvf")
            .start_owned_actor_with_bootstrap(
                &config,
                None,
                Some(Box::new(|_| {
                    panic!("preboot refusal cannot dispatch a holder")
                })),
            )
            .map(drop);
        assert!(
            refusal
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("mvm-meta")
        );
        let path = home.path().join("reservations.json");
        ActorReservations::create(&path, bootstrap.host_budget).unwrap();
        let terminal = home.path().join("terminal.json");
        let mut root = RootReservation::reserve(&path, terminal.clone(), &bootstrap).unwrap();
        root.prepared(&signed).unwrap();
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &home.path().join("audit"),
        )
        .unwrap();
        let unknown = Err(anyhow::anyhow!("unknown backend failure"));
        let host_permit = crate::admission_budget::HostBudgetPermit::reserve(
            &config.name,
            crate::admission_budget::charge_for(
                bootstrap.parent.resources.mem_mib,
                bootstrap
                    .parent
                    .grants
                    .as_ref()
                    .unwrap_or(&Default::default()),
            ),
        )
        .unwrap();
        host_permit.bind_plan(&bootstrap.parent).unwrap();
        host_permit
            .mark_dispatching_for(&bootstrap.parent, &config.name)
            .unwrap();
        let mut owner = None;
        let mut lifecycle = None;
        let mut cleanup = CleanupCustody {
            lifecycle: &mut lifecycle,
            owner: &mut owner,
            root: &mut root,
            plan: &bootstrap.parent,
            emitter: &emitter,
            startup_result: &unknown,
            dispatched: true,
            vm_name: &config.name,
            host_permit: &host_permit,
        };
        assert!(cleanup.attempt().is_err());
        cleanup.startup_result = &refusal;
        cleanup.vm_name = "another-attempt";
        assert!(cleanup.attempt().is_err());
        assert!(!terminal.exists());
        cleanup.vm_name = &config.name;
        let audit_file = crate::audit::emitter::audit_path_for_tenant(
            &home.path().join("audit"),
            &bootstrap.parent.tenant.0,
        );
        std::fs::create_dir(&audit_file).unwrap();
        assert!(cleanup.attempt().is_err());
        assert!(!terminal.exists());
        std::fs::remove_dir(&audit_file).unwrap();
        cleanup.attempt().unwrap();
        cleanup.attempt().unwrap();
        assert!(terminal.is_file());
    }

    #[test]
    fn commit_after_expiry_never_dispatches_entrypoint() {
        let committed = std::cell::Cell::new(false);
        let dispatched = std::cell::Cell::new(false);
        let admitted_deadline = Instant::now() + Duration::from_millis(10);
        let (_sender, receiver) = std::sync::mpsc::channel::<()>();
        let result = commit_and_dispatch(
            admitted_deadline,
            Some(Duration::from_secs(60)),
            || {
                // Model an ACK withheld until the admitted authority expires.
                assert_eq!(
                    receiver
                        .recv_timeout(admitted_deadline.saturating_duration_since(Instant::now())),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                );
                committed.set(true);
                Ok(())
            },
            |_| {
                dispatched.set(true);
                Ok(())
            },
        );
        assert!(committed.get());
        assert!(result.is_err());
        assert!(!dispatched.get());
    }

    #[test]
    fn committed_execution_cap_never_extends_admitted_deadline() {
        let now = Instant::now();
        let admitted = now + Duration::from_secs(10);
        assert_eq!(
            entrypoint_deadline(admitted, Some(Duration::from_secs(3)), now).unwrap(),
            now + Duration::from_secs(3)
        );
        for cap in [None, Some(Duration::from_secs(60))] {
            assert_eq!(entrypoint_deadline(admitted, cap, now).unwrap(), admitted);
        }
        assert!(entrypoint_deadline(admitted, None, admitted).is_err());
    }

    #[test]
    fn failed_commit_never_dispatches_entrypoint() {
        let result: Result<()> = commit_and_dispatch(
            Instant::now() + Duration::from_secs(10),
            None,
            || anyhow::bail!("caller disconnected before commit"),
            |_| panic!("uncommitted entrypoint must never dispatch"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn cleanup_transaction_retry_is_bounded_and_keeps_original_helper_owned() {
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_writer, reader) = UnixStream::pair().unwrap();
        let child = Mutex::new(
            Command::new("/bin/cat")
                .stdin(Stdio::from(OwnedFd::from(reader)))
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let attempts = AtomicUsize::new(0);
        let reports = AtomicUsize::new(0);
        retry_cleanup(
            || {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    anyhow::bail!("injected transient cleanup failure");
                }
                let mut child = child.lock().unwrap();
                child.kill()?;
                child.wait()?;
                Ok(())
            },
            || {
                reports.fetch_add(1, Ordering::SeqCst);
            },
            |delay| {
                assert_eq!(delay, Duration::from_secs(1));
                assert!(
                    child.lock().unwrap().try_wait().unwrap().is_none(),
                    "cleanup failure must retain the original live helper"
                );
            },
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(reports.load(Ordering::SeqCst), 1);
        assert!(child.lock().unwrap().try_wait().unwrap().is_some());
    }

    #[test]
    fn cleanup_backoff_has_a_finite_cap_without_abandoning_custody() {
        let mut attempts = 0;
        let mut delays = Vec::new();
        retry_cleanup(
            || {
                attempts += 1;
                ensure!(attempts == 9, "injected incomplete cleanup");
                Ok(())
            },
            || {},
            |delay| delays.push(delay.as_secs()),
        );
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn unknown_cleanup_keeps_the_original_error_in_the_chain() {
        let result: Result<()> = Err(std::io::Error::other("retained original custody").into());
        let error = result.context(ControllerCleanupUnknown).unwrap_err();
        assert!(error.is::<ControllerCleanupUnknown>());
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(
            serde_json::to_string(&BootstrapReply::Unknown).unwrap(),
            r#"{"status":"unknown"}"#
        );
    }
}
