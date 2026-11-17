use super::*;
use crate::commands::image;
use crate::commands::vm::up;
use mvm_client::lifecycle::MachineLifecycleLock;

pub(super) fn run_start(cmd: MachineStartCmd) -> Result<()> {
    anyhow::ensure!(
        cmd.if_hvf_boot_nonce.is_none(),
        "--if-hvf-boot-nonce requires machine restart"
    );
    if cmd.names.len() > 1 && (cmd.receipt.is_some() || cmd.json || cmd.dry_run) {
        anyhow::bail!(
            "--receipt/--json/--dry-run report on a single machine; \
             start machines individually to use them"
        );
    }
    if cmd.names.len() == 1 {
        return start_machine(cmd.start_args_for(&cmd.names[0]));
    }
    let mut had_err = false;
    for name in &cmd.names {
        if let Err(err) = start_machine(cmd.start_args_for(name)) {
            eprintln!("failed to start {name}: {err:#}");
            had_err = true;
        }
    }
    if had_err {
        anyhow::bail!("one or more machines failed to start");
    }
    Ok(())
}

pub(super) fn run_restart(cmd: MachineStartCmd) -> Result<()> {
    if let Some(nonce) = &cmd.if_hvf_boot_nonce {
        anyhow::ensure!(
            cmd.names.len() == 1 && !cmd.dry_run,
            "conditional health restart requires exactly one machine and cannot be a dry run"
        );
        let boot_nonce: [u8; 32] = hex::decode(nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a 32-byte HVF boot nonce"))?;
        let name = &cmd.names[0];
        let expected = mvm_core::protocol::hvf_control::HvfInstance {
            vm_id: name.clone(),
            boot_nonce,
        };
        let lifecycle = MachineLifecycleLock::acquire(name)?;
        mvm_client::LocalBackend::new()
            .stop_machine_in_lifecycle(
                &mvm_core::client::dto::MachineId(name.clone()),
                &lifecycle,
                Some(&expected),
            )
            .context("conditional health restart refused; no replacement launched")?;
        let pending = start_machine_in_lifecycle(cmd.start_args_for(name), &lifecycle)?;
        drop(lifecycle);
        return complete_machine_start(pending);
    }
    if cmd.names.len() > 1 && (cmd.receipt.is_some() || cmd.json || cmd.dry_run) {
        anyhow::bail!(
            "--receipt/--json/--dry-run report on a single machine; \
             restart machines individually to use them"
        );
    }
    let restart_one = |name: &str| -> Result<()> {
        if !cmd.dry_run && machine_is_running(name) {
            stop_running_machine(name);
        }
        start_machine(cmd.start_args_for(name))
    };
    if cmd.names.len() == 1 {
        return restart_one(&cmd.names[0]);
    }
    let mut had_err = false;
    for name in &cmd.names {
        if let Err(err) = restart_one(name) {
            eprintln!("failed to restart {name}: {err:#}");
            had_err = true;
        }
    }
    if had_err {
        anyhow::bail!("one or more machines failed to restart");
    }
    Ok(())
}

/// Resolve the spec for `machine start`. If the machine does not exist and a
/// source is provided (`--image` or `--manifest`), the spec is created on
/// demand. If it exists and flags are provided, the configs are reconciled.
pub(super) fn resolve_start_spec(args: &MachineStartArgs) -> Result<(MachineSpec, SpecReconcile)> {
    let existing = load_machine_spec(&args.name).ok();
    let has_source = args.create_flags.image.is_some() || args.create_flags.manifest.is_some();
    if !has_source {
        return match existing {
            Some(spec) => Ok((spec, SpecReconcile::Reuse)),
            None => anyhow::bail!(
                "machine {name:?} does not exist.
                 Run `mvmctl machine ps` to list machines,
                 or `mvmctl machine start {name} --image <ref>` to create and start one.",
                name = args.name
            ),
        };
    }
    let manifest_source = args
        .create_flags
        .manifest
        .as_deref()
        .map(|arg| load_machine_manifest_source(Path::new(arg)))
        .transpose()?;
    let workflow = manifest_source.as_ref().map(|source| &source.workflow);
    let init = workflow
        .map(|workflow| workflow.init.clone())
        .unwrap_or_default();
    let volumes = match manifest_source.as_ref() {
        Some(source) => source
            .workflow
            .volumes
            .iter()
            .map(|spec| absolutize_manifest_volume_spec(spec, &source.base_dir))
            .collect::<Result<Vec<_>>>()?,
        None => Vec::new(),
    };
    let desired = build_machine_spec(MachineSpecInputs {
        name: &args.name,
        image: args.create_flags.image.as_deref(),
        net: args.create_flags.net,
        allow_host: &args.create_flags.allow_host,
        peer: &args.create_flags.peer,
        routes: manifest_source
            .as_ref()
            .map(|source| source.routes.as_slice())
            .unwrap_or_default(),
        gpu: args.create_flags.gpu,
        gpu_device: args.create_flags.gpu_device,
        ai: None,
        cpus: args.create_flags.cpus,
        cpu_limit: args.create_flags.cpu_limit,
        timeout: args.create_flags.timeout,
        grants_file: args.create_flags.grants_file.as_deref(),
        memory: args.create_flags.memory.as_deref(),
        mem_initial: args.create_flags.mem_initial.as_deref(),
        profile: args.create_flags.profile,
        workflow,
        volumes: &volumes,
        init: &init,
        policy: &args.create_flags.policy,
        project: manifest_source.as_ref().map(|source| &source.project),
    })?;
    let action = reconcile_machine_spec(existing.as_ref(), &desired, args.create_flags.force)?;
    let spec = match action {
        SpecReconcile::Reuse => {
            existing.context("machine spec reconciliation chose reuse without an existing spec")?
        }
        SpecReconcile::Create | SpecReconcile::Recreate { .. } => desired,
    };
    Ok((spec, action))
}

pub(super) fn start_machine(args: MachineStartArgs) -> Result<()> {
    if args.dry_run {
        return complete_machine_start(start_machine_inner(args, None)?);
    }
    let lifecycle = MachineLifecycleLock::acquire(&args.name)?;
    let pending = start_machine_in_lifecycle(args, &lifecycle)?;
    drop(lifecycle);
    complete_machine_start(pending)
}

/// Boot and connect under the caller's gate; drop it before completing init.
pub(super) fn start_machine_in_lifecycle(
    args: MachineStartArgs,
    lifecycle: &MachineLifecycleLock,
) -> Result<Option<PendingMachineStart>> {
    lifecycle.require_name(&args.name)?;
    start_machine_inner(args, Some(lifecycle))
}

pub(super) struct PendingMachineStart {
    args: MachineStartArgs,
    spec: MachineSpec,
    boot_digest: String,
    receipt_input: MachineStartReceiptInput,
    stream: std::os::unix::net::UnixStream,
    custody: crate::exec::RuntimeRunCustody,
}

pub(super) fn complete_machine_start(pending: Option<PendingMachineStart>) -> Result<()> {
    let Some(pending) = pending else {
        return Ok(());
    };
    let PendingMachineStart {
        args,
        spec,
        boot_digest,
        receipt_input,
        stream,
        custody,
    } = pending;
    let _lifecycle = init_then_reacquire(
        &spec.name,
        || run_machine_init_commands(&spec.name, &spec.init, stream),
        |lifecycle| custody.require_current(lifecycle),
        |lifecycle| stop_failed_init(&spec.name, &custody, lifecycle),
    )?;
    finish_machine_start(args, spec, boot_digest, receipt_input)
}

fn stop_failed_init(
    name: &str,
    custody: &crate::exec::RuntimeRunCustody,
    lifecycle: &MachineLifecycleLock,
) -> Result<()> {
    custody.require_current(lifecycle)?;
    mvm_client::LocalBackend::new()
        .stop_machine_in_lifecycle(
            &mvm_core::client::dto::MachineId(name.to_owned()),
            lifecycle,
            custody.authenticated_hvf_instance(),
        )
        .map_err(Into::into)
}

fn init_then_reacquire(
    name: &str,
    init: impl FnOnce() -> Result<()>,
    require_current: impl FnOnce(&MachineLifecycleLock) -> Result<()>,
    rollback: impl FnOnce(&MachineLifecycleLock) -> Result<()>,
) -> Result<MachineLifecycleLock> {
    let outcome = init();
    let lifecycle = MachineLifecycleLock::acquire(name)?;
    require_current(&lifecycle)
        .context("machine changed during dev.init; refusing stale start completion or rollback")?;
    if let Err(err) = outcome {
        rollback(&lifecycle).context(format!(
            "dev.init failed ({err:#}); stopping its original machine failed"
        ))?;
        return Err(err);
    }
    Ok(lifecycle)
}

fn start_machine_inner(
    args: MachineStartArgs,
    lifecycle: Option<&MachineLifecycleLock>,
) -> Result<Option<PendingMachineStart>> {
    let (spec, action) = resolve_start_spec(&args)?;
    let barrier = mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
    mvm_client::policy_profiles::coordinator::validate_machine_spec_generation(&spec, &barrier)?;
    if args.dry_run {
        let summary = machine_start_preflight_summary(
            &spec,
            args.hypervisor.as_deref(),
            args.receipt.as_deref(),
        )?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            print_machine_start_preflight_human(&summary);
        }
        return Ok(None);
    }
    let lifecycle = lifecycle.context("machine start requires its lifecycle transition")?;
    if machine_is_running(&args.name) {
        match action {
            SpecReconcile::Reuse => {
                println!("{}", already_running_notice(&args.name, args.json));
                return Ok(None);
            }
            SpecReconcile::Recreate { ref changed } => {
                eprintln!(
                    "machine {:?}: config changed ({changed}) — stopping the old instance and recreating it",
                    args.name
                );
                mvm_client::launch::detached::stop_running_machine_in_lifecycle(
                    &args.name, lifecycle,
                )?;
            }
            SpecReconcile::Create => {
                // A freshly-created spec cannot already be running; proceed to save and boot.
            }
        }
    }
    match action {
        SpecReconcile::Create => save_machine_spec(&spec, false)?,
        SpecReconcile::Recreate { .. } => overwrite_machine_spec(&spec)?,
        SpecReconcile::Reuse => {}
    }
    enforce_dev_init_profile(&spec.profile, &spec.init)?;
    enforce_persisted_volume_profile(&spec.profile, &spec.volumes)?;
    let effective_hypervisor = super::runtime::effective_hypervisor(args.hypervisor.as_deref());
    let receipt_input = machine_start_receipt_input(&spec, &effective_hypervisor)?;
    let started = mvm_client::launch::machine_start::start_machine_spec_in_lifecycle(
        &spec,
        &CliStartHost::for_spec(&spec, args.kernel_pin.is_some()),
        mvm_client::launch::machine_start::MachineStartParams {
            hypervisor: &effective_hypervisor,
            has_ad_hoc_argv: args.has_ad_hoc_argv,
            mailbox: args.mailbox,
        },
        lifecycle,
    )?;
    let boot_digest = started.resolved_digest;
    if !spec.init.is_empty() {
        let backend = mvm_client::AnyBackend::from_hypervisor(&effective_hypervisor);
        let custody =
            match crate::exec::RuntimeRunCustody::capture(&backend, &spec.name, lifecycle) {
                Ok(custody) => custody,
                Err(error) => {
                    // The launch has not released its transition, so no successor
                    // can have acquired this name before rollback.
                    mvm_client::LocalBackend::with_hypervisor(&effective_hypervisor)
                    .stop_machine_in_lifecycle(
                        &mvm_core::client::dto::MachineId(spec.name.clone()),
                        lifecycle,
                        None,
                    )
                    .with_context(|| format!(
                        "retaining the launched instance failed ({error:#}); rollback failed"
                    ))?;
                    return Err(
                        error.context("retaining the launched instance; dev.init not dispatched")
                    );
                }
            };
        let stream = match crate::exec::connect_session(&spec.name) {
            Ok(stream) => stream,
            Err(err) => {
                stop_failed_init(&spec.name, &custody, lifecycle).context(format!(
                    "connecting dev.init failed ({err:#}); stopping its original machine failed"
                ))?;
                return Err(err);
            }
        };
        return Ok(Some(PendingMachineStart {
            args,
            spec,
            boot_digest,
            receipt_input,
            stream,
            custody,
        }));
    }
    finish_machine_start(args, spec, boot_digest, receipt_input)?;
    Ok(None)
}

fn finish_machine_start(
    args: MachineStartArgs,
    mut spec: MachineSpec,
    boot_digest: String,
    receipt_input: MachineStartReceiptInput,
) -> Result<()> {
    mark_machine_started(&mut spec, boot_digest);
    let started_at = spec
        .last_started_at
        .clone()
        .context("machine start did not stamp last_started_at")?;
    if let Err(err) = persist_start_metadata(&spec) {
        tracing::warn!(error = %err, machine = %spec.name, "updating machine start metadata failed (non-fatal)");
    }
    let outcome = MachineStartReceiptOutcome {
        resolved_digest: spec
            .resolved_digest
            .clone()
            .context("machine start did not stamp resolved_digest")?,
        started_at,
        init_commands_executed: spec.init.len(),
    };
    if let Some(path) = args.receipt.as_deref() {
        write_machine_start_receipt(path, receipt_input.clone(), outcome.clone())?;
    }
    mvm_core::audit_emit!(VmStart, vm: &spec.name, "{}", machine_start_audit_detail(&receipt_input));
    if args.json {
        let summary = MachineStartJsonSummary::from_parts(receipt_input, outcome, args.receipt);
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else if !args.quiet {
        println!("started machine {}", spec.name);
    }
    Ok(())
}

fn persist_start_metadata(started: &MachineSpec) -> Result<()> {
    // Init runs without the gate, so preserve configuration edited during it.
    let mut current = load_machine_spec(&started.name)?;
    current.resolved_digest.clone_from(&started.resolved_digest);
    current.last_started_at.clone_from(&started.last_started_at);
    overwrite_machine_spec(&current)
}

/// How the CLI supplies a machine start with what differs by process: it may
/// build the workload kernel through the builder VM, and it prepares volumes
/// through its mount cache.
pub(super) struct CliStartHost {
    /// `--kernel-pin` was passed: boot the pinned kernel.
    kernel_pinned: bool,
    /// The profile the machine's stored spec names. Its registered volumes
    /// are leased under it, so a writable one is admitted exactly where a
    /// writable `--mount` disk image is; a name that is not a profile admits
    /// nothing writable.
    profile: mvm_client::volume::AdmittedProfile,
}

impl CliStartHost {
    pub(super) fn for_spec(spec: &MachineSpec, kernel_pinned: bool) -> Self {
        let profile = mvm_client::profile::RunProfile::from_name(&spec.profile)
            .map(mvm_client::volume::AdmittedProfile::new)
            .unwrap_or_default();
        Self {
            kernel_pinned,
            profile,
        }
    }
}

impl mvm_client::launch::machine_start::StartHost for CliStartHost {
    /// The CLI boots an explicit kernel on every backend: the pinned one, or a
    /// workload kernel, prepared on first use exactly as a transient run does. A
    /// refusal means that preparation failed.
    fn workload_kernel(&self, _backend: &str) -> Result<Option<String>> {
        match up::resolve_kernel_pin_path(self.kernel_pinned)? {
            Some(kernel_path) => Ok(Some(kernel_path)),
            None => {
                crate::commands::env::builder_vm::prepare_workload_kernel_for_launch().map(Some)
            }
        }
    }

    fn resolve_image(
        &self,
        reference: &str,
    ) -> Result<mvm_client::launch::machine_start::BootImage> {
        let cached = image::resolve_or_pull_run_image(&image::oci_cache_root(), reference, false)?;
        if cached.pulled {
            let auth_source = cached.auth_source.as_deref().unwrap_or("unknown");
            mvm_core::audit_emit!(
                ImageFetch,
                "source=machine_start reference={} digest={} prod=false layers={} trust_policy={} verification_status={} auth_source={}",
                cached.reference,
                cached.resolved_digest,
                cached.provenance.layer_digests.len(),
                cached.provenance.trust_policy,
                cached.provenance.verification_status,
                auth_source
            );
        }
        Ok(mvm_client::launch::machine_start::BootImage {
            label: cached.reference.clone(),
            rootfs: cached.rootfs_path.clone(),
            digest: cached.resolved_digest.clone(),
        })
    }

    fn prepare_volumes(
        &self,
        name: &str,
        volume_specs: &[String],
    ) -> Result<mvm_client::volume::LaunchPreparation> {
        let (volume_cfg, images) = build_machine_volume_cfg(volume_specs)?;
        let mut preparation = crate::commands::vm::volume::merge_registered_volumes_for_launch(
            name,
            &volume_cfg,
            self.profile,
        )?;
        preparation.writable_images = images;
        Ok(preparation)
    }
}

/// Gate `machine shell` / `machine exec` on the machine existing at all,
/// rather than on it having a persisted spec.
///
/// Both verbs reach the guest over the per-VM vsock socket under
/// `~/.mvm/vms/<name>/` and never read the spec: loading it would be a
/// bare existence check. But `machine run` boots a transient VM that has a
/// live console and no spec, so that check refused, with "does not exist", a
/// machine `machine ps` was listing as running.
///
/// A builder VM is refused by name. It is headless by construction — no guest
/// agent, no PTY — so admitting it would trade one wrong error for a worse
/// one, and the build system is not a machine the user drives.
pub(super) fn require_console_target(name: &str) -> Result<()> {
    // Before the name reaches `vm_state_dir`: the gate is the first thing
    // either verb does, and `console::run`'s own validation is downstream of
    // it.
    validate_machine_name(name)?;
    if mvm_core::naming::is_builder_owned_vm_name(name) {
        bail!(
            "{name:?} is an internal builder VM, not a machine. \
             The builder VM is headless — it has no shell and no console. \
             Its logs are the way in; `mvmctl doctor` reports its state."
        );
    }
    if load_machine_spec(name).is_ok() || config::vm_state_dir(name).exists() {
        return Ok(());
    }
    bail!(
        "machine {name:?} does not exist. Run `mvmctl machine ps` to list machines, \
         or `mvmctl machine create {name} --image <ref>` to create one."
    )
}

pub(super) fn run_exec_with_journal(
    cli: &Cli,
    args: MachineExecArgs,
    cfg: &MvmConfig,
) -> Result<()> {
    let state_dir = config::machine_state_dir(&args.name);
    let exit_code = {
        let _journal_lock = input_journal::lock(&state_dir)?;
        let pending = input_journal::begin_exec(&state_dir, &args.argv)?;
        finish_machine_exec(&state_dir, pending, exec_machine(cli, args, cfg))?
    };
    if exit_code != 0 {
        crate::observability::exit(exit_code);
    }
    Ok(())
}

pub(super) fn finish_machine_exec(
    state_dir: &Path,
    pending: Option<input_journal::PendingExec>,
    outcome: Result<i32>,
) -> Result<i32> {
    input_journal::finish_exec(
        state_dir,
        pending,
        outcome.as_ref().is_ok_and(|code| *code == 0),
    )?;
    outcome
}

pub(in crate::commands) fn exec_machine(
    cli: &Cli,
    args: MachineExecArgs,
    cfg: &MvmConfig,
) -> Result<i32> {
    require_console_target(&args.name)?;
    let command = if args.argv.is_empty() {
        None
    } else {
        Some(machine_exec_command(&args.argv))
    };
    if args.tty || args.interactive {
        use std::io::IsTerminal as _;
        require_tty(std::io::stdin().is_terminal())?;
        console::enforce_accessible_gate(&args.name, args.force)?;
        return match command {
            Some(cmd) => console::run_pty_command_for_exit(&args.name, cmd, Vec::new()),
            None => {
                console::console_interactive(&args.name, console::ConsoleSessionOptions::default())
            }
        };
    }
    console::run_for_exit(
        cli,
        console::Args {
            name: args.name,
            command,
            force: args.force,
            list: false,
            detach_timeout: None,
            env: Vec::new(),
            pty_argv: Vec::new(),
        },
        cfg,
    )
}

pub(super) fn shell_machine(cli: &Cli, args: MachineShellArgs, cfg: &MvmConfig) -> Result<()> {
    require_console_target(&args.name)?;
    console::run(
        cli,
        console::Args {
            name: args.name,
            command: None,
            force: args.force,
            list: false,
            detach_timeout: None,
            env: Vec::new(),
            pty_argv: Vec::new(),
        },
        cfg,
    )
}

pub(super) fn stop_machine(cli: &Cli, args: MachineStopArgs, cfg: &MvmConfig) -> Result<()> {
    use std::io::IsTerminal as _;

    confirm_stop(args.yes, std::io::stdin().is_terminal(), || {
        let prompt = if args.all {
            "Stop all running machines?".to_string()
        } else if args.names.len() == 1 {
            format!("Stop machine {:?}?", args.names[0])
        } else {
            format!(
                "Stop {} machines ({})?",
                args.names.len(),
                args.names.join(", ")
            )
        };
        crate::ui::confirm(&prompt)
    })?;
    if args.all {
        return down::run(cli, down::Args { name: None }, cfg);
    }
    let mut had_err = false;
    for name in &args.names {
        if let Err(err) = down::run(
            cli,
            down::Args {
                name: Some(name.clone()),
            },
            cfg,
        ) {
            eprintln!("failed to stop {name}: {err:#}");
            had_err = true;
        }
    }
    if had_err {
        anyhow::bail!("one or more machines failed to stop");
    }
    Ok(())
}

/// Record the quarantine first, so the workload cannot relaunch, then stop it.
/// A failed stop still leaves the workload quarantined and says so.
pub(super) fn quarantine_machine(
    cli: &Cli,
    args: super::MachineQuarantineArgs,
    cfg: &MvmConfig,
) -> Result<()> {
    mvm_client::containment::quarantine(&args.name, &args.reason)?;
    println!(
        "quarantined {}: it will not launch again until replaced",
        args.name
    );
    down::run(
        cli,
        down::Args {
            name: Some(args.name.clone()),
        },
        cfg,
    )
    .with_context(|| format!("{} is quarantined but could not be stopped", args.name))
}

/// A replacement starts a new epoch; the VM still running under the old one
/// must be gone first, so no process outlives the authority it was granted.
fn ensure_not_running(name: &str, running: bool) -> Result<()> {
    anyhow::ensure!(
        !running,
        "{name} is still running under its current execution epoch; stop it first \
         (`mvmctl machine stop {name}`), then replace it"
    );
    Ok(())
}

pub(super) fn replace_machine(args: &super::MachineReplaceArgs) -> Result<()> {
    ensure_not_running(&args.name, machine_is_running(&args.name))?;
    let epoch = mvm_client::containment::replace(&args.name)?;
    println!(
        "{} may launch again under execution epoch {epoch}",
        args.name
    );
    Ok(())
}

pub(super) fn confirm_stop(
    yes: bool,
    stdin_is_terminal: bool,
    prompt: impl FnOnce() -> bool,
) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !stdin_is_terminal {
        anyhow::bail!("refusing to stop without confirmation; pass --yes");
    }
    if !prompt() {
        anyhow::bail!("stop aborted");
    }
    Ok(())
}

pub(super) use mvm_client::launch::detached::{machine_is_running, stop_running_machine};

#[cfg(test)]
mod init_tests {
    use super::init_then_reacquire;
    use mvm_core::util::test_env::TestEnv;
    use mvm_runtime::vm::instance_snapshot::{MachineLifecycleLock, try_lock_resume};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn hung_init_permits_stop_and_delayed_failure_cannot_stop_successor() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let generation = AtomicU64::new(1);
        let rolled_back = AtomicBool::new(false);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let init = scope.spawn(|| {
                init_then_reacquire(
                    "init-race",
                    move || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        anyhow::bail!("delayed init failure")
                    },
                    |_| {
                        anyhow::ensure!(generation.load(Ordering::SeqCst) == 1, "replaced");
                        Ok(())
                    },
                    |_| {
                        rolled_back.store(true, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .map(|_| ())
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // This is the same cross-process gate taken by operator stop/removal.
            let operator = try_lock_resume("init-race").unwrap();
            assert!(operator.is_some(), "hung guest init must not hold the gate");
            generation.store(2, Ordering::SeqCst);
            drop(operator);
            release_tx.send(()).unwrap();
            let err = init.join().unwrap().unwrap_err();
            assert!(err.to_string().contains("refusing stale"), "{err:#}");
        });
        assert!(!rolled_back.load(Ordering::SeqCst));
        assert_eq!(generation.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn happy_init_reacquires_gate_for_completion() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let gate = init_then_reacquire(
            "init-happy",
            || {
                assert!(try_lock_resume("init-happy")?.is_some());
                Ok(())
            },
            |gate| gate.require_name("init-happy"),
            |_| panic!("successful init must not roll back"),
        )
        .unwrap();
        assert!(try_lock_resume("init-happy").unwrap().is_none());
        drop(gate);
        assert!(MachineLifecycleLock::acquire("init-happy").is_ok());
    }

    #[test]
    fn failed_current_init_rolls_back_under_gate() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let mut rolled_back = false;
        let outcome = init_then_reacquire(
            "init-failure",
            || anyhow::bail!("init failed"),
            |_| Ok(()),
            |_| {
                assert!(try_lock_resume("init-failure")?.is_none());
                rolled_back = true;
                Ok(())
            },
        );
        assert!(outcome.is_err());
        assert!(rolled_back);
    }

    #[test]
    fn delayed_success_cannot_complete_for_successor() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let outcome = init_then_reacquire(
            "init-stale-success",
            || Ok(()),
            |_| anyhow::bail!("original run replaced"),
            |_| panic!("stale success must not roll back"),
        );
        assert!(outcome.is_err(), "stale success must not reach completion");
        assert!(try_lock_resume("init-stale-success").unwrap().is_some());
    }
}

#[cfg(test)]
mod metadata_tests {
    use mvm_core::util::test_env::TestEnv;
    use mvm_runtime::vm::instance_snapshot::MachineLifecycleLock;

    #[test]
    fn init_completion_preserves_concurrently_updated_spec() {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let mut started: super::MachineSpec = serde_json::from_value(serde_json::json!({
            "schema_version": super::MACHINE_SPEC_SCHEMA_VERSION,
            "name": "init-config",
            "image": "alpine:latest",
            "net": false,
            "allow_host": [],
            "cpus": 2,
            "memory": "512M",
            "profile": "dev",
            "init": ["echo original"]
        }))
        .unwrap();
        let mut edited = started.clone();
        edited.cpus = 4;
        edited.init = vec!["echo next-start".into(), "echo updated".into()];
        super::save_machine_spec(&edited, false).unwrap();
        super::mark_machine_started(&mut started, "sha256:original".into());

        let _gate = MachineLifecycleLock::acquire(&started.name).unwrap();
        super::persist_start_metadata(&started).unwrap();

        edited.resolved_digest.clone_from(&started.resolved_digest);
        edited.last_started_at.clone_from(&started.last_started_at);
        assert_eq!(super::load_machine_spec(&started.name).unwrap(), edited);
        assert_eq!(
            started.init.len(),
            1,
            "receipt still describes executed init"
        );
    }
}

#[cfg(test)]
mod replace_tests {
    use super::ensure_not_running;

    #[test]
    fn replacing_a_running_machine_is_refused_and_names_the_stop_verb() {
        let err = ensure_not_running("web", true).unwrap_err().to_string();
        assert!(err.contains("machine stop web"), "{err}");
        assert!(ensure_not_running("web", false).is_ok());
    }
}
