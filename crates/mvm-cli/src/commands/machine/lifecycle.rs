use super::*;
use crate::commands::vm::up;
use crate::commands::{image, shared};

pub(super) fn run_start(cmd: MachineStartCmd) -> Result<()> {
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
                 Run `mvmctl machine ls` to list machines,
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
    })?;
    let action = reconcile_machine_spec(existing.as_ref(), &desired, args.create_flags.force)?;
    let spec = match action {
        SpecReconcile::Reuse => existing.expect("reuse implies an existing spec"),
        SpecReconcile::Create | SpecReconcile::Recreate { .. } => desired,
    };
    Ok((spec, action))
}

pub(super) fn start_machine(args: MachineStartArgs) -> Result<()> {
    let (mut spec, action) = resolve_start_spec(&args)?;
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
        return Ok(());
    }
    if machine_is_running(&args.name) {
        match action {
            SpecReconcile::Reuse => {
                println!("{}", already_running_notice(&args.name, args.json));
                return Ok(());
            }
            SpecReconcile::Recreate { ref changed } => {
                eprintln!(
                    "machine {:?}: config changed ({changed}) — stopping the old instance and recreating it",
                    args.name
                );
                stop_running_machine(&args.name);
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
    let effective_hypervisor = args
        .hypervisor
        .as_deref()
        .map(String::from)
        .unwrap_or_else(|| shared::resolve_effective_hypervisor("firecracker"));
    mvm_runtime::backend::AnyBackend::require_hypervisor_selectable(&effective_hypervisor)?;
    let receipt_input = machine_start_receipt_input(&spec, &effective_hypervisor)?;
    // A granted allow-list is what the gate enforces; the legacy
    // `net`/`allow_host` fields decide the policy only for a spec that granted
    // no egress. Deriving it from the same spec the plan is admitted under is
    // what keeps the enforced policy and the signed one from diverging.
    let network_policy = shared::enforced_network_policy(
        spec.grants.as_ref().and_then(|g| g.egress.as_ref()),
        spec.net,
        &spec.allow_host,
    )?
    .with_ai(spec.ai.clone());
    let (memory_mib, mem_initial_mib) =
        validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let volume_cfg = build_machine_volume_cfg(&spec.volumes)?;

    let (direct_boot_kernel, boot_label, boot_rootfs, boot_digest) = if std::env::var(
        "MVM_DIRECT_BOOT",
    )
    .as_deref()
        == Ok("1")
    {
        let kernel = std::env::var("MVM_KERNEL_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_DIRECT_BOOT requires MVM_KERNEL_PATH"))?;
        let rootfs = std::env::var("MVM_ROOTFS_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_DIRECT_BOOT requires MVM_ROOTFS_PATH"))?;
        (
            Some(kernel),
            "direct-boot".to_string(),
            std::path::PathBuf::from(rootfs),
            "direct-boot".to_string(),
        )
    } else {
        let (label, rootfs, digest) = if let Some(deployment_path) = &spec.deployment {
            let deployment =
                super::resolve_local_deployment(std::path::Path::new(deployment_path))?;
            (
                format!("deployment:{}", deployment.directory.display()),
                deployment.rootfs,
                deployment.boot_artifact_sha256,
            )
        } else if let Some(slot_hash) = &spec.manifest {
            let (_, _vmlinux, _initrd, rootfs, rev) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_for_slot(slot_hash)
                    .with_context(|| {
                        format!("loading manifest slot {slot_hash:?} for machine start")
                    })?;
            (
                format!("manifest:{slot_hash}"),
                std::path::PathBuf::from(rootfs),
                rev,
            )
        } else if let Some(image_ref) = &spec.image {
            let cached =
                image::resolve_or_pull_run_image(&image::oci_cache_root(), image_ref, false)?;
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
            (
                cached.reference.clone(),
                cached.rootfs_path.clone(),
                cached.resolved_digest.clone(),
            )
        } else {
            anyhow::bail!(
                "machine {name:?} spec has neither deployment, image, nor manifest — use `machine rm` to remove and recreate it",
                name = spec.name
            );
        };
        (None, label, rootfs, digest)
    };
    let kernel_path = match direct_boot_kernel {
        Some(k) => Some(k),
        None => up::resolve_kernel_pin_path(args.kernel_pin.is_some())?,
    };
    up::start_persistent_oci_machine(up::PersistentImageStartParams {
        name: &spec.name,
        image_label: &boot_label,
        resolved_digest: &boot_digest,
        rootfs_path: &boot_rootfs,
        profile: &spec.profile,
        cpus: spec.cpus,
        memory_mib,
        mem_initial_mib,
        volumes: &volume_cfg,
        network_policy,
        ports: &spec.ports,
        backend_name: &effective_hypervisor,
        no_supervisor: args.no_supervisor,
        kernel_path,
        agent_verb: spec.agent_verb.clone(),
        has_ad_hoc_argv: args.has_ad_hoc_argv,
        grants: spec.grants.clone(),
    })?;
    if !spec.init.is_empty()
        && let Err(err) = run_machine_init_commands(&spec.name, &spec.init)
    {
        stop_failed_machine_start(&spec.name, &effective_hypervisor);
        return Err(err);
    }
    mark_machine_started(&mut spec, boot_digest);
    let started_at = spec
        .last_started_at
        .clone()
        .expect("mark_machine_started always stamps last_started_at");
    if let Err(err) = overwrite_machine_spec(&spec) {
        tracing::warn!(error = %err, machine = %spec.name, "updating machine start metadata failed (non-fatal)");
    }
    let outcome = MachineStartReceiptOutcome {
        resolved_digest: spec
            .resolved_digest
            .clone()
            .expect("mark_machine_started always stamps resolved_digest"),
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

/// Gate `machine shell` / `machine exec` on the machine existing at all,
/// rather than on it having a persisted spec.
///
/// Both verbs reach the guest over the per-VM vsock socket under
/// `~/.mvm/vms/<name>/` and never read the spec they used to load — it was a
/// bare existence check. But `machine run` boots a transient VM that has a
/// live console and no spec, so that check refused, with "does not exist", a
/// machine `machine ls` was listing as running.
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
        "machine {name:?} does not exist. Run `mvmctl machine ls` to list machines, \
         or `mvmctl machine create {name} --image <ref>` to create one."
    )
}

pub(super) fn exec_machine(cli: &Cli, args: MachineExecArgs, cfg: &MvmConfig) -> Result<()> {
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
            Some(cmd) => console::console_pty_command(&args.name, cmd, Vec::new()),
            None => {
                console::console_interactive_with_env_and_argv(&args.name, Vec::new(), Vec::new())
            }
        };
    }
    console::run(
        cli,
        console::Args {
            name: args.name,
            command,
            force: args.force,
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

pub(super) fn machine_is_running(name: &str) -> bool {
    mvm_client::backend_is_running(&shared::resolve_effective_hypervisor("firecracker"), name)
}

pub(super) fn stop_running_machine(name: &str) {
    let hypervisor = shared::resolve_effective_hypervisor("firecracker");
    match mvm_client::backend_stop_by_name(&hypervisor, name) {
        Ok(()) => {
            if let Err(err) = crate::commands::vm::volume::release_volume_leases_for_vm(name) {
                tracing::warn!(error = %err, machine = name, "releasing volume leases after stop failed");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, machine = name, "stopping machine before recreate failed");
        }
    }
}
