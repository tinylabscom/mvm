use super::*;
use crate::commands::shared;

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
    mvm_client::launch::detached::resolve_spec(
        &args.name,
        Some(desired),
        existing,
        args.create_flags.force,
    )
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
    if let SpecReconcile::Recreate { ref changed } = action {
        eprintln!(
            "machine {:?}: config changed ({changed}) — stopping the old instance and recreating it",
            args.name
        );
    }
    if !mvm_client::launch::detached::persist_for_start(
        mvm_client::launch::detached::DetachedBoot {
            name: &args.name,
            spec: &spec,
            action,
            secret_refs: None,
        },
    )? {
        println!("{}", already_running_notice(&args.name, args.json));
        return Ok(());
    }
    enforce_dev_init_profile(&spec.profile, &spec.init)?;
    enforce_persisted_volume_profile(&spec.profile, &spec.volumes)?;
    let effective_hypervisor = args
        .hypervisor
        .as_deref()
        .map(String::from)
        .unwrap_or_else(|| shared::resolve_effective_hypervisor("firecracker"));
    let receipt_input = machine_start_receipt_input(&spec, &effective_hypervisor)?;
    let started = mvm_client::launch::machine_start::start_machine_spec(
        &spec,
        &prepared_start_host(&spec, args.kernel_pin.is_some())?,
        mvm_client::launch::machine_start::MachineStartParams {
            hypervisor: &effective_hypervisor,
            has_ad_hoc_argv: args.has_ad_hoc_argv,
        },
    )?;
    let boot_digest = started.resolved_digest;
    if !spec.init.is_empty()
        && let Err(err) = run_machine_init_commands(&spec.name, &spec.init)
    {
        stop_failed_machine_start(&spec.name, &effective_hypervisor);
        return Err(err);
    }
    let recorded =
        mvm_client::launch::machine_start::record_started_definition(&mut spec, boot_digest);
    let outcome = MachineStartReceiptOutcome {
        resolved_digest: recorded.resolved_digest,
        started_at: recorded.started_at,
        init_commands_executed: recorded.init_commands_executed,
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

pub(super) fn prepared_start_host(
    spec: &MachineSpec,
    kernel_pinned: bool,
) -> Result<mvm_client::launch::prepared_start::PreparedStartHost> {
    let volumes = build_machine_volume_cfg(&spec.volumes)?;
    Ok(mvm_client::launch::prepared_start::PreparedStartHost::new(
        &spec.profile,
        kernel_pinned,
        volumes,
    ))
}

/// Gate `machine shell` / `machine exec` on the machine existing at all,
/// rather than on it having a persisted spec.
///
/// Both verbs reach the guest over the per-VM vsock socket under
/// `~/.mvm/vms/<name>/` and never read the spec they used to load — it was a
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

pub(in crate::commands) fn exec_machine(
    cli: &Cli,
    args: MachineExecArgs,
    cfg: &MvmConfig,
) -> Result<()> {
    require_console_target(&args.name)?;
    if let Some(tool) = args.tool {
        anyhow::ensure!(
            !args.tty && !args.interactive,
            "declared tools require a non-interactive command"
        );
        anyhow::ensure!(
            !args.argv.is_empty(),
            "declared tools require a command after --"
        );
        return console::run_declared_command(&args.name, &tool, args.argv, args.force);
    }
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
                let exit_code = console::console_interactive(
                    &args.name,
                    console::ConsoleSessionOptions::default(),
                )?;
                if exit_code != 0 {
                    mvm_observability::exit(exit_code);
                }
                Ok(())
            }
        };
    }
    console::run(
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
