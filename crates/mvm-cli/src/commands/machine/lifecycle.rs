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

pub(super) fn start_machine(args: MachineStartArgs) -> Result<()> {
    let mut spec = ensure_machine_spec_exists(&args.name)?;
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
        println!("{}", already_running_notice(&args.name, args.json));
        return Ok(());
    }
    enforce_dev_init_profile(&spec.profile, &spec.init)?;
    let effective_hypervisor = args
        .hypervisor
        .as_deref()
        .map(String::from)
        .unwrap_or_else(|| shared::resolve_effective_hypervisor("firecracker"));
    let receipt_input = machine_start_receipt_input(&spec, &effective_hypervisor)?;
    let ssh_auth_sock = if spec.ssh_agent {
        Some(ssh_auth_sock_from_env()?)
    } else {
        None
    };
    let network_policy = shared::resolve_run_network_policy(spec.net, &spec.allow_host)?;
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
        let (label, rootfs, digest) = if let Some(slot_hash) = &spec.manifest {
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
                "machine {name:?} spec has neither image nor manifest — use `machine rm` to remove and recreate it",
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
        auth: machine_start_plan_auth_policy(&spec),
        backend_name: &effective_hypervisor,
        no_supervisor: args.no_supervisor,
        kernel_path,
        agent_verb: spec.agent_verb.clone(),
        has_ad_hoc_argv: args.has_ad_hoc_argv,
    })?;
    if let Some(host_sock) = ssh_auth_sock.as_deref()
        && let Err(err) =
            configure_machine_ssh_agent_forwarding(&spec.name, &effective_hypervisor, host_sock)
    {
        stop_failed_machine_start(&spec.name, &effective_hypervisor);
        return Err(err);
    }
    if !spec.init.is_empty()
        && let Err(err) = run_machine_init_commands(&spec.name, &spec.init, spec.ssh_agent)
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

pub(super) fn exec_machine(cli: &Cli, args: MachineExecArgs, cfg: &MvmConfig) -> Result<()> {
    let spec = ensure_machine_spec_exists(&args.name)?;
    let command = if args.argv.is_empty() {
        None
    } else {
        Some(machine_exec_command(&args.argv))
    };
    if args.tty || args.interactive {
        use std::io::IsTerminal as _;
        require_tty(std::io::stdin().is_terminal())?;
        console::enforce_accessible_gate(&args.name, args.force)?;
        let env = machine_console_env(spec.ssh_agent);
        return match command {
            Some(cmd) => console::console_pty_command(&args.name, cmd, env),
            None => console::console_interactive_with_env_and_argv(&args.name, env, Vec::new()),
        };
    }
    console::run(
        cli,
        console::Args {
            name: args.name,
            command,
            force: args.force,
            env: machine_console_env(spec.ssh_agent),
            pty_argv: Vec::new(),
        },
        cfg,
    )
}

pub(super) fn shell_machine(cli: &Cli, args: MachineShellArgs, cfg: &MvmConfig) -> Result<()> {
    let spec = ensure_machine_spec_exists(&args.name)?;
    console::run(
        cli,
        console::Args {
            name: args.name,
            command: None,
            force: args.force,
            env: machine_console_env(spec.ssh_agent),
            pty_argv: Vec::new(),
        },
        cfg,
    )
}

pub(super) fn stop_machine(cli: &Cli, args: MachineStopArgs, cfg: &MvmConfig) -> Result<()> {
    if !args.yes {
        use std::io::IsTerminal as _;
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
        let confirmed = std::io::stdin().is_terminal() && crate::ui::confirm(&prompt);
        if !confirmed {
            println!("aborted");
            return Ok(());
        }
    }
    if args.all {
        return down::run(cli, down::Args { name: None }, cfg);
    }
    let mut had_err = false;
    for name in &args.names {
        reap_proxy(name);
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

pub(super) fn machine_is_running(name: &str) -> bool {
    let backend = AnyBackend::from_hypervisor(&shared::resolve_effective_hypervisor("firecracker"));
    matches!(
        backend.status(&VmId(name.to_string())),
        Ok(VmStatus::Running)
    )
}

pub(super) fn stop_running_machine(name: &str) {
    reap_proxy(name);
    let backend = AnyBackend::from_hypervisor(&shared::resolve_effective_hypervisor("firecracker"));
    if let Err(err) = backend.stop(&VmId(name.to_string())) {
        tracing::warn!(error = %err, machine = name, "stopping machine before recreate failed");
    }
}
