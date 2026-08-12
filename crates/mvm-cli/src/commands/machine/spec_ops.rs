use super::*;

pub(super) fn create_machine(args: MachineCreateArgs) -> Result<()> {
    let json = args.json;
    let force = args.force;
    let spec = args.into_spec()?;
    save_machine_spec(&spec, force)?;
    mvm_core::audit_emit!(
        ConfigChange,
        vm: &spec.name,
        "action=machine.create force={force}"
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&spec)?);
    } else {
        println!("created machine {}", spec.name);
    }
    Ok(())
}

/// A machine's persisted spec plus what its last boot actually achieved.
///
/// The spec carries the *request* — `--cpu-limit 1500` is a number a user
/// typed — and reporting only that is what let a genuinely unbounded run look
/// identical to a bounded one. The achieved tier is added alongside rather than
/// replacing it: an operator needs both to see a degradation. Absent when no
/// boot recorded one, which is not the same answer as "unenforced".
#[derive(Debug, Clone, Serialize)]
pub(super) struct MachineInspectView<'a> {
    #[serde(flatten)]
    pub(super) spec: &'a MachineSpec,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) enforced_grants: Option<mvm_contract::protocol::resource_controls::EnforcedGrants>,
}

/// The display line for a machine's enforced-CPU tier, or `None` when no boot
/// has recorded one. Split out so the rendering is testable without a boot.
pub(super) fn enforced_cpu_line(
    enforced: Option<&mvm_contract::protocol::resource_controls::EnforcedGrants>,
) -> Option<String> {
    let enforced = enforced?;
    Some(format!(
        "enforced-cpu: {} ({})",
        enforced.cpu.label(),
        if enforced.cpu.is_enforced() {
            "bounded"
        } else {
            "not bounded"
        }
    ))
}

pub(super) fn inspect_machine(args: MachineInspectArgs) -> Result<()> {
    let spec = load_machine_spec(&args.name)?;
    let enforced = mvm_client::enforced_grants_of(&spec.name);
    if args.json {
        let view = MachineInspectView {
            spec: &spec,
            enforced_grants: enforced,
        };
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else {
        println!("name: {}", spec.name);
        if let Some(image) = spec.image.as_deref() {
            println!("image: {}", image);
        }
        if let Some(manifest) = spec.manifest.as_deref() {
            println!("manifest: {}", manifest);
        }
        if let Some(deployment) = spec.deployment.as_deref() {
            println!("deployment: {}", deployment);
        }
        if let Some(resolved_digest) = spec.resolved_digest.as_deref() {
            println!("resolved-digest: {resolved_digest}");
        }
        let readiness = mvm_client::readiness_of(&spec.name);
        println!("health: {}", health_cell(readiness.as_ref()));
        println!("net: {}", spec.net);
        println!("allow-host: {}", spec.allow_host.join(","));
        println!("cpus: {}", spec.cpus);
        println!("memory: {}", spec.memory);
        if let Some(mem_initial) = spec.mem_initial.as_deref() {
            println!("mem-initial: {mem_initial}");
        }
        println!("profile: {}", spec.profile);
        if let Some(grants) = spec.grants.as_ref()
            && let Some(mvm_contract::grants::CpuGrant::Share { millicores }) = grants.cpu
        {
            println!("cpu-limit: {millicores} millicores (requested)");
        }
        if let Some(line) = enforced_cpu_line(enforced.as_ref()) {
            println!("{line}");
        }
        if !spec.volumes.is_empty() {
            println!("volumes: {}", spec.volumes.join(","));
        }
        if !spec.init.is_empty() {
            println!("init: {}", spec.init.join(" && "));
        }
        if let Some(created_at) = spec.created_at.as_deref() {
            println!("created-at: {created_at}");
        }
        if let Some(last_started_at) = spec.last_started_at.as_deref() {
            println!("last-started-at: {last_started_at}");
        }
    }
    Ok(())
}

pub(super) fn remove_machine(args: MachineRemoveArgs) -> Result<()> {
    let json = args.json;
    let targets = resolve_remove_targets(args.all, &args.names)?;
    if targets.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("no machines");
        }
        return Ok(());
    }
    if !args.yes {
        use std::io::IsTerminal as _;
        let prompt = if targets.len() == 1 {
            format!("Remove machine {:?}?", targets[0])
        } else {
            format!(
                "Remove {} machines ({})?",
                targets.len(),
                targets.join(", ")
            )
        };
        let confirmed = std::io::stdin().is_terminal() && crate::ui::confirm(&prompt);
        if !confirmed {
            println!("aborted");
            return Ok(());
        }
    }
    for name in &targets {
        validate_machine_name(name)?;
        if !config::machine_state_dir(name).exists() {
            anyhow::bail!(
                "machine {name:?} does not exist. Run `mvmctl machine ls` to list machines."
            );
        }
    }
    if !args.force {
        let running: Vec<String> = targets
            .iter()
            .filter(|name| lifecycle::machine_is_running(name))
            .cloned()
            .collect();
        if let Some(msg) = rm_running_refusal(&running) {
            anyhow::bail!(msg);
        }
    }
    let mut summaries = Vec::with_capacity(targets.len());
    for name in &targets {
        if args.force && lifecycle::machine_is_running(name) {
            lifecycle::stop_running_machine(name);
        }
        let summary = remove_machine_spec(name, true)?;
        mvm_core::audit_emit!(ConfigChange, vm: &summary.name, "action=machine.rm");
        if !json {
            println!("removed machine {}", summary.name);
        }
        summaries.push(summary);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&summaries)?);
    }
    Ok(())
}

pub(super) fn run_reconfigure(args: MachineReconfigureArgs) -> Result<()> {
    let existing = load_machine_spec(&args.name)?;
    let patch = patch_from_args(&args)?;
    let desired = apply_patch(existing.clone(), &patch);

    validate_machine_memory(&desired.memory, desired.mem_initial.as_deref())
        .context("invalid machine memory after reconfigure")?;

    let changed = machine_config_diff(&existing, &desired);
    if changed.is_empty() {
        println!("machine {:?}: no changes", args.name);
        return Ok(());
    }

    let was_running = lifecycle::machine_is_running(&args.name);
    overwrite_machine_spec(&desired)?;
    mvm_core::audit_emit!(
        ConfigChange,
        vm: &args.name,
        "action=machine.reconfigure changed={changed}"
    );

    if was_running {
        eprintln!(
            "reconfiguring {:?} ({changed}): stopping the old instance and restarting",
            args.name
        );
        lifecycle::stop_running_machine(&args.name);
        lifecycle::start_machine(MachineStartArgs {
            name: args.name.clone(),
            receipt: None,
            json: false,
            dry_run: false,
            quiet: false,
            hypervisor: args.hypervisor.clone(),
            no_supervisor: false,
            kernel_pin: None,
            has_ad_hoc_argv: false,
        })?;
    } else {
        println!(
            "machine {:?} reconfigured ({changed}); change applies on next `machine start`",
            args.name
        );
    }
    Ok(())
}
