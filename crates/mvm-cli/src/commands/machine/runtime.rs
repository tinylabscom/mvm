use super::*;
use crate::commands::shared;
use crate::commands::vm::invoke;
use mvm_client::MvmClient;

pub(super) fn resolve_persistent_spec(
    args: &MachineRunArgs,
    name: &str,
    existing: Option<MachineSpec>,
    resolved_manifest_slot: Option<&str>,
) -> Result<(MachineSpec, SpecReconcile)> {
    let direct_boot = std::env::var("MVM_DIRECT_BOOT").as_deref() == Ok("1");
    let has_source = args.image.is_some()
        || args.manifest.is_some()
        || resolved_manifest_slot.is_some()
        || direct_boot;
    if !has_source {
        return match existing {
            Some(spec) => Ok((spec, SpecReconcile::Reuse)),
            None => anyhow::bail!(
                "machine {name:?} does not exist; pass --image, --manifest, or --flake to create it"
            ),
        };
    }
    let desired = machine_run_spec(args, name.to_string(), resolved_manifest_slot)?;
    let action = reconcile_machine_spec(existing.as_ref(), &desired, args.force)?;
    let spec = match action {
        SpecReconcile::Reuse => existing.expect("reuse implies an existing spec"),
        SpecReconcile::Create | SpecReconcile::Recreate { .. } => desired,
    };
    Ok((spec, action))
}

fn run_persistent(
    cli: &Cli,
    args: MachineRunArgs,
    cfg: &MvmConfig,
    resolved_flake_slot: Option<&str>,
) -> Result<()> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "warning: piped stdin is ignored for a persistent (-d/--name) machine; \
             use a transient run or --entrypoint to deliver stdin"
        );
    }
    let name = resolve_machine_run_name(&args)?;
    let existing = load_machine_spec(&name).ok();
    let (spec, action) = resolve_persistent_spec(&args, &name, existing, resolved_flake_slot)?;

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

    let booted = persist_and_boot_machine(
        &name,
        &spec,
        action,
        MachineStartArgs {
            name: name.clone(),
            receipt: args.receipt.clone(),
            json: args.json,
            dry_run: false,
            quiet: false,
            hypervisor: args.hypervisor.clone(),
            no_supervisor: args.no_supervisor,
            kernel_pin: args.kernel_pin.clone(),
            has_ad_hoc_argv: !args.argv.is_empty(),
        },
    )?;
    if !booted && !args.json && !args.up_json {
        println!("machine {name} already running");
    }

    if let Some(dur_str) = args.ttl.as_deref() {
        apply_machine_ttl(&name, dur_str)?;
    }

    run_persistent_post_start(cli, cfg, &args, &name)
}

fn persist_and_boot_machine(
    name: &str,
    spec: &MachineSpec,
    action: SpecReconcile,
    start: MachineStartArgs,
) -> Result<bool> {
    match action {
        SpecReconcile::Reuse => {}
        SpecReconcile::Create => save_machine_spec(spec, false)?,
        SpecReconcile::Recreate { changed } => {
            eprintln!(
                "machine {name:?}: config changed ({changed}) — stopping the old instance and recreating it"
            );
            lifecycle::stop_running_machine(name);
            overwrite_machine_spec(spec)?;
        }
    }
    if lifecycle::machine_is_running(name) {
        Ok(false)
    } else {
        lifecycle::start_machine(start)?;
        Ok(true)
    }
}

fn run_persistent_post_start(
    cli: &Cli,
    cfg: &MvmConfig,
    args: &MachineRunArgs,
    name: &str,
) -> Result<()> {
    if !args.argv.is_empty() {
        if !shared::wait_for_guest_agent(name, 30) {
            anyhow::bail!("guest agent for {name:?} not reachable to run the command");
        }
        return console::run(
            cli,
            console::Args {
                name: name.to_string(),
                command: Some(machine_exec_command(&args.argv)),
                force: false,
                env: Vec::new(),
                pty_argv: Vec::new(),
            },
            cfg,
        );
    }
    if args.up_json {
        let build_mode_str = resolve_build_mode_for_envelope(args, name);
        let envelope = serde_json::json!({
            "schema_version": 1,
            "vm_id": name,
            "build_mode": build_mode_str,
        });
        println!("{envelope}");
        return Ok(());
    }
    if !args.json {
        if args.detach {
            println!("{name}");
        } else {
            println!("machine {name} is up; attach with `machine shell {name}`");
        }
    }
    Ok(())
}

fn apply_machine_ttl(name: &str, dur_str: &str) -> Result<()> {
    // Duration parsing stays a CLI concern; the facade's `set_ttl` applies the
    // resolved `expires_at` to the host registry (same op the `set-ttl` verb
    // routes through), so the machine path stays off the registry internals.
    let dur = mvm_core::crypto::policy::parse_ttl(dur_str)
        .with_context(|| format!("Invalid --ttl value {dur_str:?}"))?;
    let expires_at = mvm_core::util::time::utc_plus_duration(dur);
    let client = mvm_client::LocalBackend::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for machine TTL")?;
    match runtime
        .block_on(client.set_ttl(&mvm_client::MachineId(name.to_string()), Some(expires_at)))
    {
        Ok(()) => Ok(()),
        Err(mvm_client::MvmError::NotFound { .. }) => {
            anyhow::bail!("machine {name:?} is not registered")
        }
        Err(e) => Err(anyhow::anyhow!("{e}"))
            .with_context(|| format!("Failed to set TTL for machine {name:?}")),
    }
}

fn resolve_build_mode_for_envelope(args: &MachineRunArgs, name: &str) -> &'static str {
    resolve_machine_build_mode(args.manifest.as_deref(), name)
}

/// Resolve a machine's `build_mode` (`"dev"` / `"prod"`) from its manifest
/// slot's template revision, falling back to the runtime accessibility flag.
/// Shared by the boot-time SDK envelope and the `machine ls --json` listing so
/// an attach-from-a-fresh-process client reads the same value the boot path
/// stamps. Fails closed on `"prod"` — only an explicitly dev-built template or
/// an accessible (dev) runtime resolves to `"dev"`.
pub(super) fn resolve_machine_build_mode(manifest: Option<&str>, name: &str) -> &'static str {
    if let Some(manifest) = manifest {
        let slot_name = manifest
            .trim_end_matches('/')
            .split('/')
            .next_back()
            .unwrap_or(manifest);
        if let Ok(Some(revision)) =
            mvm_runtime::vm::template::lifecycle::template_load_current_revision(slot_name)
        {
            return match revision.build_mode.as_deref() {
                Some("dev") => "dev",
                _ => "prod",
            };
        }
    }
    match mvm_runtime::vm::runtime_meta::read(name) {
        Ok(Some(meta)) if meta.accessible => "dev",
        _ => "prod",
    }
}

fn run_entrypoint_action(args: MachineRunArgs, resolved_flake_slot: Option<String>) -> Result<()> {
    if args.image.is_some() {
        anyhow::bail!(
            "machine run --entrypoint dispatches a manifest/flake image's baked \
             /etc/mvm/entrypoint; an OCI --image runs its own command via the \
             default argv action — drop --entrypoint"
        );
    }
    let source = if args.attach {
        resolve_machine_run_name(&args)?
    } else if let Some(slot) = resolved_flake_slot {
        slot
    } else if let Some(manifest) = args.manifest.clone() {
        manifest
    } else {
        anyhow::bail!(
            "machine run --entrypoint needs `--manifest <path>` or `--flake <path>` \
             (or `--attach --name <NAME>` to dispatch into a running machine)"
        );
    };
    let (memory_mib, _) = validate_machine_memory(&args.memory, None)?;
    // Resolve `--net` / `--allow-host` into the egress policy exactly as the
    // transient argv path does, so a baked entrypoint enforces the same posture.
    let network_policy = shared::resolve_run_network_policy(args.net, &args.allow_host)?;
    use std::io::IsTerminal as _;
    let stdin = invoke::read_auto_stdin(std::io::stdin().is_terminal())?;
    invoke::run_entrypoint(invoke::EntrypointCall {
        source,
        stdin,
        timeout: args.timeout.unwrap_or(30),
        cpus: args.cpus,
        memory_mib,
        from_workload_ir: args.from_workload_ir.clone(),
        agent_verb_override: args.agent_verb.clone(),
        reset: args.reset,
        keep_alive: args.persistent(),
        keep_alive_dev: false,
        session: None,
        r#fn: None,
        attach: args.attach,
        network_policy,
    })
}

pub(super) fn run_dispatch(cli: &Cli, mut args: MachineRunArgs, cfg: &MvmConfig) -> Result<()> {
    let resolved_flake_slot = if let Some(flake_ref) = args.flake.take() {
        let slot_hash = build::build_flake_to_slot(&flake_ref, args.flake_profile.as_deref())?;
        args.manifest = Some(slot_hash.clone());
        Some(slot_hash)
    } else {
        None
    };

    if args.entrypoint {
        return run_entrypoint_action(args, resolved_flake_slot);
    }

    let mode = args.resolve_mode()?;
    let warm_pool_size = mode.warm_pool_size(None, args.name.is_some());
    tracing::debug!(?mode, warm_pool_size, "machine run warm-pool eligibility");
    match mode {
        MachineRunMode::Transient => {
            if let Some(slot) = resolved_flake_slot {
                args.manifest = Some(slot);
            }
            let mut run_args = args.into_run_args();
            run_args.warm_pool_size = warm_pool_size;
            use std::io::IsTerminal as _;
            run_args.stdin = invoke::read_auto_stdin(std::io::stdin().is_terminal())?;
            run_secure(cli, run_args, cfg)
        }
        MachineRunMode::Persistent => {
            run_persistent(cli, args, cfg, resolved_flake_slot.as_deref())
        }
        MachineRunMode::InteractiveTransient => {
            use std::io::IsTerminal as _;
            require_tty(std::io::stdin().is_terminal())?;
            if let Some(slot) = resolved_flake_slot {
                args.manifest = Some(slot);
            }
            let mut run_args = args.into_run_args();
            run_args.pty = true;
            run_args.warm_pool_size = warm_pool_size;
            run_args.stdin = invoke::read_auto_stdin(std::io::stdin().is_terminal())?;
            run_secure(cli, run_args, cfg)
        }
    }
}

pub(in crate::commands) fn boot_persistent_by_name(
    cli: &Cli,
    cfg: &MvmConfig,
    name: String,
    flake: Option<String>,
    kernel_pin: Option<String>,
    hypervisor: Option<String>,
) -> Result<()> {
    run_dispatch(
        cli,
        MachineRunArgs {
            name: Some(name),
            flake,
            kernel_pin,
            hypervisor,
            detach: true,
            image: None,
            manifest: None,
            runtime_pack: false,
            flake_profile: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            profile: RunProfile::Standard,
            agent_verb: Vec::new(),
            volume: Vec::new(),
            env: Vec::new(),
            timeout: None,
            receipt: None,
            json: false,
            dry_run: false,
            tty: false,
            interactive: false,
            force: false,
            no_supervisor: false,
            up_json: false,
            ttl: None,
            healthcheck: None,
            health_interval: 30,
            health_timeout: 5,
            health_retries: 3,
            health_start_period: 0,
            entrypoint: false,
            fresh: false,
            reset: false,
            from_workload_ir: None,
            attach: false,
            argv: Vec::new(),
            host_service: Vec::new(),
        },
        cfg,
    )
}
