use super::*;
use crate::commands::shared;
use crate::commands::vm::{invoke, logs};
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
        || args.deployment.is_some()
        || resolved_manifest_slot.is_some()
        || direct_boot;
    if !has_source {
        return match existing {
            Some(spec) => Ok((spec, SpecReconcile::Reuse)),
            None => anyhow::bail!(
                "machine {name:?} does not exist; pass --image, --manifest, --deployment, or --flake to create it"
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
    match post_start_action(args) {
        PostStart::Forward => crate::commands::vm::forward::forward_ports(name, &args.port),
        PostStart::Envelope => {
            let build_mode_str = resolve_build_mode_for_envelope(args, name);
            let envelope = serde_json::json!({
                "schema_version": 1,
                "vm_id": name,
                "build_mode": build_mode_str,
            });
            println!("{envelope}");
            Ok(())
        }
        PostStart::Quiet => Ok(()),
        PostStart::PrintId => {
            println!("{name}");
            Ok(())
        }
        PostStart::Attach => attach_to_output(name),
    }
}

/// What `machine run` does once a persistent machine is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PostStart {
    /// Keep this CLI attached as the owner of the requested host port forwards.
    Forward,
    /// `--up-json`: the SDK boot envelope, and nothing else on stdout.
    Envelope,
    /// `--json`: the caller is parsing stdout, so say nothing extra.
    Quiet,
    /// `-d`/`--detach`: the machine id, for a caller that will come back later.
    PrintId,
    /// The default: follow the machine's output.
    Attach,
}

/// Resolve the post-start behaviour from the flags alone, so the choice is
/// testable without booting anything.
pub(super) fn post_start_action(args: &MachineRunArgs) -> PostStart {
    if !args.port.is_empty() {
        PostStart::Forward
    } else if args.up_json {
        PostStart::Envelope
    } else if args.json {
        PostStart::Quiet
    } else if args.detach {
        PostStart::PrintId
    } else {
        PostStart::Attach
    }
}

/// Follow a freshly-started machine's output.
///
/// Replaces a hint pointing at `machine shell`, which is the dev-only
/// interactive path a sealed production machine bars outright — so the advice
/// was unusable exactly where output matters most. Attaching to the capture
/// works on every backend and in production, because the host owns it.
///
/// A machine with no capture is a note, not a failure: the machine booted, and
/// that is what `machine run` was asked to do.
fn attach_to_output(name: &str) -> Result<()> {
    // Say what attaching means before it blocks. The machine is persistent, so
    // interrupting detaches from the output and leaves it running — the
    // opposite of what Ctrl-C does to a foreground transient run, and worth
    // stating rather than leaving to be discovered.
    eprintln!("attached to machine {name}; press Ctrl-C to detach (it keeps running)");
    match logs::attach(name)? {
        logs::AttachOutcome::Followed => Ok(()),
        logs::AttachOutcome::NoCapture => {
            eprintln!(
                "note: machine {name} has no output capture to attach to; \
                 `machine logs {name}` will show it once one exists"
            );
            Ok(())
        }
    }
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

/// Resolve a machine's `build_mode` (`"dev"` / `"prod"`) for the boot-time
/// SDK envelope. Delegates to the shared inventory service's fail-closed
/// posture resolution so this envelope, `machine ls --json`, and every other
/// inventory consumer read the same value — only an explicitly dev-built
/// template or an accessible (dev) runtime resolves to `"dev"`.
pub(super) fn resolve_machine_build_mode(manifest: Option<&str>, name: &str) -> &'static str {
    mvm_client::inventory::resolve_workload_posture(manifest, name).label()
}

fn run_entrypoint_action(args: MachineRunArgs, resolved_flake_slot: Option<String>) -> Result<()> {
    if args.deployment.is_some() {
        anyhow::bail!(
            "machine run --entrypoint does not accept --deployment; use a manifest or flake source"
        );
    }
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
    let stdin = resolve_entrypoint_stdin(args.stdin.as_deref())?;
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

/// Turn `--stdin` into what the entrypoint call should do about stdin.
///
/// Three shapes, and the flag's value is what picks between them:
/// - absent — read a piped stdin to the end and send it as one payload, which
///   is what this command has always done and what nothing should change for a
///   caller who did not ask;
/// - `-` — stream this process's own stdin, which is a different contract with
///   the guest (its stdin stays open, EOF is something the host sends) and so
///   needs the input grant on the signed plan;
/// - a path — read that file and send it as one payload; a file has an end the
///   host already knows, so there is nothing to stream.
fn resolve_entrypoint_stdin(spec: Option<&str>) -> Result<invoke::EntrypointStdin> {
    resolve_entrypoint_stdin_with(spec, || {
        use std::io::IsTerminal as _;
        invoke::read_auto_stdin(std::io::stdin().is_terminal())
    })
}

/// The mapping itself, with the one arm that reads this process's own stdin
/// supplied rather than reached for — so every shape of the flag is decidable
/// without a real fd behind it.
fn resolve_entrypoint_stdin_with(
    spec: Option<&str>,
    piped: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<invoke::EntrypointStdin> {
    match spec {
        Some("-") => Ok(invoke::EntrypointStdin::Streaming),
        Some(path) => Ok(invoke::EntrypointStdin::OneShot(
            std::fs::read(path)
                .with_context(|| format!("reading the entrypoint's stdin payload from {path}"))?,
        )),
        None => Ok(invoke::EntrypointStdin::OneShot(piped()?)),
    }
}

/// Whether the launch's workload declared that it needs a real in-guest IP
/// stack.
///
/// Reads the same `network.raw_ip_stack` field the admission path reads, so
/// a workload cannot be admitted for one transport and booted on another.
/// Absent IR, or IR with no app declaring it, means no: silence must never
/// select the tunnel, because it is the weaker posture.
fn workload_needs_raw_ip_stack(workload_ir: Option<&std::path::Path>) -> Result<bool> {
    let Some(workload) = crate::commands::vm::up::load_workload_ir(workload_ir)? else {
        return Ok(false);
    };
    Ok(workload
        .apps
        .iter()
        .any(|app| app.network.as_ref().is_some_and(|n| n.raw_ip_stack)))
}

pub(super) fn run_dispatch(cli: &Cli, mut args: MachineRunArgs, cfg: &MvmConfig) -> Result<()> {
    let resolved_flake_slot = if let Some(flake_ref) = args.flake.take() {
        let slot_hash = build::build_flake_to_slot(&flake_ref, args.flake_profile.as_deref())?;
        args.manifest = Some(slot_hash.clone());
        Some(slot_hash)
    } else {
        None
    };
    let local_deployment = args
        .deployment
        .as_deref()
        .map(super::resolve_local_deployment)
        .transpose()?;

    // Settle the networking configuration before any build or boot work.
    // There is no mode to choose: the derivation picks the strongest
    // transport this workload and this host can actually support.
    //
    // The declaration lives in the workload IR, so a run that carries one
    // is the only run that can ask for the tunnel. An ad-hoc `--image`
    // launch has no workload to declare anything and keeps the
    // socket-aware default.
    let network_mode = super::preflight_network(workload_needs_raw_ip_stack(
        args.from_workload_ir.as_deref(),
    )?)?;
    tracing::debug!(?network_mode, "derived machine networking");

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
            // The mode settled above, not a re-derivation: one value reaches
            // both the transport decision and the signed plan.
            run_args.network_mode = network_mode;
            run_args.warm_pool_size = warm_pool_size;
            use std::io::IsTerminal as _;
            run_args.stdin = invoke::read_auto_stdin(std::io::stdin().is_terminal())?;
            let source = local_deployment
                .as_ref()
                .map(super::local_deployment_image_source)
                .transpose()?;
            run_secure_with_source(cli, run_args, cfg, source)
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
            // The mode settled above, not a re-derivation: one value reaches
            // both the transport decision and the signed plan.
            run_args.network_mode = network_mode;
            run_args.pty = true;
            run_args.warm_pool_size = warm_pool_size;
            run_args.stdin = invoke::read_auto_stdin(std::io::stdin().is_terminal())?;
            let source = local_deployment
                .as_ref()
                .map(super::local_deployment_image_source)
                .transpose()?;
            run_secure_with_source(cli, run_args, cfg, source)
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
            // Booting by name carries no caller stdin, so it requests no input
            // grant and the plan stays ungranted.
            stdin: None,
            detach: true,
            image: None,
            manifest: None,
            deployment: None,
            runtime_pack: false,
            flake_profile: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            cpu_limit: None,
            grants_file: None,
            memory: "512M".to_string(),
            profile: RunProfile::Dev,
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
            port: Vec::new(),
        },
        cfg,
    )
}

#[cfg(test)]
mod entrypoint_stdin_tests {
    use super::*;

    /// Name the variant the flag resolved to. A payload and a stream are
    /// different contracts with the guest, and only one of them puts the input
    /// grant on the signed plan — so "it parsed" is not the property.
    fn described(resolved: &invoke::EntrypointStdin) -> String {
        match resolved {
            invoke::EntrypointStdin::Streaming => "streaming".to_string(),
            invoke::EntrypointStdin::OneShot(bytes) => {
                format!("one-shot {:?}", String::from_utf8_lossy(bytes))
            }
        }
    }

    fn nothing_piped() -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    /// `expect_err` needs `Debug` on the success type, and the success type
    /// here carries the caller's own stdin — which has no business in a panic
    /// message. Name the variant instead.
    fn refusal(resolved: Result<invoke::EntrypointStdin>, why: &str) -> anyhow::Error {
        match resolved {
            Err(error) => error,
            Ok(resolved) => panic!("{why}, got {}", described(&resolved)),
        }
    }

    #[test]
    fn a_dash_asks_for_a_live_stream_rather_than_a_payload() {
        // Resolving this to a payload would disable the feature outright: no
        // grant requested, nothing streamed, and a green suite — the caller's
        // only symptom is a workload that never sees what they typed.
        let resolved =
            resolve_entrypoint_stdin_with(Some("-"), nothing_piped).expect("`-` needs no fd");
        assert!(
            matches!(resolved, invoke::EntrypointStdin::Streaming),
            "`--stdin -` must stream, got {}",
            described(&resolved)
        );
    }

    #[test]
    fn a_path_is_read_once_and_sent_as_a_payload() {
        // A file has an end the host already knows, so there is nothing to
        // stream and nothing to ask a grant for.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("payload.json");
        std::fs::write(&path, b"[[1], {}]").expect("write");
        let resolved = resolve_entrypoint_stdin_with(Some(&path.to_string_lossy()), nothing_piped)
            .expect("the file exists");
        match resolved {
            invoke::EntrypointStdin::OneShot(bytes) => assert_eq!(bytes, b"[[1], {}]"),
            other => panic!("a path must send a payload, got {}", described(&other)),
        }
    }

    #[test]
    fn an_absent_flag_keeps_the_piped_payload_it_always_had() {
        // Inferring a stream from a piped stdin would move every existing
        // piped call onto the granted path without anybody asking for it.
        let resolved = resolve_entrypoint_stdin_with(None, || Ok(b"piped in".to_vec()))
            .expect("the piped read succeeded");
        match resolved {
            invoke::EntrypointStdin::OneShot(bytes) => assert_eq!(bytes, b"piped in"),
            other => panic!("an absent flag must not stream, got {}", described(&other)),
        }
    }

    #[test]
    fn a_stdin_path_that_does_not_exist_fails_rather_than_sending_nothing() {
        // Silently sending an empty payload would call the entrypoint with the
        // wrong input and report success.
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("absent.json");
        let error = refusal(
            resolve_entrypoint_stdin_with(Some(&missing.to_string_lossy()), nothing_piped),
            "a missing payload file must not resolve",
        );
        assert!(
            format!("{error:#}").contains("absent.json"),
            "the refusal must name the file it could not read: {error:#}"
        );
    }

    #[test]
    fn a_failed_piped_read_fails_the_call() {
        let error = refusal(
            resolve_entrypoint_stdin_with(None, || {
                Err(anyhow::anyhow!("stdin payload exceeds the limit"))
            }),
            "an unreadable stdin must not resolve to an empty payload",
        );
        assert!(
            format!("{error:#}").contains("exceeds the limit"),
            "{error:#}"
        );
    }
}

#[cfg(test)]
mod raw_ip_stack_tests {
    use super::*;

    /// Build the fixture from the real IR types rather than hand-rolled
    /// JSON, so it cannot drift from the schema it is meant to exercise.
    fn write_ir(
        dir: &std::path::Path,
        network: Option<mvm_contract::ir::Network>,
    ) -> std::path::PathBuf {
        use mvm_contract::ir::*;
        let workload = Workload {
            schema_version: "0.1".into(),
            id: "l3-witness".into(),
            apps: vec![App {
                name: "probe".into(),
                source: Source::LocalPath {
                    path: ".".into(),
                    include: vec!["**".into()],
                    exclude: vec![],
                },
                image: Image::NixPackages {
                    packages: vec!["python312".into()],
                },
                entrypoints: vec![],
                env: Default::default(),
                mounts: vec![],
                network,
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 256,
                    rootfs_size_mb: 512,
                },
                dependencies: None,
                threat_tier: Default::default(),
                addons: Default::default(),
                hooks: Default::default(),
                files: Default::default(),
                health_check: Default::default(),
            }],
            volumes: vec![],
            extensions: Default::default(),
        };
        let path = dir.join("workload.json");
        std::fs::write(&path, serde_json::to_vec(&workload).expect("serialize")).expect("write");
        path
    }

    fn net(raw_ip_stack: bool) -> mvm_contract::ir::Network {
        mvm_contract::ir::Network {
            mode: mvm_contract::ir::NetworkMode::Bridge,
            ports: vec![],
            egress: None,
            peers: vec![],
            dns: None,
            raw_ip_stack,
        }
    }

    #[test]
    fn a_launch_with_no_workload_ir_keeps_the_socket_aware_default() {
        // An ad-hoc `--image` run has nothing to declare a need.
        assert!(!workload_needs_raw_ip_stack(None).expect("no ir"));
    }

    #[test]
    fn a_workload_that_declares_the_need_reaches_the_boot_path() {
        // The regression this pins: the boot path once passed a hardcoded
        // `false`, so a workload admitted for the tunnel booted on the
        // socket-aware transport instead.
        let dir = tempfile::tempdir().expect("temp dir");
        let ir = write_ir(dir.path(), Some(net(true)));
        assert!(workload_needs_raw_ip_stack(Some(&ir)).expect("ir parses"));
    }

    #[test]
    fn a_workload_that_declares_nothing_does_not_get_the_tunnel() {
        let dir = tempfile::tempdir().expect("temp dir");
        for network in [Some(net(false)), None] {
            let described = format!("{network:?}");
            let ir = write_ir(dir.path(), network);
            assert!(
                !workload_needs_raw_ip_stack(Some(&ir)).expect("ir parses"),
                "silence must not select the tunnel ({described})"
            );
        }
    }

    #[test]
    fn unreadable_workload_ir_fails_closed_rather_than_defaulting() {
        // Guessing here would admit for one transport and boot on another.
        let dir = tempfile::tempdir().expect("temp dir");
        let bad = dir.path().join("workload.json");
        std::fs::write(&bad, b"{ not json").expect("write");
        assert!(workload_needs_raw_ip_stack(Some(&bad)).is_err());
    }
}
