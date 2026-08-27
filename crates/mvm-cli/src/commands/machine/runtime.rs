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
    let has_source = args.run.image.is_some()
        || args.run.manifest.is_some()
        || args.run.deployment.is_some()
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

    if args.run.dry_run {
        let summary = machine_start_preflight_summary(
            &spec,
            args.run.hypervisor.as_deref(),
            args.run.receipt.as_deref(),
        )?;
        if args.run.json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            print_machine_start_preflight_human(&summary);
        }
        return Ok(());
    }

    let booted = persist_and_boot_machine(&name, &spec, action, start_args_for_run(&args, &name))?;
    if !booted && !args.run.json && !args.up_json {
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
    if !args.run.argv.is_empty() {
        if !shared::wait_for_guest_agent(name, 30) {
            anyhow::bail!("guest agent for {name:?} not reachable to run the command");
        }
        return console::run(
            cli,
            console::Args {
                name: name.to_string(),
                command: Some(machine_exec_command(&args.run.argv)),
                force: false,
                env: Vec::new(),
                pty_argv: Vec::new(),
            },
            cfg,
        );
    }
    match post_start_action(args) {
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
    /// `--up-json`: the SDK boot envelope, and nothing else on stdout.
    Envelope,
    /// `--json`: the caller is parsing stdout, so say nothing extra.
    Quiet,
    /// `-d`/`--detach`: the machine id, for a caller that will come back later.
    PrintId,
    /// The default: follow the machine's output.
    Attach,
}

/// Whether the human `started machine <name>` banner must be withheld.
///
/// `--up-json` reserves stdout for exactly one JSON envelope. The banner was
/// printed to stdout ahead of it, so a caller doing `json.loads(stdout)` failed
/// on line 1 — which is how the SDK's live transport broke: it shells
/// `machine run -d --up-json ...` and parses the result. `--json` is already
/// withheld inside the start path itself, by the branch that prints the summary
/// instead.
pub(crate) fn banner_suppressed(args: &MachineRunArgs) -> bool {
    args.up_json
}

/// Translate a persistent `machine run` into the start arguments it boots
/// under.
///
/// Split out from the boot call so the `quiet` wiring is testable without a VM.
/// A test that only pinned `banner_suppressed` would keep passing if this
/// mapping stopped calling it, which is the shape of the bug it exists for.
pub(crate) fn start_args_for_run(args: &MachineRunArgs, name: &str) -> MachineStartArgs {
    MachineStartArgs {
        name: name.to_string(),
        create_flags: MachineStartCreateFlags::default(),
        receipt: args.run.receipt.clone(),
        json: args.run.json,
        dry_run: false,
        quiet: banner_suppressed(args),
        hypervisor: args.run.hypervisor.clone(),
        no_supervisor: args.no_supervisor,
        kernel_pin: args.kernel_pin.clone(),
        has_ad_hoc_argv: !args.run.argv.is_empty(),
    }
}

/// Resolve the post-start behaviour from the flags alone, so the choice is
/// testable without booting anything.
pub(super) fn post_start_action(args: &MachineRunArgs) -> PostStart {
    if args.up_json {
        PostStart::Envelope
    } else if args.run.json {
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

/// `build_mode` for the SDK boot envelope: the tier of the grant this launch
/// actually carries, not the tier of the image it booted.
///
/// The SDK gates its DevOnly surfaces on this field —
/// `if self.build_mode != "dev": raise SandboxDevOnly`. Reporting the image
/// posture made that gate pass for a launch whose grant is ProdSafe-only, so
/// the SDK went ahead and the *guest* refused instead, with a verb-grant error
/// rather than the documented `SandboxDevOnly`. A caller cannot act on a field
/// that answers a different question than the one it is asked.
///
/// A grant-eligible launch receives the attenuated ProdSafe verb set
/// (`default_agent_verbs`), which admits no DevOnly verb — `--agent-verb`
/// rejects them outright — so `fs`/`proc`/`exec` will be refused no matter how
/// the image was built. That is `prod` from the SDK's point of view whatever
/// the template says.
fn resolve_build_mode_for_envelope(args: &MachineRunArgs, name: &str) -> &'static str {
    if launch_carries_restricted_grant(args) {
        return "prod";
    }
    resolve_machine_build_mode(args.run.manifest.as_deref(), name)
}

/// Whether this launch is admitted with the attenuated ProdSafe-only verb
/// grant. Mirrors the `restrict_agent_verbs` decision the persistent OCI start
/// makes, so the envelope cannot disagree with the grant that was issued.
pub(crate) fn launch_carries_restricted_grant(args: &MachineRunArgs) -> bool {
    crate::commands::vm::agent_verbs::grant_eligible(
        args.tty,
        !args.run.argv.is_empty(),
        matches!(args.run.profile, crate::commands::vm::exec::RunProfile::Dev),
    )
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
    if args.run.deployment.is_some() {
        anyhow::bail!(
            "machine run --entrypoint does not accept --deployment; use a manifest or flake source"
        );
    }
    if args.run.image.is_some() {
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
    } else if let Some(manifest) = args.run.manifest.clone() {
        manifest
    } else {
        anyhow::bail!(
            "machine run --entrypoint needs `--manifest <path>` or `--flake <path>` \
             (or `--attach --name <NAME>` to dispatch into a running machine)"
        );
    };
    let (memory_mib, _) = validate_machine_memory(&args.run.memory, None)?;
    // Resolve `--net` / `--allow-host` into the egress policy exactly as the
    // transient argv path does, so a baked entrypoint enforces the same posture.
    let network_policy = shared::resolve_run_network_policy(args.run.net, &args.run.allow_host)?;
    let stdin = resolve_entrypoint_stdin(args.stdin.as_deref())?;
    invoke::run_entrypoint(invoke::EntrypointCall {
        source,
        stdin,
        timeout: args.run.timeout.unwrap_or(30),
        cpus: args.run.cpus,
        memory_mib,
        from_workload_ir: args.from_workload_ir.clone(),
        agent_verb_override: args.run.agent_verb.clone(),
        reset: args.reset,
        keep_alive: args.persistent(),
        keep_alive_dev: false,
        session: None,
        r#fn: None,
        attach: args.attach,
        network_policy,
        hypervisor: args.run.hypervisor.clone(),
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
    resolve_entrypoint_stdin_with(spec, invoke::read_auto_stdin)
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

pub(super) fn run_dispatch(cli: &Cli, mut args: MachineRunArgs, cfg: &MvmConfig) -> Result<()> {
    // Settle the boot source before `resolve_mode` decides whether one is
    // missing — the same resolver `mvmctl run` uses, so the two verbs infer
    // identically or not at all.
    let cwd = std::env::current_dir().context("resolving the working directory")?;
    crate::commands::vm::exec::resolve_run_source(
        &mut args.run,
        &cwd,
        crate::commands::vm::exec::Inference::ExplicitOnly,
    )?
    .announce();
    let resolved_flake_slot = if let Some(flake_ref) = args.run.flake.take() {
        let slot_hash = build::build_flake_to_slot(&flake_ref, args.run.flake_profile.as_deref())?;
        args.run.manifest = Some(slot_hash.clone());
        Some(slot_hash)
    } else {
        None
    };
    let local_deployment = args
        .run
        .deployment
        .as_deref()
        .map(super::resolve_local_deployment)
        .transpose()?;

    // Parsing the workload IR happens at the compile/admission boundary. A
    // stale raw-network declaration is refused there before this single-path
    // runtime selection can be reached.
    let network_mode = super::preflight_network();
    tracing::debug!(?network_mode, "derived machine networking");

    if args.entrypoint {
        return run_entrypoint_action(args, resolved_flake_slot);
    }

    // A flake was built into a manifest slot above, and that image carries its
    // own `entrypoint.command` — so an empty argv is the image supplying one.
    let mode = args.resolve_mode(resolved_flake_slot.is_some())?;
    let warm_pool_size = mode.warm_pool_size(None, args.name.is_some());
    // The wasm backend is a claim-free, host-wasmtime runner: it has no
    // standby-pool machinery and should never be blocked by a warm-pool
    // default that it cannot satisfy.
    let warm_pool_size = if args.run.hypervisor.as_deref() == Some("wasm") {
        0
    } else {
        warm_pool_size
    };
    tracing::debug!(?mode, warm_pool_size, "machine run warm-pool eligibility");
    match mode {
        MachineRunMode::Transient => {
            if let Some(slot) = resolved_flake_slot {
                args.run.manifest = Some(slot);
            }
            let mut run_args = args.into_run_args();
            // The mode settled above, not a re-derivation: one value reaches
            // both the transport decision and the signed plan.
            run_args.network_mode = network_mode;
            run_args.warm_pool_size = warm_pool_size;
            run_args.stdin = invoke::read_auto_stdin()?;
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
                args.run.manifest = Some(slot);
            }
            let mut run_args = args.into_run_args();
            // The mode settled above, not a re-derivation: one value reaches
            // both the transport decision and the signed plan.
            run_args.network_mode = network_mode;
            run_args.pty = true;
            run_args.warm_pool_size = warm_pool_size;
            run_args.stdin = invoke::read_auto_stdin()?;
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
            kernel_pin,
            // Booting by name carries no caller stdin, so it requests no input
            // grant and the plan stays ungranted.
            stdin: None,
            detach: true,
            run: RunArgs {
                flake,
                hypervisor,
                ..Default::default()
            },
            ..Default::default()
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
mod network_surface_tests {

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

    fn net() -> mvm_contract::ir::Network {
        mvm_contract::ir::Network {
            mode: mvm_contract::ir::NetworkMode::Bridge,
            ports: vec![],
            egress: None,
            peers: vec![],
            dns: None,
            ai: None,
        }
    }

    #[test]
    fn a_launch_with_no_workload_ir_keeps_the_socket_aware_default() {
        assert_eq!(
            super::super::preflight_network(),
            mvm_contract::plan::NetworkMode::HostVsockProxy
        );
    }

    #[test]
    fn a_stale_raw_declaration_is_refused_while_loading_the_ir() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ir = dir.path().join("workload.json");
        std::fs::write(
            &ir,
            br#"{"schema_version":"0.1","id":"legacy","apps":[{"name":"probe","source":{"kind":"local_path","path":"."},"image":{"kind":"nix_packages","packages":[]},"entrypoints":[],"resources":{"cpu_cores":1,"memory_mb":256,"rootfs_size_mb":512},"network":{"mode":"bridge","raw_ip_stack":true}}]}"#,
        )
        .expect("write stale IR");
        let err = crate::commands::vm::up::load_workload_ir(Some(&ir))
            .expect_err("the retired field must fail at the IR boundary");
        let message = format!("{err:#}");
        assert!(
            message.contains("raw_ip_stack has been retired"),
            "{message}"
        );
    }

    #[test]
    fn a_workload_that_declares_nothing_does_not_get_the_tunnel() {
        let dir = tempfile::tempdir().expect("temp dir");
        for network in [Some(net()), None] {
            let described = format!("{network:?}");
            let ir = write_ir(dir.path(), network);
            let loaded = crate::commands::vm::up::load_workload_ir(Some(&ir))
                .expect("IR loads")
                .expect("workload present");
            assert_eq!(loaded.apps.len(), 1, "{described}");
        }
    }

    #[test]
    fn unreadable_workload_ir_fails_closed_rather_than_defaulting() {
        // Guessing here would admit for one transport and boot on another.
        let dir = tempfile::tempdir().expect("temp dir");
        let bad = dir.path().join("workload.json");
        std::fs::write(&bad, b"{ not json").expect("write");
        assert!(crate::commands::vm::up::load_workload_ir(Some(&bad)).is_err());
    }
}
