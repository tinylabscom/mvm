//! `mvmctl run` / `mvmctl up` / `mvmctl start` — boot a microVM from a flake or template.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::bootstrap;
use crate::ui;

use mvm_core::naming::{validate_flake_ref, validate_template_name, validate_vm_name};
use mvm_core::user_config::MvmConfig;
use mvm_core::util::parse_human_size;
use mvm_core::vm_backend::VmId;
use mvm_runtime::vm::backend::AnyBackend;
use mvm_runtime::vm::{image, lima, microvm};

use super::super::env::apple_container::ensure_default_microvm_image;
use super::Cli;
use super::forward::forward_ports;
use super::shared::{
    VmStartParams, VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
    env_vars_to_drive_file, parse_port_specs, parse_volume_spec, ports_to_drive_file,
    read_dir_to_drive_files, request_port_forward, resolve_flake_ref, resolve_network_policy,
    wait_for_guest_agent,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Nix flake reference (local path or remote URI)
    #[arg(long, value_parser = clap_flake_ref, conflicts_with = "template")]
    pub flake: Option<String>,
    /// Run from a pre-built template (skip build)
    #[arg(long)]
    pub template: Option<String>,
    /// VM name (auto-generated if omitted)
    #[arg(long, value_parser = clap_vm_name)]
    pub name: Option<String>,
    /// Flake package variant (e.g. worker, gateway). Omit to use flake default
    #[arg(long)]
    pub profile: Option<String>,
    /// vCPU cores
    #[arg(long)]
    pub cpus: Option<u32>,
    /// Memory (supports human-readable sizes: 512M, 4G, 1024K, or plain MB)
    #[arg(long)]
    pub memory: Option<String>,
    /// Runtime config (TOML) for persistent resources/volumes
    #[arg(long)]
    pub config: Option<String>,
    /// Volume (host_dir:/guest/path or host:/guest/path:size). Repeatable
    #[arg(short, long, value_parser = clap_volume_spec)]
    pub volume: Vec<String>,
    /// Hypervisor backend (firecracker, qemu, apple-container, docker). Default: auto-detect
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
    /// Port mapping (format: HOST:GUEST or PORT). Repeatable
    #[arg(short, long, value_parser = clap_port_spec)]
    pub port: Vec<String>,
    /// Environment variable to inject (format: KEY=VALUE). Repeatable
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Auto-forward declared ports after boot (blocks until Ctrl-C)
    #[arg(long)]
    pub forward: bool,
    /// Bind a Prometheus metrics endpoint on this port (0 = disabled)
    #[arg(long, default_value = "0")]
    pub metrics_port: u16,
    /// Reload ~/.mvm/config.toml automatically when it changes
    #[arg(long)]
    pub watch_config: bool,
    /// Watch the flake for changes and auto-rebuild + reboot (requires local --flake)
    #[arg(long)]
    pub watch: bool,
    /// Run in background (detached mode, like docker run -d)
    #[arg(short, long)]
    pub detach: bool,
    /// Network preset (unrestricted, none, registries, dev)
    #[arg(long)]
    pub network_preset: Option<String>,
    /// Network allowlist entry (format: HOST:PORT). Repeatable
    #[arg(long)]
    pub network_allow: Vec<String>,
    /// Seccomp profile tier (essential, minimal, standard, network, unrestricted)
    #[arg(long, default_value = "unrestricted")]
    pub seccomp: String,
    /// Secret binding (format: KEY:host, KEY:host:header, or KEY=value:host). Repeatable
    #[arg(short, long)]
    pub secret: Vec<String>,
    /// Named dev network to attach VM to (default: "default")
    #[arg(long, default_value = "default")]
    pub network: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let memory_mb = args
        .memory
        .as_ref()
        .map(|s| parse_human_size(s))
        .transpose()
        .context("Invalid memory size")?;
    // CLI flag takes precedence; fall back to per-user config defaults.
    let effective_cpus = args.cpus.or(Some(cfg.default_cpus));
    let effective_memory = memory_mb.or(Some(cfg.default_memory_mib));

    let network_policy =
        resolve_network_policy(args.network_preset.as_deref(), &args.network_allow)?;
    let seccomp_tier: mvm_security::seccomp::SeccompTier =
        args.seccomp.parse().context("Invalid --seccomp value")?;
    let secret_bindings: Vec<mvm_core::secret_binding::SecretBinding> = args
        .secret
        .iter()
        .map(|s| s.parse())
        .collect::<Result<Vec<_>>>()
        .context("Invalid --secret value")?;

    cmd_run(RunParams {
        flake_ref: args.flake.as_deref(),
        template_name: args.template.as_deref(),
        name: args.name.as_deref(),
        profile: args.profile.as_deref(),
        cpus: effective_cpus,
        memory: effective_memory,
        config_path: args.config.as_deref(),
        volumes: &args.volume,
        hypervisor: &args.hypervisor,
        ports: &args.port,
        env_vars: &args.env,
        forward: args.forward,
        metrics_port: args.metrics_port,
        watch_config: args.watch_config,
        watch: args.watch,
        detach: args.detach,
        network_policy,
        network_name: &args.network,
        seccomp_tier,
        secret_bindings,
    })
}

pub(in crate::commands) struct RunParams<'a> {
    pub(super) flake_ref: Option<&'a str>,
    pub(super) template_name: Option<&'a str>,
    pub(super) name: Option<&'a str>,
    pub(super) profile: Option<&'a str>,
    pub(super) cpus: Option<u32>,
    pub(super) memory: Option<u32>,
    pub(super) config_path: Option<&'a str>,
    pub(super) volumes: &'a [String],
    pub(super) hypervisor: &'a str,
    pub(super) ports: &'a [String],
    pub(super) env_vars: &'a [String],
    pub(super) forward: bool,
    pub(super) metrics_port: u16,
    pub(super) watch_config: bool,
    pub(super) watch: bool,
    pub(super) detach: bool,
    pub(super) network_policy: mvm_core::network_policy::NetworkPolicy,
    pub(super) network_name: &'a str,
    pub(super) seccomp_tier: mvm_security::seccomp::SeccompTier,
    pub(super) secret_bindings: Vec<mvm_core::secret_binding::SecretBinding>,
}

pub(super) fn cmd_run(params: RunParams<'_>) -> Result<()> {
    let RunParams {
        flake_ref,
        template_name,
        name,
        profile,
        cpus,
        memory,
        config_path,
        volumes,
        hypervisor,
        ports,
        env_vars,
        forward,
        metrics_port,
        watch_config,
        watch,
        detach,
        network_policy,
        network_name,
        seccomp_tier,
        secret_bindings,
    } = params;
    let _span =
        tracing::info_span!("cmd_run", name = ?name, cpus = ?cpus, memory_mib = ?memory).entered();
    if let Some(n) = name {
        validate_vm_name(n).with_context(|| format!("Invalid VM name: {:?}", n))?;
    }
    if let Some(f) = flake_ref {
        validate_flake_ref(f).with_context(|| format!("Invalid flake reference: {:?}", f))?;
    }
    if let Some(t) = template_name {
        validate_template_name(t).with_context(|| format!("Invalid template name: {:?}", t))?;
    }
    // Auto-select backend when no explicit hypervisor is specified.
    // Priority: KVM (Firecracker direct) → Apple Container → Lima + Firecracker
    let effective_hypervisor = if hypervisor == "firecracker" {
        let plat = mvm_core::platform::current();
        if plat.has_kvm() {
            "firecracker" // native KVM — best option
        } else if plat.has_apple_containers() {
            "apple-container" // macOS 26+ — no Lima
        } else if plat.has_docker() {
            "docker" // universal fallback
        } else {
            "firecracker" // Lima fallback
        }
    } else {
        hypervisor
    };

    // Apple Container doesn't need Lima — skip the upfront check entirely.
    // For Firecracker on macOS, Lima is required for both build and runtime.
    let needs_lima = effective_hypervisor != "apple-container"
        && effective_hypervisor != "docker"
        && bootstrap::is_lima_required();
    if needs_lima {
        lima::require_running()?;
    }
    let _metrics_server = if metrics_port > 0 {
        Some(crate::metrics_server::MetricsServer::start(metrics_port)?)
    } else {
        None
    };

    // Start config watcher so the user is notified if the config file changes
    // while the build or boot is in progress.
    let _config_watcher = if watch_config {
        let config_path = {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            std::path::PathBuf::from(home)
                .join(".mvm")
                .join("config.toml")
        };
        if config_path.exists() {
            match crate::config_watcher::ConfigWatcher::start(&config_path) {
                Ok(w) => {
                    tracing::info!("Watching ~/.mvm/config.toml for changes");
                    Some(w)
                }
                Err(e) => {
                    tracing::warn!("Could not start config watcher: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // Generate a VM name if not provided.
    // After codesign re-exec (macOS), the env var preserves the originally
    // generated name so we don't produce a second random name.
    let vm_name = match name {
        Some(n) => n.to_string(),
        None => std::env::var("MVM_REEXEC_NAME").unwrap_or_else(|_| {
            let mut generator = names::Generator::default();
            generator.next().unwrap_or_else(|| "vm-0".to_string())
        }),
    };

    // Register the VM name in the persistent registry (best-effort).
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm_runtime::vm::name_registry::VmNameRegistry::load(&registry_path) {
        // Deregister stale entry with the same name if it exists
        registry.deregister(&vm_name);
        let _ = registry.register(&vm_name, "", network_name, None, 0);
        let _ = registry.save(&registry_path);
    }

    // Direct boot mode: launchd agent passes kernel/rootfs via env vars.
    // Skip the build/template loading entirely.
    if std::env::var("MVM_DIRECT_BOOT").as_deref() == Ok("1") {
        let kernel = std::env::var("MVM_KERNEL_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_KERNEL_PATH not set"))?;
        let rootfs = std::env::var("MVM_ROOTFS_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_ROOTFS_PATH not set"))?;

        let start_config = mvm_core::vm_backend::VmStartConfig {
            name: vm_name.clone(),
            rootfs_path: rootfs,
            kernel_path: Some(kernel),
            cpus: cpus.unwrap_or(2),
            memory_mib: memory.unwrap_or(512),
            ..Default::default()
        };

        let backend = AnyBackend::from_hypervisor(effective_hypervisor);
        backend.start(&start_config)?;

        // Set up port forwarding from MVM_PORTS env var (via vsock)
        if let Ok(ports_str) = std::env::var("MVM_PORTS")
            && !ports_str.is_empty()
        {
            ui::info("Waiting for guest agent...");
            if wait_for_guest_agent(&vm_name, 30) {
                for spec in ports_str.split(',') {
                    if let Some((host, guest)) = spec.split_once(':')
                        && let (Ok(h), Ok(g)) = (host.parse::<u16>(), guest.parse::<u16>())
                    {
                        let _ = request_port_forward(&vm_name, g);
                        mvm_apple_container::start_port_proxy(&vm_name, h, g);
                        ui::info(&format!("Forwarding localhost:{h} → guest tcp/{g} (vsock)"));
                    }
                }
            } else {
                ui::warn("Guest agent not reachable — port forwarding unavailable.");
            }
        }

        ui::info(&format!("VM '{}' running. Press Ctrl+C to stop.", vm_name));

        // Block until signaled
        let pair = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let pair2 = pair.clone();
        let _ = ctrlc::set_handler(move || {
            let (lock, cvar) = &*pair2;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cvar.notify_all();
        });
        let (lock, cvar) = &*pair;
        let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !*stopped {
            stopped = cvar
                .wait_timeout(stopped, std::time::Duration::from_secs(1))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let _ = backend.stop(&mvm_core::vm_backend::VmId(vm_name));
        return Ok(());
    }

    // Resolve artifact paths from either a pre-built template or a flake build.
    let (
        vmlinux_path,
        initrd_path,
        rootfs_path,
        revision_hash,
        source_flake,
        source_profile,
        tmpl_cpus,
        tmpl_mem,
        snapshot_info,
    ) = if let Some(tmpl) = template_name {
        ui::step(
            1,
            2,
            &format!("Loading template '{}' for VM '{}'", tmpl, vm_name),
        );
        let (spec, vmlinux, initrd, rootfs, rev) =
            mvm_runtime::vm::template::lifecycle::template_artifacts(tmpl)?;
        ui::info(&format!("Using revision {}", rev));

        // Check for pre-built snapshot
        let snap_info = mvm_runtime::vm::template::lifecycle::template_snapshot_info(tmpl)?;
        if snap_info.is_some() {
            ui::info("Snapshot available — will restore instantly");
        }

        (
            vmlinux,
            initrd,
            rootfs,
            rev,
            spec.flake_ref.clone(),
            Some(spec.profile.clone()),
            Some(spec.vcpus as u32),
            Some(spec.mem_mib),
            snap_info,
        )
    } else if let Some(flake) = flake_ref {
        let resolved = resolve_flake_ref(flake)?;
        let profile_display = profile.unwrap_or("default");
        ui::step(
            1,
            2,
            &format!(
                "Building flake {} (profile={}, name={})",
                resolved, profile_display, vm_name
            ),
        );
        let run_build_env = mvm_runtime::build_env::default_build_env();
        let env = run_build_env.as_ref();
        let result = mvm_build::dev_build::dev_build(env, &resolved, profile)?;
        if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(env, &result) {
            ui::warn(&format!(
                "Could not verify guest agent ({}). If built with mkGuest, the agent is already included.",
                e
            ));
        }
        if result.cached {
            ui::info(&format!("Cache hit — revision {}", result.revision_hash));
        } else {
            ui::info(&format!(
                "Build complete — revision {}",
                result.revision_hash
            ));
        }
        (
            result.vmlinux_path,
            result.initrd_path,
            result.rootfs_path,
            result.revision_hash,
            flake.to_string(),
            profile.map(|s| s.to_string()),
            None,
            None,
            None, // No snapshot for flake builds
        )
    } else {
        ui::step(
            1,
            2,
            &format!(
                "No --flake or --template; using bundled default microVM image for '{}'",
                vm_name
            ),
        );
        let (kernel, rootfs) = ensure_default_microvm_image()?;
        (
            kernel,
            None,
            rootfs,
            String::new(),
            "default-microvm".to_string(),
            None,
            None,
            None,
            None,
        )
    };

    let backend_label = match effective_hypervisor {
        "apple-container" => "Apple Container",
        "qemu" => "QEMU (microvm.nix)",
        _ => "Firecracker VM",
    };
    ui::step(2, 2, &format!("Booting {} '{}'", backend_label, vm_name));

    let rt_config = match config_path {
        Some(p) => image::parse_runtime_config(p)?,
        None => image::RuntimeConfig::default(),
    };

    // Partition --volume specs into dir-inject (config/secrets) and persistent volumes
    let mut volume_cfg: Vec<image::RuntimeVolume> = Vec::new();
    let mut config_files: Vec<microvm::DriveFile> = Vec::new();
    let mut secret_files: Vec<microvm::DriveFile> = Vec::new();

    if !volumes.is_empty() {
        for v in volumes {
            match parse_volume_spec(v)? {
                VolumeSpec::DirInject {
                    host_dir,
                    guest_mount,
                } => match guest_mount.as_str() {
                    "/mnt/config" => {
                        config_files.extend(
                            read_dir_to_drive_files(&host_dir, 0o444)
                                .with_context(|| format!("reading volume '{}'", v))?,
                        );
                    }
                    "/mnt/secrets" => {
                        secret_files.extend(
                            read_dir_to_drive_files(&host_dir, 0o400)
                                .with_context(|| format!("reading volume '{}'", v))?,
                        );
                    }
                    other => anyhow::bail!(
                        "Unsupported guest mount '{}'. Supported: /mnt/config, /mnt/secrets",
                        other
                    ),
                },
                VolumeSpec::Persistent(vol) => volume_cfg.push(vol),
            }
        }
    } else {
        volume_cfg = rt_config.volumes.clone();
    };

    let user_cfg = mvm_core::user_config::load(None);
    let final_cpus = cpus
        .or(rt_config.cpus)
        .or(tmpl_cpus)
        .unwrap_or(user_cfg.default_cpus);
    let final_memory = memory
        .or(rt_config.memory)
        .or(tmpl_mem)
        .unwrap_or(user_cfg.default_memory_mib);

    // Parse port mappings and inject as config drive file
    let port_mappings = parse_port_specs(ports)?;
    if let Some(f) = ports_to_drive_file(&port_mappings) {
        config_files.push(f);
    }

    // Inject env vars as config drive file
    if let Some(f) = env_vars_to_drive_file(env_vars) {
        config_files.push(f);
    }

    // Inject seccomp manifest into config drive if not unrestricted
    if let Some(manifest) = seccomp_tier.to_manifest() {
        let json = serde_json::to_string_pretty(&manifest)
            .context("failed to serialize seccomp manifest")?;
        config_files.push(microvm::DriveFile {
            name: "seccomp.json".to_string(),
            content: json,
            mode: 0o644,
        });
    }

    // Resolve and inject secret bindings
    if !secret_bindings.is_empty() {
        let resolved = mvm_core::secret_binding::ResolvedSecrets::resolve(&secret_bindings)
            .context("failed to resolve secret bindings")?;

        // Write actual secret values to the secrets drive
        for (filename, content) in resolved.to_secret_files() {
            secret_files.push(microvm::DriveFile {
                name: filename,
                content,
                mode: 0o600,
            });
        }

        // Write secret manifest to config drive (no secret values, just metadata)
        config_files.push(microvm::DriveFile {
            name: "secrets-manifest.json".to_string(),
            content: resolved.manifest_json(),
            mode: 0o644,
        });

        // Write placeholder env vars so tools pass existence checks
        let placeholders: Vec<String> = resolved
            .placeholder_env_vars()
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        if let Some(f) = env_vars_to_drive_file(&placeholders) {
            config_files.push(microvm::DriveFile {
                name: "secret-env.env".to_string(),
                content: f.content,
                mode: f.mode,
            });
        }

        // Log which secrets are bound (without revealing values)
        for b in &secret_bindings {
            ui::info(&format!(
                "Secret {} bound to {} (header: {})",
                b.env_var, b.target_host, b.header
            ));
        }
    }

    let vm_name_owned = vm_name.clone();
    let has_ports = !port_mappings.is_empty();

    // Stash the generated VM name so that if the Apple Container backend
    // re-execs after codesigning, the new process reuses the same name.
    // SAFETY: called early in single-threaded CLI startup before spawning
    // worker threads; no other threads are reading env vars concurrently.
    unsafe { std::env::set_var("MVM_REEXEC_NAME", &vm_name) };

    // If a template snapshot exists AND the backend supports snapshots,
    // restore from it instead of cold-booting.
    let backend = AnyBackend::from_hypervisor(effective_hypervisor);
    if let Some(ref snap_info) = snapshot_info
        && let Some(tmpl) = template_name
        && backend.capabilities().snapshots
    {
        let slot = microvm::allocate_slot(&vm_name)?;
        let run_config = microvm::FlakeRunConfig {
            name: vm_name,
            slot,
            vmlinux_path,
            initrd_path,
            rootfs_path,
            revision_hash,
            flake_ref: source_flake,
            profile: source_profile,
            cpus: final_cpus,
            memory: final_memory,
            volumes: volume_cfg,
            config_files,
            secret_files,
            ports: port_mappings,
            network_policy: network_policy.clone(),
        };
        let rev = mvm_runtime::vm::template::lifecycle::current_revision_id(tmpl)?;
        let snap_dir = mvm_core::template::template_snapshot_dir(tmpl, &rev);
        ui::step(
            2,
            2,
            &format!("Restoring VM '{}' from snapshot", vm_name_owned),
        );
        microvm::restore_from_template_snapshot(tmpl, &run_config, &snap_dir, snap_info)?;
    } else {
        let start_config = VmStartParams {
            name: vm_name,
            rootfs_path,
            vmlinux_path,
            initrd_path,
            revision_hash,
            flake_ref: source_flake,
            profile: source_profile,
            cpus: final_cpus,
            memory_mib: final_memory,
            volumes: &volume_cfg,
            config_files: &config_files,
            secret_files: &secret_files,
            port_mappings: &port_mappings,
        }
        .into_start_config();

        // Apple Container with -d: install a launchd agent instead of
        // starting the VM in this process. The agent runs as a proper
        // macOS service with its own RunLoop.
        if detach && effective_hypervisor == "apple-container" {
            // Sign the binary before installing the launchd agent so the
            // daemon process launches with the entitlement already in place.
            mvm_apple_container::ensure_signed();

            // Build is already done — install launchd agent with the
            // resolved kernel/rootfs paths (no rebuild in the daemon).
            // Serialize port mappings for the daemon
            let port_specs: Vec<String> = parse_port_specs(ports)
                .unwrap_or_default()
                .iter()
                .map(|p| format!("{}:{}", p.host, p.guest))
                .collect();

            mvm_apple_container::install_launchd_direct(
                &start_config.name,
                start_config.kernel_path.as_deref().unwrap_or(""),
                &start_config.rootfs_path,
                start_config.cpus,
                start_config.memory_mib as u64,
                &port_specs,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{vm_name_owned}");
            return Ok(());
        }

        backend.start(&start_config)?;
    }

    mvm_core::audit::emit(
        mvm_core::audit::LocalAuditKind::VmStart,
        Some(&vm_name_owned),
        None,
    );

    // Apple Virtualization VMs live in-process — the process must stay alive.
    if effective_hypervisor == "apple-container" && !detach {
        // Set up port forwarding via vsock (no guest IP needed).
        // 1. Wait for guest agent to be ready on vsock port 52
        // 2. Tell the agent to start vsock→TCP forwarders for each port
        // 3. Start host-side TCP→vsock proxies
        if has_ports {
            let pm_list = parse_port_specs(ports).unwrap_or_default();

            ui::info("Waiting for guest agent...");
            let agent_ready = wait_for_guest_agent(&vm_name_owned, 30);
            if !agent_ready {
                ui::warn("Guest agent not reachable — port forwarding unavailable.");
            } else {
                // Tell guest agent to start vsock forwarders
                for pm in &pm_list {
                    match request_port_forward(&vm_name_owned, pm.guest) {
                        Ok(vsock_port) => {
                            ui::info(&format!(
                                "Guest forwarding vsock:{vsock_port} → tcp/{}",
                                pm.guest
                            ));
                        }
                        Err(e) => {
                            ui::warn(&format!(
                                "Failed to set up guest forwarder for port {}: {e}",
                                pm.guest
                            ));
                        }
                    }
                }

                // Start host-side proxies
                for pm in &pm_list {
                    mvm_apple_container::start_port_proxy(&vm_name_owned, pm.host, pm.guest);
                    ui::info(&format!(
                        "Forwarding localhost:{} → guest tcp/{} (vsock)",
                        pm.host, pm.guest
                    ));
                }

                // Persist port mappings so `ps` can display them
                let ports_str: Vec<String> = pm_list
                    .iter()
                    .map(|p| format!("{}:{}", p.host, p.guest))
                    .collect();
                let ports_file = format!(
                    "{}/.mvm/vms/{}/ports",
                    std::env::var("HOME").unwrap_or_default(),
                    vm_name_owned
                );
                let _ = std::fs::write(&ports_file, ports_str.join(","));
            }
        }

        ui::info(&format!(
            "VM '{}' running. Press Ctrl+C to stop.",
            vm_name_owned
        ));

        // Block until signaled (Ctrl+C or SIGTERM)
        let pair = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let pair2 = pair.clone();
        let _ = ctrlc::set_handler(move || {
            let (lock, cvar) = &*pair2;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cvar.notify_all();
        });

        let (lock, cvar) = &*pair;
        let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !*stopped {
            stopped = cvar
                .wait_timeout(stopped, std::time::Duration::from_secs(1))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }

        ui::info(&format!("Stopping VM '{}'...", vm_name_owned));
        let _ = backend.stop(&mvm_core::vm_backend::VmId(vm_name_owned.clone()));
        return Ok(());
    }

    if forward {
        if has_ports {
            forward_ports(&vm_name_owned, &[])?;
        } else {
            ui::warn("--forward was set but no ports were declared. Use -p to specify ports.");
        }
    }

    // Watch mode: on each .nix / flake.lock change, stop the VM, rebuild, reboot.
    if watch {
        let Some(flake) = flake_ref else {
            // Template mode — watch not supported.
            return Ok(());
        };
        if flake.contains(':') {
            ui::warn("--watch requires a local flake; running a single boot instead.");
            return Ok(());
        }
        let flake_dir = resolve_flake_ref(flake)?;
        loop {
            ui::info("Watching for .nix and .lock changes (Ctrl+C to exit)...");
            match crate::watch::wait_for_changes(&flake_dir) {
                Ok(trigger) => {
                    let display = crate::watch::display_trigger(&trigger, &flake_dir);
                    ui::info(&format!("\nChange detected: {display} — rebuilding..."));
                }
                Err(e) => {
                    tracing::warn!("Watch error: {e}");
                    break;
                }
            }

            // Stop the running VM.
            let backend = AnyBackend::default_backend();
            if let Err(e) = backend.stop(&VmId::from(vm_name_owned.as_str())) {
                tracing::warn!("Could not stop '{}': {e}", vm_name_owned);
            }

            // Rebuild the flake.
            let env = mvm_runtime::build_env::RuntimeBuildEnv;
            let result = match mvm_build::dev_build::dev_build(&env, &flake_dir, profile) {
                Ok(r) => r,
                Err(e) => {
                    ui::warn(&format!("Rebuild failed: {e}; waiting for next change..."));
                    continue;
                }
            };
            if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result) {
                tracing::warn!("Guest agent check failed: {e}");
            }
            ui::success(&format!(
                "Build complete — revision {}",
                result.revision_hash
            ));

            // Re-parse volumes, ports and env vars for the fresh boot.
            let rt_cfg_watch = match config_path {
                Some(p) => image::parse_runtime_config(p).unwrap_or_default(),
                None => image::RuntimeConfig::default(),
            };
            let mut w_volume_cfg: Vec<image::RuntimeVolume> = Vec::new();
            let mut w_config_files: Vec<microvm::DriveFile> = Vec::new();
            let mut w_secret_files: Vec<microvm::DriveFile> = Vec::new();
            if !volumes.is_empty() {
                for v in volumes {
                    match parse_volume_spec(v) {
                        Ok(VolumeSpec::DirInject {
                            host_dir,
                            guest_mount,
                        }) => match guest_mount.as_str() {
                            "/mnt/config" => {
                                if let Ok(files) = read_dir_to_drive_files(&host_dir, 0o444) {
                                    w_config_files.extend(files);
                                }
                            }
                            "/mnt/secrets" => {
                                if let Ok(files) = read_dir_to_drive_files(&host_dir, 0o400) {
                                    w_secret_files.extend(files);
                                }
                            }
                            _ => {}
                        },
                        Ok(VolumeSpec::Persistent(vol)) => w_volume_cfg.push(vol),
                        Err(_) => {}
                    }
                }
            } else {
                w_volume_cfg = rt_cfg_watch.volumes.clone();
            }
            let w_port_mappings = parse_port_specs(ports).unwrap_or_default();
            if let Some(f) = ports_to_drive_file(&w_port_mappings) {
                w_config_files.push(f);
            }
            if let Some(f) = env_vars_to_drive_file(env_vars) {
                w_config_files.push(f);
            }
            let w_start_config = VmStartParams {
                name: vm_name_owned.clone(),
                rootfs_path: result.rootfs_path,
                vmlinux_path: result.vmlinux_path,
                initrd_path: result.initrd_path,
                revision_hash: result.revision_hash,
                flake_ref: flake.to_string(),
                profile: profile.map(|s| s.to_string()),
                cpus: final_cpus,
                memory_mib: final_memory,
                volumes: &w_volume_cfg,
                config_files: &w_config_files,
                secret_files: &w_secret_files,
                port_mappings: &w_port_mappings,
            }
            .into_start_config();
            let w_backend = AnyBackend::from_hypervisor(effective_hypervisor);
            if let Err(e) = w_backend.start(&w_start_config) {
                ui::warn(&format!(
                    "Could not start VM: {e}; waiting for next change..."
                ));
            } else {
                mvm_core::audit::emit(
                    mvm_core::audit::LocalAuditKind::VmStart,
                    Some(&vm_name_owned),
                    None,
                );
                ui::success(&format!("VM '{}' rebooted.", vm_name_owned));
            }
        }
    }

    Ok(())
}
