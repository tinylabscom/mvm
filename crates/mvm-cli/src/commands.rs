use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use crate::bootstrap;
use crate::fleet;
use crate::logging::{self, LogFormat};
use crate::template_cmd;
use crate::ui;
use crate::upgrade;

use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::{firecracker, image, lima, microvm};

#[derive(Parser)]
#[command(name = "mvm", version, about = "Firecracker microVM development tool")]
struct Cli {
    /// Log format: human (default) or json (structured)
    #[arg(long, global = true)]
    log_format: Option<String>,

    /// Override Firecracker version (e.g., v1.14.0)
    #[arg(long, global = true)]
    fc_version: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Full environment setup from scratch
    Bootstrap {
        /// Production mode (skip Homebrew, assume Linux with apt)
        #[arg(long)]
        production: bool,
    },
    /// Create Lima VM, install Firecracker, download kernel/rootfs (requires limactl)
    Setup {
        /// Delete the existing rootfs and rebuild it from scratch
        #[arg(long)]
        recreate: bool,
        /// Re-run all setup steps even if already complete
        #[arg(long)]
        force: bool,
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
    },
    /// Launch the Lima development environment, auto-bootstrapping if needed
    Dev {
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
        /// Project directory to cd into inside the VM
        #[arg(long)]
        project: Option<String>,
    },
    /// Start a Firecracker microVM (headless, no SSH)
    Start {
        /// Path to a built .elf image file (omit for default Ubuntu microVM)
        image: Option<String>,
        /// Runtime config file (TOML) with defaults for resources and volumes
        #[arg(long)]
        config: Option<String>,
        /// Volume override (format: host_path:guest_mount:size). Repeatable.
        #[arg(long, short = 'v')]
        volume: Vec<String>,
        /// CPU cores
        #[arg(long, short = 'c')]
        cpus: Option<u32>,
        /// Memory in MB
        #[arg(long, short = 'm')]
        memory: Option<u32>,
    },
    /// Stop a running microVM (by name) or all VMs (--all)
    Stop {
        /// Name of the VM to stop
        name: Option<String>,
        /// Stop all running VMs
        #[arg(long)]
        all: bool,
    },
    /// Open a shell in the Lima VM (alias for 'mvm shell')
    Ssh,
    /// Print an SSH config entry for the Lima VM
    SshConfig,
    /// Open a shell in the Lima VM (where Firecracker and Nix are installed)
    Shell {
        /// Project directory to cd into inside the VM (Lima maps ~ → ~)
        #[arg(long)]
        project: Option<String>,
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
    },
    /// Build mvm from source inside the Lima VM and install to /usr/local/bin/
    Sync {
        /// Build in debug mode (faster compile, slower runtime)
        #[arg(long)]
        debug: bool,
        /// Skip installing build dependencies (rustup, apt packages)
        #[arg(long)]
        skip_deps: bool,
        /// Rebuild and reinstall even if versions match inside the VM
        #[arg(long)]
        force: bool,
    },
    /// Show console logs from a running microVM
    Logs {
        /// Name of the VM
        name: String,
        /// Follow log output (like tail -f)
        #[arg(long, short = 'f')]
        follow: bool,
        /// Number of lines to show (default 50)
        #[arg(long, short = 'n', default_value = "50")]
        lines: u32,
        /// Show Firecracker hypervisor logs instead of guest console output
        #[arg(long)]
        hypervisor: bool,
    },
    /// Show status of Lima VM and microVM
    Status,
    /// Tear down Lima VM and all resources
    Destroy {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Check for and install the latest version of mvm
    Upgrade {
        /// Only check for updates, don't install
        #[arg(long)]
        check: bool,
        /// Force reinstall even if already up to date
        #[arg(long)]
        force: bool,
    },
    /// System diagnostics and dependency checks
    Doctor {
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
    /// Pre-release checks (deploy guard + cargo publish dry-run)
    Release {
        /// Run cargo publish --dry-run for all crates
        #[arg(long)]
        dry_run: bool,
        /// Run deploy guard checks only (version, tag, inter-crate deps)
        #[arg(long)]
        guard_only: bool,
    },
    /// Manage global templates (shared base images)
    Template {
        #[command(subcommand)]
        action: TemplateCmd,
    },
    /// Build a microVM image from a Mvmfile.toml config or Nix flake
    Build {
        /// Image name (built-in like "openclaw") or path to directory with Mvmfile.toml
        #[arg(default_value = ".")]
        path: String,
        /// Output path for the built .elf image
        #[arg(long, short = 'o')]
        output: Option<String>,
        /// Nix flake reference (enables flake build mode)
        #[arg(long)]
        flake: Option<String>,
        /// Flake package variant (e.g. worker, gateway). Omit to use flake default.
        #[arg(long)]
        profile: Option<String>,
        /// Watch flake.lock and rebuild on change (flake mode)
        #[arg(long)]
        watch: bool,
    },
    /// Build from a Nix flake and boot a headless Firecracker VM
    Run {
        /// Nix flake reference (local path or remote URI)
        #[arg(long)]
        flake: String,
        /// VM name (auto-generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Flake package variant (e.g. worker, gateway). Omit to use flake default.
        #[arg(long)]
        profile: Option<String>,
        /// vCPU cores
        #[arg(long, default_value = "2")]
        cpus: Option<u32>,
        /// Memory in MiB
        #[arg(long, default_value = "1024")]
        memory: Option<u32>,
        /// Runtime config (TOML) for persistent resources/volumes
        #[arg(long)]
        config: Option<String>,
        /// Volume override (format: host_path:guest_mount:size). Repeatable.
        #[arg(long, short = 'v')]
        volume: Vec<String>,
    },
    /// Launch microVMs (from mvm.toml or CLI flags)
    Up {
        /// VM name (from fleet config, or for a new single VM)
        name: Option<String>,
        /// Path to fleet config (default: auto-discover mvm.toml)
        #[arg(long, short = 'f')]
        config: Option<String>,
        /// Nix flake reference (launches a single VM without config file)
        #[arg(long)]
        flake: Option<String>,
        /// Flake package variant (e.g. worker, gateway)
        #[arg(long)]
        profile: Option<String>,
        /// vCPU cores (overrides config file)
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory in MiB (overrides config file)
        #[arg(long)]
        memory: Option<u32>,
    },
    /// Stop microVMs (from mvm.toml, by name, or all)
    Down {
        /// VM name to stop (or all VMs if omitted)
        name: Option<String>,
        /// Path to fleet config (stops only VMs defined in config)
        #[arg(long, short = 'f')]
        config: Option<String>,
    },
    /// Interact with a running microVM via vsock
    Vm {
        #[command(subcommand)]
        action: VmCmd,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum TemplateCmd {
    /// Create a new template (single role/profile)
    Create {
        name: String,
        #[arg(long)]
        flake: String,
        #[arg(long)]
        profile: String,
        #[arg(long, default_value = "worker")]
        role: String,
        #[arg(long)]
        cpus: u8,
        #[arg(long)]
        mem: u32,
        #[arg(long, default_value = "0")]
        data_disk: u32,
    },
    /// Create multiple role-specific templates (name-role)
    CreateMulti {
        base: String,
        #[arg(long)]
        flake: String,
        #[arg(long)]
        profile: String,
        /// Comma-separated roles, e.g. gateway,agent
        #[arg(long)]
        roles: String,
        #[arg(long)]
        cpus: u8,
        #[arg(long)]
        mem: u32,
        #[arg(long, default_value = "0")]
        data_disk: u32,
    },
    /// Build a template (shared image)
    Build {
        name: String,
        #[arg(long)]
        force: bool,
        /// Optional template config TOML to build multiple variants
        #[arg(long)]
        config: Option<String>,
    },
    /// Push a built template revision to the object storage registry
    Push {
        name: String,
        /// Revision hash to push (defaults to current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// Pull a template revision from the object storage registry
    Pull {
        name: String,
        /// Revision hash to pull (defaults to registry current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// Verify a locally installed template revision against checksums.json
    Verify {
        name: String,
        /// Revision hash to verify (defaults to current)
        #[arg(long)]
        revision: Option<String>,
    },
    /// List templates
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show template info
    Info {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Delete a template
    Delete {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// Initialize on-disk template layout (idempotent)
    Init {
        /// Template ID
        name: String,
        /// Create locally instead of inside the VM (/var/lib/mvm/templates)
        #[arg(long)]
        local: bool,
        /// Force VM location (overrides --local)
        #[arg(long)]
        vm: bool,
        /// Base directory for local init (default: current dir)
        #[arg(long, default_value = ".")]
        dir: String,
    },
}

#[derive(Subcommand)]
enum VmCmd {
    /// Health-check running microVMs via vsock (all if no name given)
    Ping {
        /// Name of the VM (omit to ping all running VMs)
        name: Option<String>,
    },
    /// Query worker status from running microVMs (all if no name given)
    Status {
        /// Name of the VM (omit to query all running VMs)
        name: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

// ============================================================================
// Entry point
// ============================================================================

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    // Apply FC version override before anything reads it.
    // SAFETY: called once at startup before any threads are spawned.
    if let Some(ref version) = cli.fc_version {
        unsafe { std::env::set_var("MVM_FC_VERSION", version) };
    }

    // Initialize logging
    let log_format = match cli.log_format.as_deref() {
        Some("json") => LogFormat::Json,
        Some("human") => LogFormat::Human,
        Some(other) => {
            eprintln!(
                "Unknown --log-format '{}', using 'human'. Valid: human, json",
                other
            );
            LogFormat::Human
        }
        None => LogFormat::Human,
    };
    logging::init(log_format);

    let result = match cli.command {
        Commands::Bootstrap { production } => cmd_bootstrap(production),
        Commands::Setup {
            recreate,
            force,
            lima_cpus,
            lima_mem,
        } => cmd_setup(recreate, force, lima_cpus, lima_mem),
        Commands::Dev {
            lima_cpus,
            lima_mem,
            project,
        } => cmd_dev(lima_cpus, lima_mem, project.as_deref()),
        Commands::Start {
            image,
            config,
            volume,
            cpus,
            memory,
        } => match image {
            Some(ref elf) => cmd_start_image(elf, config.as_deref(), &volume, cpus, memory),
            None => cmd_start(),
        },
        Commands::Stop { name, all } => cmd_stop(name.as_deref(), all),
        Commands::Ssh => cmd_ssh(),
        Commands::SshConfig => cmd_ssh_config(),
        Commands::Shell {
            project,
            lima_cpus,
            lima_mem,
        } => cmd_shell(project.as_deref(), lima_cpus, lima_mem),
        Commands::Sync {
            debug,
            skip_deps,
            force,
        } => cmd_sync(debug, skip_deps, force),
        Commands::Logs {
            name,
            follow,
            lines,
            hypervisor,
        } => cmd_logs(&name, follow, lines, hypervisor),
        Commands::Status => cmd_status(),
        Commands::Destroy { yes } => cmd_destroy(yes),
        Commands::Upgrade { check, force } => cmd_upgrade(check, force),
        Commands::Doctor { json } => cmd_doctor(json),
        Commands::Release {
            dry_run,
            guard_only,
        } => cmd_release(dry_run, guard_only),
        Commands::Build {
            path,
            output,
            flake,
            profile,
            watch,
        } => {
            if let Some(flake_ref) = flake {
                cmd_build_flake(&flake_ref, profile.as_deref(), watch)
            } else {
                cmd_build(&path, output.as_deref())
            }
        }
        Commands::Run {
            flake,
            name,
            profile,
            cpus,
            memory,
            config,
            volume,
        } => cmd_run(
            &flake,
            name.as_deref(),
            profile.as_deref(),
            cpus,
            memory,
            config.as_deref(),
            &volume,
        ),
        Commands::Up {
            name,
            config,
            flake,
            profile,
            cpus,
            memory,
        } => cmd_up(
            name.as_deref(),
            config.as_deref(),
            flake.as_deref(),
            profile.as_deref(),
            cpus,
            memory,
        ),
        Commands::Down { name, config } => cmd_down(name.as_deref(), config.as_deref()),
        Commands::Completions { shell } => cmd_completions(shell),
        Commands::Template { action } => cmd_template(action),
        Commands::Vm { action } => cmd_vm(action),
    };

    with_hints(result)
}

// ============================================================================
// Dev mode handlers
// ============================================================================

fn cmd_bootstrap(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");

    if !production {
        bootstrap::check_package_manager()?;
    }

    ui::info("\nInstalling prerequisites...");
    bootstrap::ensure_lima()?;

    // Bootstrap uses default Lima resources (8 vCPUs, 16 GiB), never forces
    run_setup_steps(false, 8, 16)?;

    ui::success("\nBootstrap complete! Run 'mvm dev' to enter the development environment.");
    Ok(())
}

fn cmd_setup(recreate: bool, force: bool, lima_cpus: u32, lima_mem: u32) -> Result<()> {
    if recreate {
        recreate_rootfs()?;
        ui::success("\nRootfs recreated! Run 'mvm start' or 'mvm dev' to launch.");
        return Ok(());
    }

    if !bootstrap::is_lima_required() {
        // Native Linux — just install FC directly
        run_setup_steps(force, lima_cpus, lima_mem)?;
        ui::success("\nSetup complete! Run 'mvm start' to launch a microVM.");
        return Ok(());
    }

    which::which("limactl").map_err(|_| {
        anyhow::anyhow!(
            "'limactl' not found. Install Lima first: brew install lima\n\
             Or run 'mvm bootstrap' for full automatic setup."
        )
    })?;

    run_setup_steps(force, lima_cpus, lima_mem)?;

    ui::success("\nSetup complete! Run 'mvm start' to launch a microVM.");
    Ok(())
}

/// Stop the running microVM and rebuild the rootfs from the upstream squashfs.
fn recreate_rootfs() -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    // Stop Firecracker if running
    if firecracker::is_running()? {
        ui::info("Stopping running microVM...");
        microvm::stop()?;
    }

    ui::info("Removing existing rootfs...");
    shell::run_in_vm(&format!(
        "rm -f {dir}/ubuntu-*.ext4",
        dir = config::MICROVM_DIR,
    ))?;

    ui::info("Rebuilding rootfs...");
    firecracker::prepare_rootfs()?;
    firecracker::write_state()?;

    Ok(())
}

fn cmd_dev(lima_cpus: u32, lima_mem: u32, project: Option<&str>) -> Result<()> {
    ui::info("Launching development environment...\n");

    if bootstrap::is_lima_required() {
        // macOS or Linux without KVM — need Lima
        if which::which("limactl").is_err() {
            ui::info("Lima not found. Running bootstrap...\n");
            cmd_bootstrap(false)?;
        } else {
            let lima_status = lima::get_status()?;
            match lima_status {
                lima::LimaStatus::NotFound => {
                    ui::info("Lima VM not found. Running setup...\n");
                    run_setup_steps(false, lima_cpus, lima_mem)?;
                }
                lima::LimaStatus::Stopped => {
                    ui::info("Lima VM is stopped. Starting...");
                    lima::start()?;
                }
                lima::LimaStatus::Running => {}
            }
        }
    }

    // Install Firecracker if not present (so it's ready for `mvm start` inside Lima)
    if !firecracker::is_installed()? {
        ui::info("Firecracker not installed. Running setup steps...\n");
        firecracker::install()?;
        firecracker::download_assets()?;
        firecracker::prepare_rootfs()?;
        firecracker::write_state()?;
    }

    // Drop into the Lima VM shell (the development environment)
    cmd_shell(project, lima_cpus, lima_mem)
}

fn run_setup_steps(force: bool, lima_cpus: u32, lima_mem: u32) -> Result<()> {
    // Step 1: Lima VM
    if bootstrap::is_lima_required() {
        let lima_status = lima::get_status()?;
        if !force && matches!(lima_status, lima::LimaStatus::Running) {
            ui::step(1, 4, "Lima VM already running — skipping.");
        } else {
            let opts = config::LimaRenderOptions {
                cpus: Some(lima_cpus),
                memory_gib: Some(lima_mem),
                ..Default::default()
            };
            let lima_yaml = config::render_lima_yaml_with(&opts)?;
            ui::info(&format!(
                "Lima VM resources: {} vCPUs, {} GiB memory",
                lima_cpus, lima_mem,
            ));
            ui::step(1, 4, "Setting up Lima VM...");
            lima::ensure_running(lima_yaml.path())?;
        }
    } else {
        ui::step(1, 4, "Native Linux detected — skipping Lima VM setup.");
    }

    // Step 2: Firecracker
    if !force && firecracker::is_installed()? {
        ui::step(2, 4, "Firecracker already installed — skipping.");
    } else {
        ui::step(2, 4, "Installing Firecracker...");
        firecracker::install()?;
    }

    // Step 3: Assets
    ui::step(3, 4, "Downloading kernel and rootfs...");
    firecracker::download_assets()?;

    if !firecracker::validate_rootfs_squashfs()? {
        ui::warn("Downloaded rootfs is corrupted. Re-downloading...");
        shell::run_in_vm(&format!(
            "rm -f {dir}/ubuntu-*.squashfs.upstream",
            dir = config::MICROVM_DIR,
        ))?;
        firecracker::download_assets()?;
    }

    // Step 4: Rootfs
    ui::step(4, 4, "Preparing root filesystem...");
    firecracker::prepare_rootfs()?;

    firecracker::write_state()?;
    Ok(())
}

fn cmd_start() -> Result<()> {
    microvm::start()
}

fn cmd_start_image(
    elf_path: &str,
    config_path: Option<&str>,
    volumes: &[String],
    cpus: Option<u32>,
    memory: Option<u32>,
) -> Result<()> {
    // If limactl isn't available (likely already inside Lima), skip host VM check.
    let limactl_present = shell::run_host("which", &["limactl"])
        .map(|o| o.status.success())
        .unwrap_or(false);
    if limactl_present {
        lima::require_running()?;
    } else {
        ui::warn("limactl not found; assuming we're already inside the Lima VM and proceeding.");
    }

    let rt_config = match config_path {
        Some(p) => image::parse_runtime_config(p)?,
        None => image::RuntimeConfig::default(),
    };

    let mut elf_args = Vec::new();

    let final_cpus = cpus.or(rt_config.cpus);
    let final_memory = memory.or(rt_config.memory);
    if let Some(c) = final_cpus {
        elf_args.push("--cpus".to_string());
        elf_args.push(c.to_string());
    }
    if let Some(m) = final_memory {
        elf_args.push("--memory".to_string());
        elf_args.push(m.to_string());
    }

    if !volumes.is_empty() {
        for v in volumes {
            elf_args.push("--volume".to_string());
            elf_args.push(v.clone());
        }
    } else {
        for v in &rt_config.volumes {
            elf_args.push("--volume".to_string());
            elf_args.push(format!("{}:{}:{}", v.host, v.guest, v.size));
        }
    }

    let args_str = elf_args
        .iter()
        .map(|a| shell_escape(a))
        .collect::<Vec<_>>()
        .join(" ");

    let cmd = if args_str.is_empty() {
        elf_path.to_string()
    } else {
        format!("{} {}", elf_path, args_str)
    };

    ui::info(&format!("Starting image: {}", elf_path));
    shell::replace_process("limactl", &["shell", config::VM_NAME, "bash", "-c", &cmd])
}

fn shell_escape(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') || s.contains('"') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

fn cmd_stop(name: Option<&str>, all: bool) -> Result<()> {
    match (name, all) {
        (Some(n), _) => microvm::stop_vm(n),
        (None, true) => microvm::stop_all_vms(),
        (None, false) => {
            // Default: stop all VMs (both named and legacy)
            let vms = microvm::list_vms().unwrap_or_default();
            if !vms.is_empty() {
                microvm::stop_all_vms()
            } else {
                microvm::stop()
            }
        }
    }
}

fn cmd_ssh() -> Result<()> {
    // `mvm ssh` is now an alias for `mvm shell` — drops into the Lima VM.
    // MicroVMs never have SSH enabled; use vsock for guest communication.
    cmd_shell(None, 8, 16)
}

fn cmd_ssh_config() -> Result<()> {
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    let lima_ssh_config = format!("{}/.lima/{}/ssh.config", home_dir, config::VM_NAME);

    // Parse Lima's ssh.config for the forwarded port and identity file
    let (hostname, port, user, identity) =
        parse_lima_ssh_config(&lima_ssh_config).unwrap_or_else(|| {
            (
                "127.0.0.1".to_string(),
                "# <port>  # run 'mvm setup' first".to_string(),
                std::env::var("USER").unwrap_or_else(|_| "lima".to_string()),
                format!("{}/.lima/_config/user", home_dir),
            )
        });

    println!(
        r#"# mvm Lima VM — add to ~/.ssh/config
Host mvm
    HostName {hostname}
    Port {port}
    User {user}
    IdentityFile {identity}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR"#,
        hostname = hostname,
        port = port,
        user = user,
        identity = identity,
    );
    Ok(())
}

/// Parse Lima's generated ssh.config to extract Hostname, Port, User, IdentityFile.
fn parse_lima_ssh_config(path: &str) -> Option<(String, String, String, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut hostname = None;
    let mut port = None;
    let mut user = None;
    let mut identity = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("Hostname ") {
            hostname = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("Port ") {
            port = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("User ") {
            user = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("IdentityFile ") {
            identity = Some(val.trim().trim_matches('"').to_string());
        }
    }

    Some((hostname?, port?, user?, identity?))
}

fn cmd_shell(project: Option<&str>, _lima_cpus: u32, _lima_mem: u32) -> Result<()> {
    lima::require_running()?;

    // Print welcome banner with tool versions
    let fc_ver =
        shell::run_in_vm_stdout("firecracker --version 2>/dev/null | head -1").unwrap_or_default();
    let nix_ver = shell::run_in_vm_stdout("nix --version 2>/dev/null").unwrap_or_default();

    ui::info("mvm development shell");
    ui::info(&format!(
        "  Firecracker: {}",
        if fc_ver.trim().is_empty() {
            "not installed"
        } else {
            fc_ver.trim()
        }
    ));
    ui::info(&format!(
        "  Nix:         {}",
        if nix_ver.trim().is_empty() {
            "not installed"
        } else {
            nix_ver.trim()
        }
    ));
    let mvm_in_vm = shell::run_in_vm_stdout("test -f /usr/local/bin/mvm && echo yes || echo no")
        .unwrap_or_default();
    if mvm_in_vm.trim() == "yes" {
        let mvm_ver =
            shell::run_in_vm_stdout("/usr/local/bin/mvm --version 2>/dev/null").unwrap_or_default();
        ui::info(&format!(
            "  mvm:         {}",
            if mvm_ver.trim().is_empty() {
                "installed"
            } else {
                mvm_ver.trim()
            }
        ));
    } else {
        ui::warn("  mvm not installed in VM. Run 'mvm sync' to build and install it.");
    }

    ui::info(&format!("  Lima VM:     {}\n", config::VM_NAME));

    match project {
        Some(path) => {
            let cmd = format!("cd {} && exec bash -l", shell_escape(path));
            shell::replace_process("limactl", &["shell", config::VM_NAME, "bash", "-c", &cmd])
        }
        None => shell::replace_process("limactl", &["shell", config::VM_NAME]),
    }
}

fn sync_deps_script() -> String {
    "dpkg -s build-essential binutils lld pkg-config libssl-dev >/dev/null 2>&1 || \
     (sudo apt-get update -qq && \
      sudo apt-get install -y -qq build-essential binutils lld pkg-config libssl-dev)"
        .to_string()
}

fn sync_rustup_script() -> String {
    "export PATH=\"$HOME/.cargo/bin:$PATH\"; \
     if command -v rustup >/dev/null 2>&1; then \
       rustup update stable --no-self-update 2>/dev/null || true; \
     else \
       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable; \
     fi && \
     if [ -f \"$HOME/.cargo/env\" ]; then . \"$HOME/.cargo/env\"; fi && \
     rustc --version"
        .to_string()
}

fn sync_build_script(source_dir: &str, debug: bool, vm_arch: &str) -> String {
    let release_flag = if debug { "" } else { " --release" };
    let target_dir = format!("target/linux-{}", vm_arch);
    format!(
        "export PATH=\"$HOME/.cargo/bin:$PATH\" && \
         if [ -f \"$HOME/.cargo/env\" ]; then . \"$HOME/.cargo/env\"; fi && \
         cd '{}' && \
         CARGO_TARGET_DIR='{}' cargo build{} --bin mvm",
        source_dir.replace('\'', "'\\''"),
        target_dir,
        release_flag,
    )
}

fn sync_install_script(source_dir: &str, debug: bool, vm_arch: &str) -> String {
    let profile = if debug { "debug" } else { "release" };
    let target_dir = format!("target/linux-{}", vm_arch);
    format!(
        "sudo install -m 0755 \
         '{src}/{target}/{profile}/mvm' \
         /usr/local/bin/",
        src = source_dir.replace('\'', "'\\''"),
        target = target_dir,
        profile = profile,
    )
}

fn cmd_sync(debug: bool, skip_deps: bool, force: bool) -> Result<()> {
    if !bootstrap::is_lima_required() && !force {
        ui::info("Native Linux detected. The host mvm binary is already Linux-native.");
        ui::info("No sync needed — mvm is already available. Use --force to rebuild anyway.");
        return Ok(());
    }

    let limactl_available = shell::run_host("which", &["limactl"])
        .map(|o| o.status.success())
        .unwrap_or(false);

    if limactl_available {
        lima::require_running()?;
    } else if shell::inside_lima() {
        ui::info("Running inside Lima guest; skipping limactl check.");
    } else if bootstrap::is_lima_required() {
        anyhow::bail!(
            "Lima is required but 'limactl' is not available. Install Lima or run inside the Lima VM."
        );
    } else {
        ui::warn("limactl not found; proceeding on native host.");
    }

    let vm_arch = shell::run_in_vm_stdout("uname -m")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let source_dir = std::env::current_dir()
        .context("Failed to determine current directory")?
        .to_string_lossy()
        .to_string();

    let profile_name = if debug { "debug" } else { "release" };
    let total_steps: u32 = if skip_deps { 2 } else { 4 };
    let mut step = 0u32;

    // Fast-path: skip if already matching version unless forced
    if !force {
        let desired_version = env!("CARGO_PKG_VERSION");
        if let Ok(current) =
            shell::run_in_vm_stdout("/usr/local/bin/mvm --version 2>/dev/null || true")
            && current.contains(desired_version)
        {
            ui::success(&format!(
                "mvm {} already installed inside Lima VM. Use --force to rebuild.",
                desired_version
            ));
            return Ok(());
        }
    }

    if !skip_deps {
        step += 1;
        ui::step(step, total_steps, "Ensuring build dependencies (apt)...");
        shell::run_in_vm_visible(&sync_deps_script())?;

        step += 1;
        ui::step(step, total_steps, "Ensuring Rust toolchain...");
        shell::run_in_vm_visible(&sync_rustup_script())?;
    }

    step += 1;
    let build_msg = format!("Building mvm ({profile_name} profile)...");
    ui::step(step, total_steps, &build_msg);
    shell::run_in_vm_visible(&sync_build_script(&source_dir, debug, &vm_arch))?;

    step += 1;
    ui::step(
        step,
        total_steps,
        "Installing binaries to /usr/local/bin/...",
    );
    shell::run_in_vm_visible(&sync_install_script(&source_dir, debug, &vm_arch))?;

    let version = shell::run_in_vm_stdout("/usr/local/bin/mvm --version")
        .unwrap_or_else(|_| "unknown".to_string());
    ui::success(&format!("Sync complete! Installed: {}", version.trim()));
    ui::info("The mvm binary is now available inside 'mvm shell'.");

    Ok(())
}

fn cmd_logs(name: &str, follow: bool, lines: u32, hypervisor: bool) -> Result<()> {
    microvm::logs(name, follow, lines, hypervisor)
}

fn cmd_status() -> Result<()> {
    ui::status_header();

    ui::status_line("Platform:", &mvm_core::platform::current().to_string());

    if bootstrap::is_lima_required() {
        let lima_status = lima::get_status()?;
        match lima_status {
            lima::LimaStatus::NotFound => {
                ui::status_line("Lima VM:", "Not created (run 'mvm setup')");
                ui::status_line("Firecracker:", "-");
                ui::status_line("MicroVM:", "-");
                return Ok(());
            }
            lima::LimaStatus::Stopped => {
                ui::status_line("Lima VM:", "Stopped");
                ui::status_line("Firecracker:", "-");
                ui::status_line("MicroVM:", "-");
                return Ok(());
            }
            lima::LimaStatus::Running => {
                ui::status_line("Lima VM:", "Running");
            }
        }
    } else {
        ui::status_line("Lima VM:", "Not required (native KVM)");
    }

    // Show tool versions inside the VM
    let nix_ver = shell::run_in_vm_stdout("nix --version 2>/dev/null").unwrap_or_default();
    let nix_display = nix_ver.trim();
    ui::status_line(
        "Nix:",
        if nix_display.is_empty() {
            "Not installed"
        } else {
            nix_display
        },
    );

    if firecracker::is_running()? {
        ui::status_line("Firecracker:", "Running");
    } else {
        if firecracker::is_installed()? {
            let fc_ver = shell::run_in_vm_stdout("firecracker --version 2>/dev/null | head -1")
                .unwrap_or_default();
            let fc_display = fc_ver.trim();
            let status = if fc_display.is_empty() {
                "Installed, not running".to_string()
            } else {
                format!("{}, not running", fc_display)
            };
            ui::status_line("Firecracker:", &status);
        } else {
            ui::status_line("Firecracker:", "Not installed");
        }
        ui::status_line("MicroVM:", "Not running");
        return Ok(());
    }

    // Show running named VMs (multi-VM mode)
    let vms = microvm::list_vms().unwrap_or_default();
    if !vms.is_empty() {
        // Check vsock availability for each VM
        let abs_vms =
            shell::run_in_vm_stdout(&format!("echo {}", config::VMS_DIR)).unwrap_or_default();
        let vsock_check = shell::run_in_vm_stdout(&format!(
            "for d in {dir}/*/; do \
                name=$(basename \"$d\"); \
                [ -S \"$d/v.sock\" ] && echo \"$name:yes\" || echo \"$name:no\"; \
            done",
            dir = abs_vms,
        ))
        .unwrap_or_default();
        let vsock_map: std::collections::HashMap<&str, &str> = vsock_check
            .lines()
            .filter_map(|line| line.split_once(':'))
            .collect();

        ui::status_line("MicroVMs:", &format!("{} running", vms.len()));
        println!();
        println!(
            "  {:<16} {:<10} {:<16} {:<14} {:<8} STATUS",
            "NAME", "PROFILE", "GUEST IP", "REVISION", "VSOCK"
        );
        println!("  {}", "-".repeat(78));
        for vm in &vms {
            let name = vm.name.as_deref().unwrap_or("?");
            let profile = vm.profile.as_deref().unwrap_or("default");
            let ip = vm.guest_ip.as_deref().unwrap_or("?");
            let rev = vm
                .revision
                .as_deref()
                .map(|r| if r.len() > 10 { &r[..10] } else { r })
                .unwrap_or("?");
            let vsock = vsock_map.get(name).copied().unwrap_or("?");
            println!(
                "  {:<16} {:<10} {:<16} {:<14} {:<8} Running",
                name, profile, ip, rev, vsock
            );
        }
    } else if let Some(info) = microvm::read_run_info()
        && info.mode == "flake"
    {
        // Legacy single-VM run info
        let rev = info.revision.as_deref().unwrap_or("unknown");
        let ip = info.guest_ip.as_deref().unwrap_or(config::GUEST_IP);
        ui::status_line(
            "MicroVM:",
            &format!("Running — flake (revision {}, guest IP {})", rev, ip),
        );
    } else {
        ui::status_line(
            "MicroVM:",
            &format!("Running (guest IP {})", config::GUEST_IP),
        );
    }

    Ok(())
}

fn cmd_upgrade(check: bool, force: bool) -> Result<()> {
    upgrade::upgrade(check, force)
}

fn cmd_doctor(json: bool) -> Result<()> {
    crate::doctor::run(json)
}

// ============================================================================
// Error hints
// ============================================================================

/// Wrap a command result with actionable hints for common errors.
fn with_hints(result: Result<()>) -> Result<()> {
    if let Err(ref e) = result {
        let msg = format!("{:#}", e);
        if msg.contains("limactl: command not found") || msg.contains("limactl: not found") {
            ui::warn("Hint: Install Lima with 'brew install lima' or run 'mvm bootstrap'.");
        } else if msg.contains("firecracker: command not found")
            || msg.contains("firecracker: not found")
        {
            ui::warn("Hint: Run 'mvm setup' to install Firecracker.");
        } else if msg.contains("/dev/kvm") {
            ui::warn(
                "Hint: Enable KVM/virtualization in your BIOS or VM settings.\n      \
                 On macOS, KVM is available inside the Lima VM.",
            );
        } else if msg.contains("Permission denied") && msg.contains("/var/lib/mvm") {
            ui::warn("Hint: Check directory permissions on /var/lib/mvm or run with sudo.");
        } else if msg.contains("nix: command not found") || msg.contains("nix: not found") {
            ui::warn("Hint: Nix is installed inside the Lima VM. Run 'mvm shell' first.");
        }
    }
    result
}

// ============================================================================
// Release commands
// ============================================================================

/// Crates to publish in dependency order.
const PUBLISH_CRATES: &[&str] = &[
    "mvm-core",
    "mvm-guest",
    "mvm-build",
    "mvm-runtime",
    "mvm-cli",
    "mvm",
];

fn cmd_release(dry_run: bool, guard_only: bool) -> Result<()> {
    let workspace_root = find_workspace_root()?;

    ui::info("Running deploy guard checks...\n");

    // 1. Extract workspace version
    let cargo_toml_path = workspace_root.join("Cargo.toml");
    let cargo_toml =
        std::fs::read_to_string(&cargo_toml_path).context("Failed to read workspace Cargo.toml")?;

    let workspace_version = extract_workspace_version(&cargo_toml)?;
    ui::status_line("Workspace version:", &workspace_version);

    // 2. Check all crates use workspace version (no hardcoded versions)
    let crates_dir = workspace_root.join("crates");
    check_no_hardcoded_versions(&crates_dir)?;
    ui::success("All crates use version.workspace = true");

    // 3. Check inter-crate dependency versions match
    check_inter_crate_versions(&workspace_root, &workspace_version)?;
    ui::success(&format!(
        "All inter-crate dependencies use version {}",
        workspace_version
    ));

    // 4. Check git tag
    let tag_name = format!("v{}", workspace_version);
    match check_git_tag(&tag_name) {
        Ok(()) => ui::success(&format!("HEAD is tagged with {}", tag_name)),
        Err(e) => ui::warn(&format!("Tag check: {} (ok for pre-release)", e)),
    }

    if guard_only {
        ui::success("\nDeploy guard checks passed.");
        return Ok(());
    }

    if !dry_run {
        anyhow::bail!(
            "Live publish not supported from CLI. Use --dry-run for local validation,\n\
             or trigger the publish-crates GitHub Action for real releases."
        );
    }

    // 5. Run cargo publish --dry-run for each crate
    ui::info("\nRunning cargo publish --dry-run for all crates...\n");

    let mut failed = Vec::new();
    for (idx, crate_name) in PUBLISH_CRATES.iter().enumerate() {
        ui::step(
            (idx + 1) as u32,
            PUBLISH_CRATES.len() as u32,
            &format!("Checking {}", crate_name),
        );

        let output = std::process::Command::new("cargo")
            .args([
                "publish",
                "-p",
                crate_name,
                "--dry-run",
                "--allow-dirty",
                "--no-verify",
            ])
            .current_dir(&workspace_root)
            .output()
            .with_context(|| format!("Failed to run cargo publish for {}", crate_name))?;

        if output.status.success() {
            ui::success(&format!("  {} passed", crate_name));
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            ui::warn(&format!("  {} failed: {}", crate_name, stderr.trim()));
            failed.push(*crate_name);
        }
    }

    println!();
    if failed.is_empty() {
        ui::success("All crates passed dry-run! Ready to publish.");
    } else {
        ui::warn(&format!(
            "{} crate(s) failed dry-run (expected if deps not yet on crates.io):",
            failed.len()
        ));
        for name in &failed {
            ui::warn(&format!("  - {}", name));
        }
    }

    Ok(())
}

/// Find the workspace root by walking up from cwd looking for Cargo.toml with [workspace].
fn find_workspace_root() -> Result<std::path::PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            let content = std::fs::read_to_string(&candidate)?;
            if content.contains("[workspace]") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            anyhow::bail!("Could not find workspace root (no Cargo.toml with [workspace])");
        }
    }
}

/// Extract workspace version from Cargo.toml content.
fn extract_workspace_version(cargo_toml: &str) -> Result<String> {
    let mut in_workspace_package = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_workspace_package = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_workspace_package = false;
            continue;
        }
        if in_workspace_package
            && trimmed.starts_with("version")
            && let Some(version) = trimmed.split('"').nth(1)
        {
            return Ok(version.to_string());
        }
    }
    anyhow::bail!("Could not find version in [workspace.package]")
}

/// Verify no crate has a hardcoded version (all must use version.workspace = true).
fn check_no_hardcoded_versions(crates_dir: &std::path::Path) -> Result<()> {
    for entry in std::fs::read_dir(crates_dir)? {
        let entry = entry?;
        let cargo_toml = entry.path().join("Cargo.toml");
        if !cargo_toml.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&cargo_toml)?;
        for line in content.lines() {
            let trimmed = line.trim();
            // Match "version = " at the start of a line (not inside a dependency spec)
            if trimmed.starts_with("version = \"") {
                let crate_name = entry.file_name().to_string_lossy().to_string();
                anyhow::bail!(
                    "Hardcoded version in {}: {}\nUse 'version.workspace = true' instead.",
                    crate_name,
                    trimmed
                );
            }
        }
    }
    Ok(())
}

/// Verify inter-crate dependency versions match the workspace version.
fn check_inter_crate_versions(workspace_root: &std::path::Path, expected: &str) -> Result<()> {
    let mut files_to_check = vec![workspace_root.join("Cargo.toml")];
    let crates_dir = workspace_root.join("crates");
    if crates_dir.is_dir() {
        for entry in std::fs::read_dir(&crates_dir)? {
            let entry = entry?;
            let cargo_toml = entry.path().join("Cargo.toml");
            if cargo_toml.is_file() {
                files_to_check.push(cargo_toml);
            }
        }
    }

    for path in &files_to_check {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            // Match: mvm-<name> = { path = "...", version = "X.Y.Z" }
            if trimmed.starts_with("mvm-")
                && trimmed.contains("version = \"")
                && let Some(version) = trimmed
                    .split("version = \"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                && version != expected
            {
                let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                anyhow::bail!(
                    "Version mismatch in {}: found '{}', expected '{}'\n  Line: {}",
                    file_name,
                    version,
                    expected,
                    trimmed
                );
            }
        }
    }
    Ok(())
}

/// Check if HEAD is tagged with the expected tag name.
fn check_git_tag(expected_tag: &str) -> Result<()> {
    let output = std::process::Command::new("git")
        .args(["tag", "--points-at", "HEAD"])
        .output()
        .context("Failed to run git tag")?;

    let tags = String::from_utf8_lossy(&output.stdout);
    let tag_list: Vec<&str> = tags.lines().collect();

    if tag_list.contains(&expected_tag) {
        Ok(())
    } else {
        let current = if tag_list.is_empty() {
            "<none>".to_string()
        } else {
            tag_list.join(", ")
        };
        anyhow::bail!(
            "HEAD is not tagged with {}. Current tags: {}",
            expected_tag,
            current
        )
    }
}

fn cmd_build(path: &str, output: Option<&str>) -> Result<()> {
    let elf_path = image::build(path, output)?;
    ui::success(&format!("\nImage ready: {}", elf_path));
    ui::info(&format!("Run with: mvm start {}", elf_path));
    Ok(())
}

fn cmd_build_flake(flake_ref: &str, profile: Option<&str>, watch: bool) -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let resolved = resolve_flake_ref(flake_ref)?;

    let env = mvm_runtime::build_env::RuntimeBuildEnv;
    let watch_enabled = watch && !resolved.contains(':');

    if watch && resolved.contains(':') {
        ui::warn("Watch mode requires a local flake; running a single build instead.");
    }

    let mut last_mtime = std::fs::metadata(format!("{}/flake.lock", resolved))
        .and_then(|m| m.modified())
        .ok();

    loop {
        let profile_display = profile.unwrap_or("default");
        ui::step(
            1,
            2,
            &format!("Building flake {} (profile={})", resolved, profile_display),
        );

        let result = mvm_build::dev_build::dev_build(&env, &resolved, profile)?;
        mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result)?;

        ui::step(2, 2, "Build complete");

        if result.cached {
            ui::success(&format!("\nCache hit — revision {}", result.revision_hash));
        } else {
            ui::success(&format!(
                "\nBuild complete — revision {}",
                result.revision_hash
            ));
        }

        ui::info(&format!("  Kernel: {}", result.vmlinux_path));
        ui::info(&format!("  Rootfs: {}", result.rootfs_path));
        ui::info(&format!("\nRun with: mvm run --flake {}", flake_ref));

        if !watch_enabled {
            return Ok(());
        }

        // Watch mode: wait for flake.lock mtime change
        ui::info("Watching flake.lock for changes (Ctrl+C to exit)...");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let new_mtime = std::fs::metadata(format!("{}/flake.lock", resolved))
                .and_then(|m| m.modified())
                .ok();
            if new_mtime.is_some() && new_mtime != last_mtime {
                last_mtime = new_mtime;
                break;
            }
        }
    }
}

/// Resolve a flake reference: relative/absolute paths are canonicalized,
/// remote refs (containing `:`) pass through unchanged.
fn resolve_flake_ref(flake_ref: &str) -> Result<String> {
    if flake_ref.contains(':') {
        // Remote ref like "github:user/repo" — pass through
        return Ok(flake_ref.to_string());
    }

    // Local path — canonicalize to absolute
    let path = std::path::Path::new(flake_ref);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Flake path '{}' does not exist", flake_ref))?;

    Ok(canonical.to_string_lossy().to_string())
}

fn cmd_run(
    flake_ref: &str,
    name: Option<&str>,
    profile: Option<&str>,
    cpus: Option<u32>,
    memory: Option<u32>,
    config_path: Option<&str>,
    volumes: &[String],
) -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let resolved = resolve_flake_ref(flake_ref)?;
    let profile_display = profile.unwrap_or("default");

    // Generate a VM name if not provided
    let vm_name = match name {
        Some(n) => n.to_string(),
        None => {
            let mut generator = names::Generator::default();
            generator.next().unwrap_or_else(|| "vm-0".to_string())
        }
    };

    ui::step(
        1,
        2,
        &format!(
            "Building flake {} (profile={}, name={})",
            resolved, profile_display, vm_name
        ),
    );

    let env = mvm_runtime::build_env::RuntimeBuildEnv;
    let result = mvm_build::dev_build::dev_build(&env, &resolved, profile)?;
    mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result)?;

    if result.cached {
        ui::info(&format!("Cache hit — revision {}", result.revision_hash));
    } else {
        ui::info(&format!(
            "Build complete — revision {}",
            result.revision_hash
        ));
    }

    ui::step(2, 2, &format!("Booting Firecracker VM '{}'", vm_name));

    let rt_config = match config_path {
        Some(p) => image::parse_runtime_config(p)?,
        None => image::RuntimeConfig::default(),
    };

    let volume_cfg: Vec<image::RuntimeVolume> = if !volumes.is_empty() {
        volumes
            .iter()
            .map(|v| parse_runtime_volume(v))
            .collect::<Result<_>>()?
    } else {
        rt_config.volumes.clone()
    };

    const DEFAULT_CPUS: u32 = 2;
    const DEFAULT_MEM: u32 = 1024;

    let final_cpus = cpus.or(rt_config.cpus).unwrap_or(DEFAULT_CPUS);
    let final_memory = memory.or(rt_config.memory).unwrap_or(DEFAULT_MEM);

    // Allocate a network slot for this VM
    let slot = microvm::allocate_slot(&vm_name)?;

    let run_config = microvm::FlakeRunConfig {
        name: vm_name,
        slot,
        vmlinux_path: result.vmlinux_path,
        initrd_path: result.initrd_path,
        rootfs_path: result.rootfs_path,
        revision_hash: result.revision_hash,
        flake_ref: flake_ref.to_string(),
        profile: profile.map(|s| s.to_string()),
        cpus: final_cpus,
        memory: final_memory,
        volumes: volume_cfg,
    };

    microvm::run_from_build(&run_config)
}

fn parse_runtime_volume(spec: &str) -> Result<image::RuntimeVolume> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 {
        anyhow::bail!(
            "Invalid volume '{}'. Expected format host_path:guest_mount:size",
            spec
        );
    }
    Ok(image::RuntimeVolume {
        host: parts[0].to_string(),
        guest: parts[1].to_string(),
        size: parts[2].to_string(),
    })
}

// ============================================================================
// Fleet commands (mvm up / mvm down)
// ============================================================================

fn cmd_up(
    name: Option<&str>,
    config_path: Option<&str>,
    flake: Option<&str>,
    profile: Option<&str>,
    cpus: Option<u32>,
    memory: Option<u32>,
) -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    // Try to load fleet config (explicit path > auto-discover > none)
    let fleet_found = load_fleet_config(config_path)?;

    match (fleet_found, flake) {
        // Fleet mode: config file found (with optional CLI overrides)
        (Some((fleet_config, base_dir)), _) => {
            // CLI --flake overrides config file flake
            let flake_ref = match flake {
                Some(f) => resolve_flake_ref(f)?,
                None => {
                    let flake_path = base_dir.join(&fleet_config.flake);
                    resolve_flake_ref(&flake_path.to_string_lossy())?
                }
            };

            // Filter to requested VM or all
            let vm_names: Vec<String> = match name {
                Some(n) => {
                    if !fleet_config.vms.contains_key(n) {
                        let available: Vec<&str> =
                            fleet_config.vms.keys().map(|s| s.as_str()).collect();
                        anyhow::bail!(
                            "VM '{}' not defined in config. Available: {:?}",
                            n,
                            available
                        );
                    }
                    vec![n.to_string()]
                }
                None => fleet_config.vms.keys().cloned().collect(),
            };

            if vm_names.is_empty() {
                anyhow::bail!("No VMs defined in config. Add [vms.<name>] sections.");
            }

            // Build once per unique profile (deduplication)
            // CLI --profile overrides all VMs when set
            let profiles: std::collections::BTreeSet<Option<String>> = vm_names
                .iter()
                .filter_map(|n| fleet_config.vms.get(n))
                .map(|vm| {
                    profile.map(|p| p.to_string()).or_else(|| {
                        vm.profile
                            .clone()
                            .or_else(|| fleet_config.defaults.profile.clone())
                    })
                })
                .collect();

            let builds = build_profiles(&profiles, &flake_ref)?;

            // Launch each VM
            let total = vm_names.len();
            for (idx, vm_name) in vm_names.iter().enumerate() {
                let mut resolved = fleet::resolve_vm(&fleet_config, vm_name)?;

                // CLI flags override config values
                if let Some(p) = profile {
                    resolved.profile = Some(p.to_string());
                }
                if let Some(c) = cpus {
                    resolved.cpus = c;
                }
                if let Some(m) = memory {
                    resolved.memory = m;
                }

                let build_result = builds.get(&resolved.profile).ok_or_else(|| {
                    anyhow::anyhow!("No build for profile {:?}", resolved.profile)
                })?;

                let volumes: Vec<image::RuntimeVolume> = resolved
                    .volumes
                    .iter()
                    .map(|v| parse_runtime_volume(v))
                    .collect::<Result<_>>()?;

                ui::step(
                    (idx + 1) as u32,
                    total as u32,
                    &format!("Launching VM '{}'", vm_name),
                );

                let slot = microvm::allocate_slot(vm_name)?;

                let run_config = microvm::FlakeRunConfig {
                    name: vm_name.clone(),
                    slot,
                    vmlinux_path: build_result.vmlinux_path.clone(),
                    initrd_path: build_result.initrd_path.clone(),
                    rootfs_path: build_result.rootfs_path.clone(),
                    revision_hash: build_result.revision_hash.clone(),
                    flake_ref: flake_ref.clone(),
                    profile: resolved.profile,
                    cpus: resolved.cpus,
                    memory: resolved.memory,
                    volumes,
                };

                microvm::run_from_build(&run_config)?;
            }

            ui::success(&format!("{} VMs running", vm_names.len()));
            Ok(())
        }

        // Single VM mode: no config file, use CLI flags
        (None, Some(flake_ref)) => {
            let resolved_flake = resolve_flake_ref(flake_ref)?;

            let vm_name = match name {
                Some(n) => n.to_string(),
                None => {
                    let mut generator = names::Generator::default();
                    generator.next().unwrap_or_else(|| "vm-0".to_string())
                }
            };

            const DEFAULT_CPUS: u32 = 2;
            const DEFAULT_MEM: u32 = 1024;

            let env = mvm_runtime::build_env::RuntimeBuildEnv;
            let result = mvm_build::dev_build::dev_build(&env, &resolved_flake, profile)?;
            mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result)?;

            let slot = microvm::allocate_slot(&vm_name)?;

            let run_config = microvm::FlakeRunConfig {
                name: vm_name,
                slot,
                vmlinux_path: result.vmlinux_path,
                initrd_path: result.initrd_path,
                rootfs_path: result.rootfs_path,
                revision_hash: result.revision_hash,
                flake_ref: flake_ref.to_string(),
                profile: profile.map(|s| s.to_string()),
                cpus: cpus.unwrap_or(DEFAULT_CPUS),
                memory: memory.unwrap_or(DEFAULT_MEM),
                volumes: vec![],
            };

            microvm::run_from_build(&run_config)
        }

        // No config, no flake — nothing to do
        (None, None) => {
            anyhow::bail!(
                "No mvm.toml found and no --flake specified.\n\
                 Use 'mvm up --flake <path>' or create an mvm.toml."
            );
        }
    }
}

/// Load fleet config from an explicit path or auto-discover mvm.toml.
fn load_fleet_config(
    config_path: Option<&str>,
) -> Result<Option<(fleet::FleetConfig, std::path::PathBuf)>> {
    match config_path {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path))?;
            let config: fleet::FleetConfig =
                toml::from_str(&content).with_context(|| format!("Failed to parse {}", path))?;
            let dir = std::path::Path::new(path)
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            Ok(Some((config, dir)))
        }
        None => fleet::find_fleet_config(),
    }
}

/// Build once per unique profile. Returns map from profile -> build result.
fn build_profiles(
    profiles: &std::collections::BTreeSet<Option<String>>,
    resolved_flake: &str,
) -> Result<std::collections::HashMap<Option<String>, mvm_build::dev_build::DevBuildResult>> {
    let mut builds = std::collections::HashMap::new();
    let env = mvm_runtime::build_env::RuntimeBuildEnv;

    for (idx, profile) in profiles.iter().enumerate() {
        let label = profile.as_deref().unwrap_or("default");
        ui::step(
            (idx + 1) as u32,
            profiles.len() as u32,
            &format!("Building profile '{}'", label),
        );

        let result = mvm_build::dev_build::dev_build(&env, resolved_flake, profile.as_deref())?;
        mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result)?;

        if result.cached {
            ui::info(&format!("Cache hit — revision {}", result.revision_hash));
        } else {
            ui::info(&format!(
                "Build complete — revision {}",
                result.revision_hash
            ));
        }

        builds.insert(profile.clone(), result);
    }
    Ok(builds)
}

fn cmd_down(name: Option<&str>, config_path: Option<&str>) -> Result<()> {
    match name {
        Some(n) => microvm::stop_vm(n),
        None => {
            let found = load_fleet_config(config_path)?;
            if let Some((fleet_config, _base_dir)) = found {
                let mut stopped = 0;
                for vm_name in fleet_config.vms.keys() {
                    if microvm::stop_vm(vm_name).is_ok() {
                        stopped += 1;
                    }
                }

                // Clean up bridge if no VMs remain
                let remaining = microvm::list_vms().unwrap_or_default();
                if remaining.is_empty() {
                    let _ = mvm_runtime::vm::network::bridge_teardown();
                }

                ui::success(&format!("Stopped {} VMs", stopped));
                Ok(())
            } else {
                microvm::stop_all_vms()
            }
        }
    }
}

fn cmd_completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "mvm", &mut std::io::stdout());
    Ok(())
}

fn cmd_destroy(yes: bool) -> Result<()> {
    let status = lima::get_status()?;

    if matches!(status, lima::LimaStatus::NotFound) {
        ui::info("Nothing to destroy. Lima VM does not exist.");
        return Ok(());
    }

    if matches!(status, lima::LimaStatus::Running) && firecracker::is_running()? {
        microvm::stop()?;
    }

    if !yes && !ui::confirm("This will delete the Lima VM and all microVM data. Continue?") {
        ui::info("Cancelled.");
        return Ok(());
    }

    ui::info("Destroying Lima VM...");
    lima::destroy()?;
    ui::success("Destroyed.");
    Ok(())
}

// ============================================================================
// Template commands
// ============================================================================

fn cmd_template(action: TemplateCmd) -> Result<()> {
    match action {
        TemplateCmd::Create {
            name,
            flake,
            profile,
            role,
            cpus,
            mem,
            data_disk,
        } => template_cmd::create_single(&name, &flake, &profile, &role, cpus, mem, data_disk),
        TemplateCmd::CreateMulti {
            base,
            flake,
            profile,
            roles,
            cpus,
            mem,
            data_disk,
        } => {
            let role_list: Vec<String> = roles.split(',').map(|s| s.trim().to_string()).collect();
            template_cmd::create_multi(&base, &flake, &profile, &role_list, cpus, mem, data_disk)
        }
        TemplateCmd::Build {
            name,
            force,
            config,
        } => template_cmd::build(&name, force, config.as_deref()),
        TemplateCmd::Push { name, revision } => template_cmd::push(&name, revision.as_deref()),
        TemplateCmd::Pull { name, revision } => template_cmd::pull(&name, revision.as_deref()),
        TemplateCmd::Verify { name, revision } => template_cmd::verify(&name, revision.as_deref()),
        TemplateCmd::List { json } => template_cmd::list(json),
        TemplateCmd::Info { name, json } => template_cmd::info(&name, json),
        TemplateCmd::Delete { name, force } => template_cmd::delete(&name, force),
        TemplateCmd::Init {
            name,
            local,
            vm,
            dir,
        } => {
            let use_local = local && !vm;
            template_cmd::init(&name, use_local, &dir)
        }
    }
}

// ============================================================================
// VM interaction commands (vsock)
// ============================================================================

fn cmd_vm(action: VmCmd) -> Result<()> {
    match action {
        VmCmd::Ping { name: Some(name) } => cmd_vm_ping(&name),
        VmCmd::Ping { name: None } => cmd_vm_ping_all(),
        VmCmd::Status {
            name: Some(name),
            json,
        } => cmd_vm_status(&name, json),
        VmCmd::Status { name: None, json } => cmd_vm_status_all(json),
    }
}

/// Resolve a VM name to its absolute directory path inside the Lima VM
/// and verify it is running.
fn resolve_running_vm(name: &str) -> Result<String> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let abs_vms = shell::run_in_vm_stdout(&format!("echo {}", config::VMS_DIR))?;
    let abs_dir = format!("{}/{}", abs_vms, name);
    let pid_file = format!("{}/fc.pid", abs_dir);

    if !firecracker::is_vm_running(&pid_file)? {
        anyhow::bail!(
            "VM '{}' is not running. Use 'mvm status' to list running VMs.",
            name
        );
    }

    Ok(abs_dir)
}

fn cmd_vm_ping(name: &str) -> Result<()> {
    let abs_dir = resolve_running_vm(name)?;

    // Vsock UDS lives inside the Lima VM — delegate when on macOS
    if bootstrap::is_lima_required() {
        let mvm_installed =
            shell::run_in_vm_stdout("test -f /usr/local/bin/mvm && echo yes || echo no")?;
        if mvm_installed.trim() != "yes" {
            anyhow::bail!("mvm is not installed inside the Lima VM. Run 'mvm sync' first.");
        }
        shell::run_in_vm_visible(&format!("/usr/local/bin/mvm vm ping {}", name))?;
        return Ok(());
    }

    // Native Linux / inside Lima — call vsock directly
    let vsock_path = format!("{}/v.sock", abs_dir);
    match mvm_guest::vsock::ping_at(&vsock_path) {
        Ok(true) => {
            ui::success(&format!("VM '{}' is alive (pong received)", name));
            Ok(())
        }
        Ok(false) => {
            ui::error(&format!("VM '{}' did not respond to ping", name));
            anyhow::bail!("Ping failed")
        }
        Err(e) => {
            ui::error(&format!("Failed to connect to VM '{}': {}", name, e));
            Err(e)
        }
    }
}

fn cmd_vm_status(name: &str, json: bool) -> Result<()> {
    let abs_dir = resolve_running_vm(name)?;

    // Vsock UDS lives inside the Lima VM — delegate when on macOS
    if bootstrap::is_lima_required() {
        let mvm_installed =
            shell::run_in_vm_stdout("test -f /usr/local/bin/mvm && echo yes || echo no")?;
        if mvm_installed.trim() != "yes" {
            anyhow::bail!("mvm is not installed inside the Lima VM. Run 'mvm sync' first.");
        }
        let json_flag = if json { " --json" } else { "" };
        shell::run_in_vm_visible(&format!(
            "/usr/local/bin/mvm vm status {}{}",
            name, json_flag
        ))?;
        return Ok(());
    }

    // Native Linux / inside Lima — call vsock directly
    let vsock_path = format!("{}/v.sock", abs_dir);
    let resp = mvm_guest::vsock::query_worker_status_at(&vsock_path)
        .with_context(|| format!("Failed to query status for VM '{}'", name))?;

    match resp {
        mvm_guest::vsock::GuestResponse::WorkerStatus {
            status,
            last_busy_at,
        } => {
            // Query integration health (best-effort — old agents return empty list)
            let integrations =
                mvm_guest::vsock::query_integration_status_at(&vsock_path).unwrap_or_default();

            if json {
                let integration_json: Vec<serde_json::Value> = integrations
                    .iter()
                    .map(|ig| {
                        serde_json::json!({
                            "name": ig.name,
                            "status": ig.status,
                            "healthy": ig.health.as_ref().map(|h| h.healthy),
                            "detail": ig.health.as_ref().map(|h| &h.detail),
                            "checked_at": ig.health.as_ref().map(|h| &h.checked_at),
                        })
                    })
                    .collect();
                let obj = serde_json::json!({
                    "name": name,
                    "worker_status": status,
                    "last_busy_at": last_busy_at,
                    "integrations": integration_json,
                });
                println!("{}", serde_json::to_string_pretty(&obj)?);
            } else {
                ui::status_line("VM:", name);
                ui::status_line("Worker status:", &status);
                let busy = last_busy_at.as_deref().unwrap_or("never");
                ui::status_line("Last busy:", busy);
                if !integrations.is_empty() {
                    println!();
                    ui::status_line(
                        "Integrations:",
                        &format!("{} registered", integrations.len()),
                    );
                    for ig in &integrations {
                        let health_str = match &ig.health {
                            Some(h) if h.healthy => "healthy".to_string(),
                            Some(h) => format!("unhealthy: {}", h.detail),
                            None => "pending".to_string(),
                        };
                        println!("  {:<24} {}", ig.name, health_str);
                    }
                }
            }
            Ok(())
        }
        mvm_guest::vsock::GuestResponse::Error { message } => {
            anyhow::bail!("Guest agent error: {}", message)
        }
        _ => anyhow::bail!("Unexpected response from guest agent"),
    }
}

/// List all running VMs and return their names.
fn list_running_vm_names() -> Result<Vec<String>> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }
    let vms = microvm::list_vms().unwrap_or_default();
    Ok(vms.into_iter().filter_map(|vm| vm.name).collect())
}

fn cmd_vm_ping_all() -> Result<()> {
    // Delegate to Lima on macOS — run as single command
    if bootstrap::is_lima_required() {
        lima::require_running()?;
        shell::run_in_vm_visible("/usr/local/bin/mvm vm ping")?;
        return Ok(());
    }

    let names = list_running_vm_names()?;
    if names.is_empty() {
        ui::info("No running VMs found.");
        return Ok(());
    }

    let mut any_failed = false;
    for name in &names {
        let abs_dir = format!(
            "{}/{}",
            shell::run_in_vm_stdout(&format!("echo {}", config::VMS_DIR))?,
            name
        );
        let vsock_path = format!("{}/v.sock", abs_dir);
        match mvm_guest::vsock::ping_at(&vsock_path) {
            Ok(true) => ui::success(&format!("VM '{}' is alive (pong received)", name)),
            Ok(false) => {
                ui::error(&format!("VM '{}' did not respond to ping", name));
                any_failed = true;
            }
            Err(e) => {
                ui::error(&format!("VM '{}': {}", name, e));
                any_failed = true;
            }
        }
    }
    if any_failed {
        anyhow::bail!("Some VMs did not respond to ping");
    }
    Ok(())
}

fn cmd_vm_status_all(json: bool) -> Result<()> {
    // Delegate to Lima on macOS
    if bootstrap::is_lima_required() {
        lima::require_running()?;
        let json_flag = if json { " --json" } else { "" };
        shell::run_in_vm_visible(&format!("/usr/local/bin/mvm vm status{}", json_flag))?;
        return Ok(());
    }

    let names = list_running_vm_names()?;
    if names.is_empty() {
        if json {
            println!("[]");
        } else {
            ui::info("No running VMs found.");
        }
        return Ok(());
    }

    if json {
        let mut results = Vec::new();
        for name in &names {
            match cmd_vm_status_json(name) {
                Ok(obj) => results.push(obj),
                Err(e) => results.push(serde_json::json!({
                    "name": name,
                    "error": e.to_string(),
                })),
            }
        }
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        let integ_header = "INTEGRATIONS";
        println!(
            "  {:<16} {:<10} {:<24} {}",
            "NAME", "STATUS", "LAST BUSY", integ_header
        );
        println!("  {}", "-".repeat(66));
        for name in &names {
            match cmd_vm_status_row(name) {
                Ok((status, last_busy, integrations)) => {
                    let busy = last_busy.as_deref().unwrap_or("never");
                    println!(
                        "  {:<16} {:<10} {:<24} {}",
                        name, status, busy, integrations
                    );
                }
                Err(e) => {
                    println!("  {:<16} {:<10} {}", name, "error", e);
                }
            }
        }
    }
    Ok(())
}

/// Query a single VM's status and return the JSON value.
fn cmd_vm_status_json(name: &str) -> Result<serde_json::Value> {
    let abs_dir = resolve_running_vm(name)?;
    let vsock_path = format!("{}/v.sock", abs_dir);
    let resp = mvm_guest::vsock::query_worker_status_at(&vsock_path)?;
    match resp {
        mvm_guest::vsock::GuestResponse::WorkerStatus {
            status,
            last_busy_at,
        } => {
            let integrations =
                mvm_guest::vsock::query_integration_status_at(&vsock_path).unwrap_or_default();
            let integration_json: Vec<serde_json::Value> = integrations
                .iter()
                .map(|ig| {
                    serde_json::json!({
                        "name": ig.name,
                        "status": ig.status,
                        "healthy": ig.health.as_ref().map(|h| h.healthy),
                        "detail": ig.health.as_ref().map(|h| &h.detail),
                        "checked_at": ig.health.as_ref().map(|h| &h.checked_at),
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "name": name,
                "worker_status": status,
                "last_busy_at": last_busy_at,
                "integrations": integration_json,
            }))
        }
        mvm_guest::vsock::GuestResponse::Error { message } => {
            anyhow::bail!("Guest agent error: {}", message)
        }
        _ => anyhow::bail!("Unexpected response"),
    }
}

/// Query a single VM's status and return (status, last_busy_at, integrations_summary).
fn cmd_vm_status_row(name: &str) -> Result<(String, Option<String>, String)> {
    let abs_dir = resolve_running_vm(name)?;
    let vsock_path = format!("{}/v.sock", abs_dir);
    let resp = mvm_guest::vsock::query_worker_status_at(&vsock_path)?;
    match resp {
        mvm_guest::vsock::GuestResponse::WorkerStatus {
            status,
            last_busy_at,
        } => {
            let integrations =
                mvm_guest::vsock::query_integration_status_at(&vsock_path).unwrap_or_default();
            let summary = if integrations.is_empty() {
                "-".to_string()
            } else {
                let healthy = integrations
                    .iter()
                    .filter(|ig| ig.health.as_ref().is_some_and(|h| h.healthy))
                    .count();
                format!("{}/{} healthy", healthy, integrations.len())
            };
            Ok((status, last_busy_at, summary))
        }
        mvm_guest::vsock::GuestResponse::Error { message } => {
            anyhow::bail!("Guest agent error: {}", message)
        }
        _ => anyhow::bail!("Unexpected response"),
    }
}

// ============================================================================
// Utilities
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_sync_command_parses() {
        let cli = Cli::try_parse_from(["mvm", "sync"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Sync {
                debug: false,
                skip_deps: false,
                force: false,
            }
        ));
    }

    #[test]
    fn test_sync_debug_flag() {
        let cli = Cli::try_parse_from(["mvm", "sync", "--debug"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Sync {
                debug: true,
                skip_deps: false,
                force: false,
            }
        ));
    }

    #[test]
    fn test_sync_skip_deps_flag() {
        let cli = Cli::try_parse_from(["mvm", "sync", "--skip-deps"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Sync {
                debug: false,
                skip_deps: true,
                force: false
            }
        ));
    }

    #[test]
    fn test_sync_both_flags() {
        let cli = Cli::try_parse_from(["mvm", "sync", "--debug", "--skip-deps"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Sync {
                debug: true,
                skip_deps: true,
                force: false,
            }
        ));
    }

    #[test]
    fn test_sync_build_script_release() {
        let script = sync_build_script("/home/user/mvm", false, "aarch64");
        assert!(script.contains("--release"));
        assert!(script.contains("CARGO_TARGET_DIR='target/linux-aarch64'"));
        assert!(script.contains("--bin mvm"));
        assert!(script.contains("cd '/home/user/mvm'"));
    }

    #[test]
    fn test_sync_build_script_debug() {
        let script = sync_build_script("/home/user/mvm", true, "aarch64");
        assert!(!script.contains("--release"));
        assert!(script.contains("CARGO_TARGET_DIR='target/linux-aarch64'"));
        assert!(script.contains("--bin mvm"));
    }

    #[test]
    fn test_sync_build_script_x86_64() {
        let script = sync_build_script("/home/user/mvm", false, "x86_64");
        assert!(script.contains("CARGO_TARGET_DIR='target/linux-x86_64'"));
    }

    #[test]
    fn test_sync_install_script_release() {
        let script = sync_install_script("/home/user/mvm", false, "aarch64");
        assert!(script.contains("/target/linux-aarch64/release/mvm"));
        assert!(script.contains("/usr/local/bin/"));
        assert!(script.contains("install -m 0755"));
    }

    #[test]
    fn test_sync_install_script_debug() {
        let script = sync_install_script("/home/user/mvm", true, "aarch64");
        assert!(script.contains("/target/linux-aarch64/debug/mvm"));
    }

    #[test]
    fn test_sync_deps_script_checks_before_installing() {
        let script = sync_deps_script();
        assert!(script.contains("dpkg -s"));
        assert!(script.contains("apt-get install"));
    }

    #[test]
    fn test_sync_rustup_script_idempotent() {
        let script = sync_rustup_script();
        assert!(script.contains("command -v rustup"));
        assert!(script.contains("rustup update stable"));
        assert!(script.contains("rustup.rs"));
        assert!(script.contains("rustc --version"));
    }

    // ---- Build --flake tests ----

    #[test]
    fn test_build_flake_with_profile() {
        let cli =
            Cli::try_parse_from(["mvm", "build", "--flake", ".", "--profile", "gateway"]).unwrap();
        match cli.command {
            Commands::Build { flake, profile, .. } => {
                assert_eq!(flake.as_deref(), Some("."));
                assert_eq!(profile.as_deref(), Some("gateway"));
            }
            _ => panic!("Expected Build command"),
        }
    }

    #[test]
    fn test_build_flake_defaults_to_no_profile() {
        let cli = Cli::try_parse_from(["mvm", "build", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Build { flake, profile, .. } => {
                assert_eq!(flake.as_deref(), Some("."));
                assert!(profile.is_none(), "profile should be None when omitted");
            }
            _ => panic!("Expected Build command"),
        }
    }

    #[test]
    fn test_build_mvmfile_mode_still_works() {
        let cli = Cli::try_parse_from(["mvm", "build", "myimage"]).unwrap();
        match cli.command {
            Commands::Build { path, flake, .. } => {
                assert_eq!(path, "myimage");
                assert!(flake.is_none(), "Mvmfile mode should have no --flake");
            }
            _ => panic!("Expected Build command"),
        }
    }

    #[test]
    fn test_resolve_flake_ref_remote_passthrough() {
        let resolved = resolve_flake_ref("github:user/repo").unwrap();
        assert_eq!(resolved, "github:user/repo");
    }

    #[test]
    fn test_resolve_flake_ref_remote_with_path() {
        let resolved = resolve_flake_ref("github:user/repo#attr").unwrap();
        assert_eq!(resolved, "github:user/repo#attr");
    }

    #[test]
    fn test_resolve_flake_ref_absolute_path() {
        let resolved = resolve_flake_ref("/tmp").unwrap();
        // /tmp may be a symlink on macOS to /private/tmp
        assert!(
            resolved == "/tmp" || resolved == "/private/tmp",
            "unexpected resolved path: {}",
            resolved
        );
    }

    #[test]
    fn test_resolve_flake_ref_nonexistent_fails() {
        let result = resolve_flake_ref("/nonexistent/path/that/does/not/exist");
        assert!(result.is_err());
    }

    // ---- Run command tests ----

    #[test]
    fn test_run_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "mvm",
            "run",
            "--flake",
            ".",
            "--profile",
            "full",
            "--cpus",
            "4",
            "--memory",
            "2048",
        ])
        .unwrap();
        match cli.command {
            Commands::Run {
                flake,
                profile,
                cpus,
                memory,
                name: _,
                volume: _,
                config: _,
            } => {
                assert_eq!(flake, ".");
                assert_eq!(profile.as_deref(), Some("full"));
                assert_eq!(cpus, Some(4));
                assert_eq!(memory, Some(2048));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_defaults() {
        let cli = Cli::try_parse_from(["mvm", "run", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Run {
                flake,
                name,
                profile,
                cpus,
                memory,
                config: _,
                volume,
            } => {
                assert_eq!(flake, ".");
                assert!(name.is_none(), "name should be None when omitted");
                assert!(profile.is_none(), "profile should be None when omitted");
                assert_eq!(cpus, Some(2));
                assert_eq!(memory, Some(1024));
                assert_eq!(volume.len(), 0);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_requires_flake() {
        let result = Cli::try_parse_from(["mvm", "run"]);
        assert!(result.is_err(), "run should require --flake");
    }

    // ---- VM subcommand tests ----

    #[test]
    fn test_vm_ping_parses() {
        let cli = Cli::try_parse_from(["mvm", "vm", "ping", "happy-panda"]).unwrap();
        match cli.command {
            Commands::Vm {
                action: VmCmd::Ping { name },
            } => {
                assert_eq!(name.as_deref(), Some("happy-panda"));
            }
            _ => panic!("Expected Vm Ping command"),
        }
    }

    #[test]
    fn test_vm_ping_no_name_targets_all() {
        let cli = Cli::try_parse_from(["mvm", "vm", "ping"]).unwrap();
        match cli.command {
            Commands::Vm {
                action: VmCmd::Ping { name },
            } => {
                assert!(name.is_none(), "no name means ping all");
            }
            _ => panic!("Expected Vm Ping command"),
        }
    }

    #[test]
    fn test_vm_status_parses() {
        let cli = Cli::try_parse_from(["mvm", "vm", "status", "my-vm"]).unwrap();
        match cli.command {
            Commands::Vm {
                action: VmCmd::Status { name, json },
            } => {
                assert_eq!(name.as_deref(), Some("my-vm"));
                assert!(!json);
            }
            _ => panic!("Expected Vm Status command"),
        }
    }

    #[test]
    fn test_vm_status_no_name_targets_all() {
        let cli = Cli::try_parse_from(["mvm", "vm", "status"]).unwrap();
        match cli.command {
            Commands::Vm {
                action: VmCmd::Status { name, json },
            } => {
                assert!(name.is_none(), "no name means status all");
                assert!(!json);
            }
            _ => panic!("Expected Vm Status command"),
        }
    }

    #[test]
    fn test_vm_status_json_flag() {
        let cli = Cli::try_parse_from(["mvm", "vm", "status", "my-vm", "--json"]).unwrap();
        match cli.command {
            Commands::Vm {
                action: VmCmd::Status { name, json },
            } => {
                assert_eq!(name.as_deref(), Some("my-vm"));
                assert!(json);
            }
            _ => panic!("Expected Vm Status command"),
        }
    }

    #[test]
    fn test_vm_requires_subcommand() {
        let result = Cli::try_parse_from(["mvm", "vm"]);
        assert!(result.is_err(), "vm should require a subcommand");
    }

    // ---- Up/Down command tests ----

    #[test]
    fn test_up_parses_no_args() {
        let cli = Cli::try_parse_from(["mvm", "up"]).unwrap();
        match cli.command {
            Commands::Up {
                name,
                config,
                flake,
                profile,
                cpus,
                memory,
            } => {
                assert!(name.is_none());
                assert!(config.is_none());
                assert!(flake.is_none());
                assert!(profile.is_none());
                assert!(cpus.is_none());
                assert!(memory.is_none());
            }
            _ => panic!("Expected Up command"),
        }
    }

    #[test]
    fn test_up_parses_with_flake() {
        let cli = Cli::try_parse_from(["mvm", "up", "--flake", "./nix/openclaw/"]).unwrap();
        match cli.command {
            Commands::Up { flake, name, .. } => {
                assert_eq!(flake.as_deref(), Some("./nix/openclaw/"));
                assert!(name.is_none());
            }
            _ => panic!("Expected Up command"),
        }
    }

    #[test]
    fn test_up_parses_with_all_flags() {
        let cli = Cli::try_parse_from([
            "mvm",
            "up",
            "gw",
            "-f",
            "fleet.toml",
            "--flake",
            ".",
            "--profile",
            "gateway",
            "--cpus",
            "4",
            "--memory",
            "2048",
        ])
        .unwrap();
        match cli.command {
            Commands::Up {
                name,
                config,
                flake,
                profile,
                cpus,
                memory,
            } => {
                assert_eq!(name.as_deref(), Some("gw"));
                assert_eq!(config.as_deref(), Some("fleet.toml"));
                assert_eq!(flake.as_deref(), Some("."));
                assert_eq!(profile.as_deref(), Some("gateway"));
                assert_eq!(cpus, Some(4));
                assert_eq!(memory, Some(2048));
            }
            _ => panic!("Expected Up command"),
        }
    }

    #[test]
    fn test_down_parses_no_args() {
        let cli = Cli::try_parse_from(["mvm", "down"]).unwrap();
        match cli.command {
            Commands::Down { name, config } => {
                assert!(name.is_none());
                assert!(config.is_none());
            }
            _ => panic!("Expected Down command"),
        }
    }

    #[test]
    fn test_down_parses_with_name() {
        let cli = Cli::try_parse_from(["mvm", "down", "gw"]).unwrap();
        match cli.command {
            Commands::Down { name, config } => {
                assert_eq!(name.as_deref(), Some("gw"));
                assert!(config.is_none());
            }
            _ => panic!("Expected Down command"),
        }
    }

    #[test]
    fn test_down_parses_with_config() {
        let cli = Cli::try_parse_from(["mvm", "down", "-f", "my-fleet.toml"]).unwrap();
        match cli.command {
            Commands::Down { name, config } => {
                assert!(name.is_none());
                assert_eq!(config.as_deref(), Some("my-fleet.toml"));
            }
            _ => panic!("Expected Down command"),
        }
    }

    // ---- Release command tests ----

    #[test]
    fn test_release_dry_run_parses() {
        let cli = Cli::try_parse_from(["mvm", "release", "--dry-run"]).unwrap();
        match cli.command {
            Commands::Release {
                dry_run,
                guard_only,
            } => {
                assert!(dry_run);
                assert!(!guard_only);
            }
            _ => panic!("Expected Release command"),
        }
    }

    #[test]
    fn test_release_guard_only_parses() {
        let cli = Cli::try_parse_from(["mvm", "release", "--guard-only"]).unwrap();
        match cli.command {
            Commands::Release {
                dry_run,
                guard_only,
            } => {
                assert!(!dry_run);
                assert!(guard_only);
            }
            _ => panic!("Expected Release command"),
        }
    }

    #[test]
    fn test_release_no_flags_parses() {
        let cli = Cli::try_parse_from(["mvm", "release"]).unwrap();
        match cli.command {
            Commands::Release {
                dry_run,
                guard_only,
            } => {
                assert!(!dry_run);
                assert!(!guard_only);
            }
            _ => panic!("Expected Release command"),
        }
    }

    #[test]
    fn test_extract_workspace_version() {
        let toml = r#"
[workspace]
members = ["crates/mvm-core"]

[workspace.package]
version = "1.2.3"
edition = "2024"
"#;
        let version = extract_workspace_version(toml).unwrap();
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn test_extract_workspace_version_missing() {
        let toml = "[workspace]\nmembers = []";
        let result = extract_workspace_version(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_publish_crates_order() {
        // Foundation crate must come first, facade last
        assert_eq!(PUBLISH_CRATES[0], "mvm-core");
        assert_eq!(*PUBLISH_CRATES.last().unwrap(), "mvm");
    }
}
