use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};

use crate::bootstrap;
use crate::display;
use crate::logging::{self, LogFormat};
use crate::output::{self, OutputFormat};
use crate::ui;
use crate::upgrade;

use mvm_core::naming;
use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::{bridge, firecracker, image, lima, microvm, pool, tenant};

#[derive(Parser)]
#[command(
    name = "mvm",
    version,
    about = "Multi-tenant Firecracker microVM fleet manager"
)]
struct Cli {
    /// Output format: table, json, yaml
    #[arg(long, short = 'o', global = true, default_value = "table")]
    output: String,

    /// Override Firecracker version (e.g., v1.14.0)
    #[arg(long, global = true)]
    fc_version: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ---- Tenant management ----
    /// Manage tenants (security/quota/network boundaries)
    Tenant {
        #[command(subcommand)]
        action: TenantCmd,
    },

    // ---- Pool management ----
    /// Manage worker pools within tenants
    Pool {
        #[command(subcommand)]
        action: PoolCmd,
    },

    // ---- Instance operations ----
    /// Manage individual microVM instances
    Instance {
        #[command(subcommand)]
        action: InstanceCmd,
    },

    // ---- Agent ----
    /// Agent reconcile loop and daemon
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },

    // ---- Coordinator client ----
    /// Coordinator client for multi-node fleet management
    Coordinator {
        #[command(subcommand)]
        action: CoordinatorCmd,
    },

    // ---- Dev cluster (local) ----
    DevCluster {
        #[command(subcommand)]
        action: DevClusterCmd,
    },

    // ---- Network ----
    /// Network verification and diagnostics
    Net {
        #[command(subcommand)]
        action: NetCmd,
    },

    // ---- Node ----
    /// Node information and statistics
    Node {
        #[command(subcommand)]
        action: NodeCmd,
    },

    // ---- Dev mode (UNCHANGED) ----
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
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
    },
    /// Launch into microVM, auto-bootstrapping if needed
    Dev {
        /// Number of vCPUs for the Lima VM
        #[arg(long, default_value = "8")]
        lima_cpus: u32,
        /// Memory (GiB) for the Lima VM
        #[arg(long, default_value = "16")]
        lima_mem: u32,
    },
    /// Start the microVM and drop into interactive SSH
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
    /// Stop the running microVM and clean up
    Stop,
    /// SSH into a running microVM
    Ssh,
    /// Print an SSH config entry for ~/.ssh/config
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
    /// Show status of Lima VM and microVM
    Status,
    /// Tear down Lima VM and all resources
    Destroy,
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
    Doctor,
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
        /// Guest profile (flake mode, default: minimal)
        #[arg(long, default_value = "minimal")]
        profile: String,
        /// Instance role (flake mode, default: worker)
        #[arg(long, default_value = "worker")]
        role: String,
        /// Watch flake.lock and rebuild on change (flake mode)
        #[arg(long)]
        watch: bool,
    },
    /// Build from a Nix flake, boot a Firecracker VM, and drop into SSH
    Run {
        /// Nix flake reference (local path or remote URI)
        #[arg(long)]
        flake: String,
        /// Guest profile (default: minimal)
        #[arg(long, default_value = "minimal")]
        profile: String,
        /// Instance role (default: worker)
        #[arg(long, default_value = "worker")]
        role: String,
        /// vCPU cores
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory in MiB
        #[arg(long)]
        memory: Option<u32>,
        /// Guest SSH user
        #[arg(long, default_value = "root")]
        user: String,
        /// Runtime config (TOML) for persistent resources/volumes
        #[arg(long)]
        config: Option<String>,
        /// Volume override (format: host_path:guest_mount:size). Repeatable.
        #[arg(long, short = 'v')]
        volume: Vec<String>,
        /// Boot in background, don't drop into SSH
        #[arg(long)]
        detach: bool,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Tail audit events for a tenant
    Events {
        /// Tenant ID
        tenant: String,
        /// Number of recent events to show
        #[arg(long, short = 'n', default_value = "20")]
        last: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    // ---- Onboarding ----
    /// Prepare a host to join the fleet
    Add {
        #[command(subcommand)]
        action: AddCmd,
    },

    /// Create a deployment from a built-in template
    New {
        /// Template name (e.g., "openclaw")
        template: String,
        /// Deployment name (becomes tenant ID)
        name: String,
        /// Override auto-allocated network ID
        #[arg(long)]
        net_id: Option<u16>,
        /// Override auto-computed subnet (CIDR)
        #[arg(long)]
        subnet: Option<String>,
        /// Override template's default flake reference
        #[arg(long)]
        flake: Option<String>,
        /// Config file with secrets and resource overrides (TOML)
        #[arg(long)]
        config: Option<String>,
    },

    /// Deploy from a standalone manifest file
    Deploy {
        /// Path to deployment manifest (TOML)
        manifest: String,
        /// Watch mode: re-reconcile at interval
        #[arg(long)]
        watch: bool,
        /// Watch interval in seconds (default: 30)
        #[arg(long, default_value = "30")]
        interval: u64,
    },

    /// Show deployment dashboard (gateway, instances, connection info)
    Connect {
        /// Deployment name (tenant ID)
        name: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

// --- Tenant subcommands ---

#[derive(Subcommand)]
enum TenantCmd {
    /// Create a new tenant
    Create {
        /// Tenant ID (lowercase alphanumeric + hyphens)
        id: String,
        /// Coordinator-assigned network ID (0-4095, cluster-unique)
        #[arg(long)]
        net_id: u16,
        /// Coordinator-assigned IPv4 subnet (CIDR), e.g. "10.240.3.0/24"
        #[arg(long)]
        subnet: String,
        /// Maximum vCPUs across all instances
        #[arg(long, default_value = "16")]
        max_vcpus: u32,
        /// Maximum memory in MiB across all instances
        #[arg(long, default_value = "32768")]
        max_mem: u64,
        /// Maximum concurrently running instances
        #[arg(long, default_value = "8")]
        max_running: u32,
        /// Maximum warm instances
        #[arg(long, default_value = "4")]
        max_warm: u32,
    },
    /// List all tenants on this node
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show tenant details
    Info {
        /// Tenant ID
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Destroy a tenant and all its resources
    Destroy {
        /// Tenant ID
        id: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
        /// Also wipe persistent volumes
        #[arg(long)]
        wipe_volumes: bool,
    },
    /// Set tenant secrets from a file
    Secrets {
        #[command(subcommand)]
        action: TenantSecretsCmd,
    },
}

#[derive(Subcommand)]
enum TenantSecretsCmd {
    /// Set secrets from a JSON file
    Set {
        /// Tenant ID
        id: String,
        /// Path to secrets JSON file
        #[arg(long)]
        from_file: String,
    },
    /// Rotate secrets (bump epoch)
    Rotate {
        /// Tenant ID
        id: String,
    },
}

// --- Pool subcommands ---

#[derive(Subcommand)]
enum PoolCmd {
    /// Create a new pool within a tenant
    Create {
        /// Pool path: <tenant>/<pool>
        path: String,
        /// Nix flake reference
        #[arg(long)]
        flake: String,
        /// Guest profile: minimal, baseline, python
        #[arg(long)]
        profile: String,
        /// Instance role: gateway, worker, builder
        #[arg(long, default_value = "worker")]
        role: String,
        /// vCPUs per instance
        #[arg(long)]
        cpus: u8,
        /// Memory per instance (MiB)
        #[arg(long)]
        mem: u32,
        /// Data disk per instance (MiB)
        #[arg(long, default_value = "0")]
        data_disk: u32,
    },
    /// List pools in a tenant
    List {
        /// Tenant ID
        tenant: String,
        #[arg(long)]
        json: bool,
    },
    /// Show pool details
    Info {
        /// Pool path: <tenant>/<pool>
        path: String,
        #[arg(long)]
        json: bool,
    },
    /// Build pool artifacts (ephemeral Firecracker builder VM)
    Build {
        /// Pool path: <tenant>/<pool>
        path: String,
        /// Build timeout in seconds
        #[arg(long)]
        timeout: Option<u64>,
        /// Builder vCPUs
        #[arg(long)]
        builder_cpus: Option<u8>,
        /// Builder memory (MiB)
        #[arg(long)]
        builder_mem: Option<u32>,
    },
    /// Scale pool desired counts
    Scale {
        /// Pool path: <tenant>/<pool>
        path: String,
        /// Desired running instances
        #[arg(long)]
        running: Option<u32>,
        /// Desired warm instances
        #[arg(long)]
        warm: Option<u32>,
        /// Desired sleeping instances
        #[arg(long)]
        sleeping: Option<u32>,
    },
    /// Destroy a pool and all its instances
    Destroy {
        /// Pool path: <tenant>/<pool>
        path: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
    /// Clean up old build revisions for a pool
    Gc {
        /// Pool path: <tenant>/<pool>
        path: String,
        /// Number of revisions to keep
        #[arg(long, default_value = "2")]
        keep: usize,
    },
}

// --- Instance subcommands ---

#[derive(Subcommand)]
enum InstanceCmd {
    /// Create a new instance in a pool
    Create {
        /// Pool path: <tenant>/<pool>
        path: String,
    },
    /// List instances
    List {
        /// Filter by tenant
        #[arg(long)]
        tenant: Option<String>,
        /// Filter by pool (requires --tenant)
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Start an instance
    Start {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
    },
    /// Stop an instance
    Stop {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
    },
    /// Pause vCPUs (Running → Warm)
    Warm {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
    },
    /// Snapshot and shutdown (Warm → Sleeping)
    Sleep {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
        /// Skip guest prep ACK, force snapshot
        #[arg(long)]
        force: bool,
    },
    /// Restore from snapshot (Sleeping → Running)
    Wake {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
    },
    /// SSH into a running instance
    #[command(name = "ssh")]
    Ssh {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
    },
    /// Show instance stats
    Stats {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
        #[arg(long)]
        json: bool,
    },
    /// Destroy an instance
    Destroy {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
        /// Also wipe persistent volumes
        #[arg(long)]
        wipe_volumes: bool,
    },
    /// View instance logs
    Logs {
        /// Instance path: <tenant>/<pool>/<instance>
        path: String,
    },
}

// --- Agent subcommands ---

#[derive(Subcommand)]
enum AgentCmd {
    /// Run a single reconcile pass against a desired state file
    Reconcile {
        /// Path to desired state JSON
        #[arg(long)]
        desired: String,
        /// Destroy tenants/pools not in desired state
        #[arg(long)]
        prune: bool,
    },
    /// Start the agent daemon (reconcile loop + QUIC API)
    Serve {
        /// Reconcile interval in seconds
        #[arg(long, default_value = "30")]
        interval_secs: u64,
        /// Path to desired state file (alternative to QUIC push)
        #[arg(long)]
        desired: Option<String>,
        /// Listen address for QUIC API
        #[arg(long)]
        listen: Option<String>,
    },
    /// Generate desired state JSON from existing tenants and pools
    Desired {
        /// Write to file instead of stdout
        #[arg(long)]
        file: Option<String>,
        /// Node identifier
        #[arg(long, default_value = "local")]
        node_id: String,
    },
    /// Manage mTLS certificates for agent communication
    Certs {
        #[command(subcommand)]
        action: AgentCertsCmd,
    },
}

#[derive(Subcommand)]
enum AgentCertsCmd {
    /// Initialize with a CA certificate
    Init {
        /// Path to CA certificate PEM file (omit for self-signed dev CA)
        #[arg(long)]
        ca: Option<String>,
    },
    /// Rotate the node certificate
    Rotate,
    /// Show certificate status
    Status {
        #[arg(long)]
        json: bool,
    },
}

// --- Coordinator subcommands ---

#[derive(Subcommand)]
enum CoordinatorCmd {
    /// Push desired state to a remote node
    Push {
        /// Path to desired state JSON file
        #[arg(long)]
        desired: String,
        /// Remote node address (host:port)
        #[arg(long)]
        node: String,
    },
    /// Query node status
    Status {
        /// Remote node address (host:port)
        #[arg(long)]
        node: String,
    },
    /// List instances on a remote node
    ListInstances {
        /// Remote node address (host:port)
        #[arg(long)]
        node: String,
        /// Tenant ID to filter by
        #[arg(long)]
        tenant: String,
        /// Optional pool ID filter
        #[arg(long)]
        pool: Option<String>,
    },
    /// Wake a sleeping instance on a remote node
    Wake {
        /// Remote node address (host:port)
        #[arg(long)]
        node: String,
        /// Tenant ID
        #[arg(long)]
        tenant: String,
        /// Pool ID
        #[arg(long)]
        pool: String,
        /// Instance ID
        #[arg(long)]
        instance: String,
    },
    /// Run the coordinator server (TCP proxy with on-demand wake)
    Serve {
        /// Path to coordinator TOML config file
        #[arg(long)]
        config: String,
    },
    /// Display the routing table from a coordinator config
    Routes {
        /// Path to coordinator TOML config file
        #[arg(long)]
        config: String,
    },
}

#[derive(Subcommand)]
enum DevClusterCmd {
    /// Generate dev cluster config + certs
    Init,
    /// Start agent + coordinator in background
    Up,
    /// Show status of dev cluster processes
    Status,
    /// Stop dev cluster processes
    Down,
}

// --- Network subcommands ---

#[derive(Subcommand)]
enum NetCmd {
    /// Verify network configuration for all tenants
    Verify {
        #[arg(long)]
        json: bool,
    },
}

// --- Node subcommands ---

#[derive(Subcommand)]
enum NodeCmd {
    /// Show node information
    Info {
        #[arg(long)]
        json: bool,
    },
    /// Show aggregate node statistics
    Stats {
        #[arg(long)]
        json: bool,
    },
    /// Show disk usage report
    Disk {
        #[arg(long)]
        json: bool,
    },
    /// Run garbage collection across all pools
    Gc {
        /// Number of revisions to keep per pool
        #[arg(long, default_value = "2")]
        keep: usize,
    },
}

// --- Add subcommands ---

#[derive(Subcommand)]
enum AddCmd {
    /// Prepare this machine to join the fleet (bootstrap + certs + signing key)
    Host {
        /// Path to CA certificate PEM file (omit for self-signed dev CA)
        #[arg(long)]
        ca: Option<String>,
        /// Path to coordinator's Ed25519 public key file
        #[arg(long)]
        signing_key: Option<String>,
        /// Enable production mode checks
        #[arg(long)]
        production: bool,
    },
}

// ============================================================================
// Command dispatch
// ============================================================================

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    // Apply FC version override before anything reads it.
    // SAFETY: called once at startup before any threads are spawned.
    if let Some(ref version) = cli.fc_version {
        unsafe { std::env::set_var("MVM_FC_VERSION", version) };
    }

    // Initialize logging: JSON for daemon mode, human-readable for CLI
    let log_format = match &cli.command {
        Commands::Agent {
            action: AgentCmd::Serve { .. },
        } => LogFormat::Json,
        _ => LogFormat::Human,
    };
    logging::init(log_format);

    let out_fmt = OutputFormat::from_str_arg(&cli.output);

    match cli.command {
        // --- Dev mode (unchanged) ---
        Commands::Bootstrap { production } => cmd_bootstrap(production),
        Commands::Setup {
            recreate,
            lima_cpus,
            lima_mem,
        } => cmd_setup(recreate, lima_cpus, lima_mem),
        Commands::Dev {
            lima_cpus,
            lima_mem,
        } => cmd_dev(lima_cpus, lima_mem),
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
        Commands::Stop => cmd_stop(),
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
        Commands::Status => cmd_status(),
        Commands::Destroy => cmd_destroy(),
        Commands::Upgrade { check, force } => cmd_upgrade(check, force),
        Commands::Doctor => cmd_doctor(),
        Commands::Build {
            path,
            output,
            flake,
            profile,
            role,
            watch,
        } => {
            if let Some(flake_ref) = flake {
                cmd_build_flake(&flake_ref, &profile, &role, watch)
            } else {
                cmd_build(&path, output.as_deref())
            }
        }
        Commands::Run {
            flake,
            profile,
            role,
            cpus,
            memory,
            user,
            config,
            volume,
            detach,
        } => cmd_run(
            &flake,
            &profile,
            &role,
            cpus,
            memory,
            &user,
            config.as_deref(),
            &volume,
            detach,
        ),
        Commands::Completions { shell } => cmd_completions(shell),
        Commands::Events { tenant, last, json } => cmd_events(&tenant, last, json),

        // --- Multi-tenant ---
        Commands::Tenant { action } => cmd_tenant(action, out_fmt),
        Commands::Pool { action } => cmd_pool(action, out_fmt),
        Commands::Instance { action } => cmd_instance(action, out_fmt),
        Commands::Agent { action } => cmd_agent(action),
        Commands::Coordinator { action } => cmd_coordinator(action, out_fmt),
        Commands::DevCluster { action } => cmd_dev_cluster(action),
        Commands::Net { action } => cmd_net(action, out_fmt),
        Commands::Node { action } => cmd_node(action, out_fmt),

        // --- Onboarding ---
        Commands::Add { action } => cmd_add(action),
        Commands::New {
            template,
            name,
            net_id,
            subnet,
            flake,
            config,
        } => cmd_new(
            &template,
            &name,
            net_id,
            subnet.as_deref(),
            flake.as_deref(),
            config.as_deref(),
        ),
        Commands::Deploy {
            manifest,
            watch,
            interval,
        } => cmd_deploy(&manifest, watch, interval),
        Commands::Connect { name, json } => cmd_connect(&name, json),
    }
}

// ============================================================================
// Dev mode handlers (unchanged except bootstrap)
// ============================================================================

fn cmd_bootstrap(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");

    if !production {
        bootstrap::check_package_manager()?;
    }

    ui::info("\nInstalling prerequisites...");
    bootstrap::ensure_lima()?;

    // Bootstrap uses default Lima resources (8 vCPUs, 16 GiB)
    run_setup_steps(8, 16)?;

    ui::success("\nBootstrap complete! Run 'mvm start' or 'mvm dev' to launch a microVM.");
    Ok(())
}

fn cmd_setup(recreate: bool, lima_cpus: u32, lima_mem: u32) -> Result<()> {
    if recreate {
        recreate_rootfs()?;
        ui::success("\nRootfs recreated! Run 'mvm start' or 'mvm dev' to launch.");
        return Ok(());
    }

    if !bootstrap::is_lima_required() {
        // Native Linux — just install FC directly
        run_setup_steps(lima_cpus, lima_mem)?;
        ui::success("\nSetup complete! Run 'mvm start' to launch a microVM.");
        return Ok(());
    }

    which::which("limactl").map_err(|_| {
        anyhow::anyhow!(
            "'limactl' not found. Install Lima first: brew install lima\n\
             Or run 'mvm bootstrap' for full automatic setup."
        )
    })?;

    run_setup_steps(lima_cpus, lima_mem)?;

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

fn cmd_dev(lima_cpus: u32, lima_mem: u32) -> Result<()> {
    ui::info("Launching development environment...\n");

    if bootstrap::is_lima_required() {
        // macOS or Linux without KVM — need Lima
        if which::which("limactl").is_err() {
            ui::info("Lima not found. Running bootstrap...\n");
            cmd_bootstrap(false)?;
            return microvm::start();
        }

        let lima_status = lima::get_status()?;
        match lima_status {
            lima::LimaStatus::NotFound => {
                ui::info("Lima VM not found. Running setup...\n");
                run_setup_steps(lima_cpus, lima_mem)?;
                return microvm::start();
            }
            lima::LimaStatus::Stopped => {
                ui::info("Lima VM is stopped. Starting...");
                lima::start()?;
            }
            lima::LimaStatus::Running => {}
        }
    }

    if !firecracker::is_installed()? {
        ui::info("Firecracker not installed. Running setup steps...\n");
        firecracker::install()?;
        firecracker::download_assets()?;
        firecracker::prepare_rootfs()?;
        firecracker::write_state()?;
        return microvm::start();
    }

    if firecracker::is_running()? {
        if microvm::is_ssh_reachable()? {
            ui::info("MicroVM is already running. Connecting...\n");
            return microvm::ssh();
        }
        ui::warn("Firecracker running but microVM not reachable.");
        ui::info("Stopping and restarting...");
        microvm::stop()?;
    }

    microvm::start()
}

fn run_setup_steps(lima_cpus: u32, lima_mem: u32) -> Result<()> {
    if bootstrap::is_lima_required() {
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
        ui::info(&format!(
            "Using rendered Lima config: {}",
            lima_yaml.path().display()
        ));

        ui::step(1, 4, "Setting up Lima VM...");
        lima::ensure_running(lima_yaml.path())?;
    } else {
        ui::step(1, 4, "Native Linux detected — skipping Lima VM setup.");
    }

    ui::step(2, 4, "Installing Firecracker...");
    firecracker::install()?;

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

fn cmd_stop() -> Result<()> {
    microvm::stop()
}

fn cmd_ssh() -> Result<()> {
    microvm::ssh()
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
    "dpkg -s build-essential pkg-config libssl-dev >/dev/null 2>&1 || \
     (sudo apt-get update -qq && \
      sudo apt-get install -y -qq build-essential pkg-config libssl-dev)"
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
         CARGO_TARGET_DIR='{}' cargo build{} --bin mvm --bin mvm-hostd",
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
         '{src}/{target}/{profile}/mvm-hostd' \
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
    } else if bootstrap::is_lima_required() {
        anyhow::bail!(
            "Lima is required but 'limactl' is not available. Install Lima or run inside the Lima VM."
        );
    } else {
        ui::warn("limactl not found; assuming we're already inside Lima and proceeding.");
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
        let pid = shell::run_in_vm_stdout("cat ~/microvm/.fc-pid 2>/dev/null || echo '?'")
            .unwrap_or_else(|_| "?".to_string());
        ui::status_line("Firecracker:", &format!("Running (PID {})", pid));
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

    // Check for flake run info to distinguish run modes
    if let Some(info) = microvm::read_run_info()
        && info.mode == "flake"
    {
        let rev = info.revision.as_deref().unwrap_or("unknown");
        ui::status_line(
            "MicroVM:",
            &format!(
                "Running — flake (revision {}, {}@{})",
                rev,
                info.guest_user,
                config::GUEST_IP
            ),
        );
    } else if microvm::is_ssh_reachable()? {
        ui::status_line(
            "MicroVM:",
            &format!("Running (SSH: {}@{})", config::GUEST_USER, config::GUEST_IP),
        );
    } else {
        ui::status_line("MicroVM:", "Starting or unreachable");
    }

    Ok(())
}

fn cmd_upgrade(check: bool, force: bool) -> Result<()> {
    upgrade::upgrade(check, force)
}

fn cmd_doctor() -> Result<()> {
    crate::doctor::run()
}

fn cmd_build(path: &str, output: Option<&str>) -> Result<()> {
    let elf_path = image::build(path, output)?;
    ui::success(&format!("\nImage ready: {}", elf_path));
    ui::info(&format!("Run with: mvm start {}", elf_path));
    Ok(())
}

fn cmd_build_flake(flake_ref: &str, profile: &str, role_str: &str, watch: bool) -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let role = parse_role(role_str)?;
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
        ui::step(
            1,
            2,
            &format!(
                "Building flake {} (profile={}, role={})",
                resolved, profile, role
            ),
        );

        let result = mvm_build::dev_build::dev_build(&env, &resolved, profile, &role)?;

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

#[allow(clippy::too_many_arguments)]
fn cmd_run(
    flake_ref: &str,
    profile: &str,
    role_str: &str,
    cpus: Option<u32>,
    memory: Option<u32>,
    guest_user: &str,
    config_path: Option<&str>,
    volumes: &[String],
    detach: bool,
) -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let role = parse_role(role_str)?;
    let resolved = resolve_flake_ref(flake_ref)?;

    ui::step(
        1,
        3,
        &format!(
            "Building flake {} (profile={}, role={})",
            resolved, profile, role
        ),
    );

    let env = mvm_runtime::build_env::RuntimeBuildEnv;
    let result = mvm_build::dev_build::dev_build(&env, &resolved, profile, &role)?;

    if result.cached {
        ui::info(&format!("Cache hit — revision {}", result.revision_hash));
    } else {
        ui::info(&format!(
            "Build complete — revision {}",
            result.revision_hash
        ));
    }

    ui::step(2, 3, "Booting Firecracker VM");

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

    let run_config = microvm::FlakeRunConfig {
        vmlinux_path: result.vmlinux_path,
        rootfs_path: result.rootfs_path,
        revision_hash: result.revision_hash,
        flake_ref: flake_ref.to_string(),
        cpus: final_cpus,
        memory: final_memory,
        guest_user: guest_user.to_string(),
        detach,
        volumes: volume_cfg,
    };

    ui::step(3, 3, "Connecting");
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

fn cmd_completions(shell: clap_complete::Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "mvm", &mut std::io::stdout());
    Ok(())
}

fn cmd_events(tenant_id: &str, last: usize, json: bool) -> Result<()> {
    let entries = mvm_runtime::security::audit::read_audit_log(tenant_id, last)?;

    if entries.is_empty() {
        ui::info(&format!("No audit events for tenant '{}'.", tenant_id));
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for entry in &entries {
            println!(
                "{} [{}] {:?}{}{}",
                entry.timestamp,
                entry.tenant_id,
                entry.action,
                entry
                    .pool_id
                    .as_ref()
                    .map(|p| format!(" pool={}", p))
                    .unwrap_or_default(),
                entry
                    .instance_id
                    .as_ref()
                    .map(|i| format!(" instance={}", i))
                    .unwrap_or_default(),
            );
        }
    }
    Ok(())
}

fn cmd_destroy() -> Result<()> {
    let status = lima::get_status()?;

    if matches!(status, lima::LimaStatus::NotFound) {
        ui::info("Nothing to destroy. Lima VM does not exist.");
        return Ok(());
    }

    if matches!(status, lima::LimaStatus::Running) && firecracker::is_running()? {
        microvm::stop()?;
    }

    if !ui::confirm("This will delete the Lima VM and all microVM data. Continue?") {
        ui::info("Cancelled.");
        return Ok(());
    }

    ui::info("Destroying Lima VM...");
    lima::destroy()?;
    ui::success("Destroyed.");
    Ok(())
}

// ============================================================================
// Multi-tenant command handlers
// ============================================================================

fn cmd_tenant(action: TenantCmd, out_fmt: OutputFormat) -> Result<()> {
    use display::{TenantInfo, TenantRow};
    use mvm_core::tenant::{TenantNet, TenantQuota};

    match action {
        TenantCmd::Create {
            id,
            net_id,
            subnet,
            max_vcpus,
            max_mem,
            max_running,
            max_warm,
        } => {
            naming::validate_id(&id, "Tenant")?;

            // Derive gateway from subnet (first usable IP)
            let gateway = mvm_agent::templates::gateway_from_subnet(&subnet)?;
            let net = TenantNet::new(net_id, &subnet, &gateway);
            let quotas = TenantQuota {
                max_vcpus,
                max_mem_mib: max_mem,
                max_running,
                max_warm,
                ..TenantQuota::default()
            };

            let config = tenant::lifecycle::tenant_create(&id, net, quotas)?;
            ui::success(&format!("Tenant '{}' created.", config.tenant_id));
            ui::info(&format!(
                "  Network: {} (bridge: {})",
                config.net.ipv4_subnet, config.net.bridge_name
            ));
            Ok(())
        }
        TenantCmd::List { json } => {
            let fmt = if json { OutputFormat::Json } else { out_fmt };
            let tenant_ids = tenant::lifecycle::tenant_list()?;

            if fmt == OutputFormat::Table && tenant_ids.is_empty() {
                ui::info("No tenants found.");
                return Ok(());
            }

            let mut rows = Vec::new();
            for tid in &tenant_ids {
                if let Ok(config) = tenant::lifecycle::tenant_load(tid) {
                    rows.push(TenantRow {
                        tenant_id: config.tenant_id,
                        subnet: config.net.ipv4_subnet,
                        bridge: config.net.bridge_name,
                        max_vcpus: config.quotas.max_vcpus,
                        max_mem_mib: config.quotas.max_mem_mib,
                    });
                } else {
                    rows.push(TenantRow {
                        tenant_id: tid.clone(),
                        subnet: "?".to_string(),
                        bridge: "?".to_string(),
                        max_vcpus: 0,
                        max_mem_mib: 0,
                    });
                }
            }
            output::render_list(&rows, fmt);
            Ok(())
        }
        TenantCmd::Info { id, json } => {
            let fmt = if json { OutputFormat::Json } else { out_fmt };
            let config = tenant::lifecycle::tenant_load(&id)?;
            let info = TenantInfo {
                tenant_id: config.tenant_id,
                subnet: config.net.ipv4_subnet,
                gateway: config.net.gateway_ip,
                bridge: config.net.bridge_name,
                net_id: config.net.tenant_net_id,
                max_vcpus: config.quotas.max_vcpus,
                max_mem_mib: config.quotas.max_mem_mib,
                max_running: config.quotas.max_running,
                max_warm: config.quotas.max_warm,
                created_at: config.created_at,
            };
            output::render_one(&info, fmt);
            Ok(())
        }
        TenantCmd::Destroy {
            id,
            force,
            wipe_volumes,
        } => {
            if !force && !ui::confirm(&format!("Destroy tenant '{}' and all its resources?", id)) {
                ui::info("Cancelled.");
                return Ok(());
            }
            // Tear down bridge before destroying tenant
            if let Ok(config) = tenant::lifecycle::tenant_load(&id) {
                let _ = bridge::destroy_tenant_bridge(&config.net);
            }
            tenant::lifecycle::tenant_destroy(&id, wipe_volumes)?;
            ui::success(&format!("Tenant '{}' destroyed.", id));
            Ok(())
        }
        TenantCmd::Secrets { action } => match action {
            TenantSecretsCmd::Set { id, from_file } => {
                tenant::secrets::secrets_set(&id, &from_file)?;
                ui::success(&format!("Secrets set for tenant '{}'.", id));
                Ok(())
            }
            TenantSecretsCmd::Rotate { id } => {
                tenant::secrets::secrets_rotate(&id)?;
                ui::success(&format!("Secrets rotated for tenant '{}'.", id));
                Ok(())
            }
        },
    }
}

fn cmd_pool(action: PoolCmd, out_fmt: OutputFormat) -> Result<()> {
    use display::{PoolInfo, PoolRow};
    use mvm_core::pool::InstanceResources;

    match action {
        PoolCmd::Create {
            path,
            flake,
            profile,
            role,
            cpus,
            mem,
            data_disk,
        } => {
            let (tenant_id, pool_id) = naming::parse_pool_path(&path)?;
            let parsed_role = parse_role(&role)?;
            let resources = InstanceResources {
                vcpus: cpus,
                mem_mib: mem,
                data_disk_mib: data_disk,
            };
            let spec = pool::lifecycle::pool_create(
                tenant_id,
                pool_id,
                &flake,
                &profile,
                resources,
                parsed_role,
            )?;
            ui::success(&format!(
                "Pool '{}/{}' created.",
                spec.tenant_id, spec.pool_id
            ));
            Ok(())
        }
        PoolCmd::List { tenant, json } => {
            let fmt = if json { OutputFormat::Json } else { out_fmt };
            let pool_ids = pool::lifecycle::pool_list(&tenant)?;

            if fmt == OutputFormat::Table && pool_ids.is_empty() {
                ui::info(&format!("No pools found for tenant '{}'.", tenant));
                return Ok(());
            }

            let mut rows = Vec::new();
            for pid in &pool_ids {
                if let Ok(spec) = pool::lifecycle::pool_load(&tenant, pid) {
                    rows.push(PoolRow {
                        pool_path: format!("{}/{}", tenant, pid),
                        role: spec.role.to_string(),
                        profile: spec.profile,
                        vcpus: spec.instance_resources.vcpus,
                        mem_mib: spec.instance_resources.mem_mib,
                        desired_running: spec.desired_counts.running,
                        desired_warm: spec.desired_counts.warm,
                        desired_sleeping: spec.desired_counts.sleeping,
                    });
                }
            }
            output::render_list(&rows, fmt);
            Ok(())
        }
        PoolCmd::Info { path, json } => {
            let fmt = if json { OutputFormat::Json } else { out_fmt };
            let (tenant_id, pool_id) = naming::parse_pool_path(&path)?;
            let spec = pool::lifecycle::pool_load(tenant_id, pool_id)?;
            let info = PoolInfo {
                pool_path: format!("{}/{}", spec.tenant_id, spec.pool_id),
                role: spec.role.to_string(),
                flake_ref: spec.flake_ref,
                profile: spec.profile,
                vcpus: spec.instance_resources.vcpus,
                mem_mib: spec.instance_resources.mem_mib,
                data_disk_mib: spec.instance_resources.data_disk_mib,
                desired_running: spec.desired_counts.running,
                desired_warm: spec.desired_counts.warm,
                desired_sleeping: spec.desired_counts.sleeping,
                seccomp_policy: spec.seccomp_policy,
            };
            output::render_one(&info, fmt);
            Ok(())
        }
        PoolCmd::Build {
            path,
            timeout,
            builder_cpus,
            builder_mem,
        } => {
            let (tenant_id, pool_id) = naming::parse_pool_path(&path)?;
            let env = mvm_runtime::build_env::RuntimeBuildEnv;
            let opts = mvm_build::build::PoolBuildOpts {
                timeout_secs: timeout,
                builder_vcpus: builder_cpus,
                builder_mem_mib: builder_mem,
            };
            mvm_build::build::pool_build_with_opts(&env, tenant_id, pool_id, opts)
        }
        PoolCmd::Scale {
            path,
            running,
            warm,
            sleeping,
        } => {
            let (tenant_id, pool_id) = naming::parse_pool_path(&path)?;
            pool::lifecycle::pool_scale(tenant_id, pool_id, running, warm, sleeping)?;
            ui::success(&format!("Pool '{}' scaled.", path));
            Ok(())
        }
        PoolCmd::Destroy { path, force } => {
            let (tenant_id, pool_id) = naming::parse_pool_path(&path)?;
            pool::lifecycle::pool_destroy(tenant_id, pool_id, force)?;
            ui::success(&format!("Pool '{}' destroyed.", path));
            Ok(())
        }
        PoolCmd::Gc { path, keep } => {
            let (tenant_id, pool_id) = naming::parse_pool_path(&path)?;
            let removed =
                mvm_runtime::vm::disk_manager::cleanup_old_revisions(tenant_id, pool_id, keep)?;
            if removed > 0 {
                ui::success(&format!(
                    "Cleaned up {} old revisions for '{}'.",
                    removed, path
                ));
            } else {
                ui::info(&format!("No old revisions to clean up for '{}'.", path));
            }
            Ok(())
        }
    }
}

fn cmd_instance(action: InstanceCmd, out_fmt: OutputFormat) -> Result<()> {
    use display::{InstanceInfo, InstanceRow};
    use mvm_runtime::vm::instance::lifecycle as inst;

    match action {
        InstanceCmd::Create { path } => {
            let (t, p) = naming::parse_pool_path(&path)?;
            let instance_id = inst::instance_create(t, p)?;
            ui::success(&format!(
                "Instance '{}' created in {}/{}.",
                instance_id, t, p
            ));
            Ok(())
        }
        InstanceCmd::List { tenant, pool, json } => {
            let fmt = if json { OutputFormat::Json } else { out_fmt };
            let tenants = match &tenant {
                Some(t) => vec![t.clone()],
                None => tenant::lifecycle::tenant_list()?,
            };

            let mut all_states = Vec::new();
            for tid in &tenants {
                let pools = match &pool {
                    Some(p) => vec![p.clone()],
                    None => pool::lifecycle::pool_list(tid)?,
                };
                for pid in &pools {
                    if let Ok(states) = inst::instance_list(tid, pid) {
                        all_states.extend(states);
                    }
                }
            }

            if fmt == OutputFormat::Table && all_states.is_empty() {
                ui::info("No instances found.");
                return Ok(());
            }

            let rows: Vec<InstanceRow> = all_states
                .iter()
                .map(|s| InstanceRow {
                    instance_path: format!("{}/{}/{}", s.tenant_id, s.pool_id, s.instance_id),
                    status: s.status.to_string(),
                    guest_ip: s.net.guest_ip.clone(),
                    tap_dev: s.net.tap_dev.clone(),
                    pid: s
                        .firecracker_pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                })
                .collect();
            output::render_list(&rows, fmt);
            Ok(())
        }
        InstanceCmd::Start { path } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            inst::instance_start(t, p, i)?;
            ui::success(&format!("Instance '{}' started.", path));
            Ok(())
        }
        InstanceCmd::Stop { path } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            inst::instance_stop(t, p, i)?;
            ui::success(&format!("Instance '{}' stopped.", path));
            Ok(())
        }
        InstanceCmd::Warm { path } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            inst::instance_warm(t, p, i)?;
            ui::success(&format!("Instance '{}' paused (warm).", path));
            Ok(())
        }
        InstanceCmd::Sleep { path, force } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            inst::instance_sleep(t, p, i, force)
        }
        InstanceCmd::Wake { path } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            inst::instance_wake(t, p, i)
        }
        InstanceCmd::Ssh { path } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            inst::instance_ssh(t, p, i)
        }
        InstanceCmd::Stats { path, json } => {
            let fmt = if json { OutputFormat::Json } else { out_fmt };
            let (t, p, i) = naming::parse_instance_path(&path)?;
            let state = inst::instance_list(t, p)?
                .into_iter()
                .find(|s| s.instance_id == i)
                .ok_or_else(|| anyhow::anyhow!("Instance not found: {}", path))?;

            let info = InstanceInfo {
                instance_path: format!("{}/{}/{}", t, p, i),
                status: state.status.to_string(),
                guest_ip: state.net.guest_ip.clone(),
                tap_dev: state.net.tap_dev.clone(),
                mac: state.net.mac.clone(),
                pid: state
                    .firecracker_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                revision: state.revision_hash.unwrap_or_else(|| "-".to_string()),
                last_started: state.last_started_at.unwrap_or_else(|| "-".to_string()),
                last_stopped: state.last_stopped_at.unwrap_or_else(|| "-".to_string()),
            };
            output::render_one(&info, fmt);
            Ok(())
        }
        InstanceCmd::Destroy { path, wipe_volumes } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            inst::instance_destroy(t, p, i, wipe_volumes)?;
            ui::success(&format!("Instance '{}' destroyed.", path));
            Ok(())
        }
        InstanceCmd::Logs { path } => {
            let (t, p, i) = naming::parse_instance_path(&path)?;
            let logs = inst::instance_logs(t, p, i)?;
            println!("{}", logs);
            Ok(())
        }
    }
}

fn cmd_agent(action: AgentCmd) -> Result<()> {
    use mvm_runtime::security::certs;

    match action {
        AgentCmd::Reconcile { desired, prune } => mvm_agent::agent::reconcile(&desired, prune),
        AgentCmd::Desired { file, node_id } => {
            let desired = mvm_agent::agent::generate_desired(&node_id)?;
            let json = serde_json::to_string_pretty(&desired)?;
            match file {
                Some(path) => {
                    std::fs::write(&path, &json)?;
                    ui::success(&format!("Desired state written to {}", path));
                }
                None => println!("{}", json),
            }
            Ok(())
        }
        AgentCmd::Serve {
            interval_secs,
            desired,
            listen,
        } => mvm_agent::agent::serve(interval_secs, desired.as_deref(), listen.as_deref()),
        AgentCmd::Certs { action } => match action {
            AgentCertsCmd::Init { ca } => {
                match ca {
                    Some(ca_path) => {
                        certs::init_ca(&ca_path)?;
                        ui::success("CA certificate initialized.");
                    }
                    None => {
                        // Generate self-signed dev CA + node cert
                        let node_id = format!(
                            "mvm-{}",
                            uuid::Uuid::new_v4()
                                .to_string()
                                .split('-')
                                .next()
                                .unwrap_or("dev")
                        );
                        let paths = certs::generate_self_signed(&node_id)?;
                        ui::success(&format!(
                            "Self-signed certificates generated for '{}'.",
                            node_id
                        ));
                        ui::info(&format!("  CA:   {}", paths.ca_cert));
                        ui::info(&format!("  Cert: {}", paths.node_cert));
                        ui::info(&format!("  Key:  {}", paths.node_key));
                    }
                }
                Ok(())
            }
            AgentCertsCmd::Rotate => {
                let node_id =
                    shell::run_in_vm_stdout("cat /var/lib/mvm/node_id 2>/dev/null || echo mvm-dev")
                        .unwrap_or_else(|_| "mvm-dev".to_string());
                let paths = certs::rotate_certs(node_id.trim())?;
                ui::success("Certificates rotated.");
                ui::info(&format!("  Cert: {}", paths.node_cert));
                Ok(())
            }
            AgentCertsCmd::Status { json } => certs::show_status(json),
        },
    }
}

fn cmd_net(action: NetCmd, out_fmt: OutputFormat) -> Result<()> {
    match action {
        NetCmd::Verify { json } => {
            let fmt = if json { OutputFormat::Json } else { out_fmt };
            let tenants = tenant::lifecycle::tenant_list()?;
            let mut reports = Vec::new();
            let mut all_issues = Vec::new();

            for tid in &tenants {
                if let Ok(config) = tenant::lifecycle::tenant_load(tid) {
                    let report = bridge::full_bridge_report(tid, &config.net)?;
                    for issue in &report.issues {
                        all_issues.push(format!("{}: {}", tid, issue));
                    }
                    reports.push(report);
                }
            }

            if fmt != OutputFormat::Table {
                // JSON/YAML: always output structured data
                match fmt {
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&reports)?);
                    }
                    OutputFormat::Yaml => {
                        println!("{}", serde_yaml::to_string(&reports)?);
                    }
                    _ => unreachable!(),
                }
            } else if all_issues.is_empty() {
                ui::success("All tenant networks verified.");
                for r in &reports {
                    ui::info(&format!(
                        "  {} ({}) — bridge: {}, TAPs: {}",
                        r.tenant_id,
                        r.subnet,
                        if r.bridge_up { "UP" } else { "DOWN" },
                        r.tap_devices.len(),
                    ));
                }
            } else {
                ui::warn("Network issues found:");
                for issue in &all_issues {
                    ui::error(&format!("  {}", issue));
                }
            }
            Ok(())
        }
    }
}

fn cmd_node(action: NodeCmd, out_fmt: OutputFormat) -> Result<()> {
    let _ = out_fmt; // node commands already handle json flag internally
    match action {
        NodeCmd::Info { json } => {
            let info =
                mvm_agent::node::collect_info().with_context(|| "Failed to collect node info")?;

            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("Node ID:       {}", info.node_id);
                println!("Hostname:      {}", info.hostname);
                println!("Architecture:  {}", info.arch);
                println!("vCPUs:         {}", info.total_vcpus);
                println!("Memory:        {} MiB", info.total_mem_mib);
                println!(
                    "Lima:          {}",
                    info.lima_status.as_deref().unwrap_or("unknown")
                );
                println!(
                    "Firecracker:   {}",
                    info.firecracker_version.as_deref().unwrap_or("not found")
                );
                println!(
                    "Jailer:        {}",
                    if info.jailer_available {
                        "available"
                    } else {
                        "not found"
                    }
                );
                println!(
                    "cgroup v2:     {}",
                    if info.cgroup_v2 { "yes" } else { "no" }
                );
            }

            Ok(())
        }
        NodeCmd::Stats { json } => {
            let stats =
                mvm_agent::node::collect_stats().with_context(|| "Failed to collect node stats")?;

            if json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!("Tenants:    {}", stats.tenant_count);
                println!("Pools:      {}", stats.pool_count);
                println!("Running:    {}", stats.running_instances);
                println!("Warm:       {}", stats.warm_instances);
                println!("Sleeping:   {}", stats.sleeping_instances);
                println!("Stopped:    {}", stats.stopped_instances);
            }

            Ok(())
        }
        NodeCmd::Disk { json } => {
            let report = mvm_runtime::vm::disk_manager::disk_usage_report()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Total disk usage: {} bytes", report.total_bytes);
                for t in &report.tenants {
                    println!("  Tenant '{}': {} bytes", t.tenant_id, t.total_bytes);
                    for p in &t.pools {
                        println!(
                            "    Pool '{}': artifacts={}, instances={}, total={}",
                            p.pool_id, p.artifacts_bytes, p.instances_bytes, p.total_bytes
                        );
                    }
                }
            }
            Ok(())
        }
        NodeCmd::Gc { keep } => {
            let tenant_ids = tenant::lifecycle::tenant_list()?;
            let mut total_removed = 0u32;
            for tid in &tenant_ids {
                if let Ok(pool_ids) = pool::lifecycle::pool_list(tid) {
                    for pid in &pool_ids {
                        match mvm_runtime::vm::disk_manager::cleanup_old_revisions(tid, pid, keep) {
                            Ok(n) => total_removed += n,
                            Err(e) => ui::warn(&format!("GC failed for {}/{}: {}", tid, pid, e)),
                        }
                    }
                }
            }
            if total_removed > 0 {
                ui::success(&format!(
                    "Removed {} old revisions across all pools.",
                    total_removed
                ));
            } else {
                ui::info("No old revisions to clean up.");
            }
            Ok(())
        }
    }
}

fn cmd_coordinator(action: CoordinatorCmd, _out_fmt: OutputFormat) -> Result<()> {
    use mvm_coordinator::client::{CoordinatorClient, run_coordinator_command};
    use mvm_core::agent::{AgentRequest, AgentResponse, DesiredState};

    match action {
        CoordinatorCmd::Push { desired, node } => {
            let json = std::fs::read_to_string(&desired)
                .with_context(|| format!("Failed to read desired state file: {}", desired))?;
            let state: DesiredState = serde_json::from_str(&json)
                .with_context(|| "Failed to parse desired state JSON")?;

            let addr: std::net::SocketAddr = node
                .parse()
                .with_context(|| format!("Invalid node address: {}", node))?;

            run_coordinator_command(async {
                let client = CoordinatorClient::new()?;
                let response = client.send(addr, &AgentRequest::Reconcile(state)).await?;
                match response {
                    AgentResponse::ReconcileResult(report) => {
                        ui::success(&format!(
                            "Reconcile pushed to {}. Instances: +{} started, {} errors",
                            node,
                            report.instances_started,
                            report.errors.len()
                        ));
                        if !report.errors.is_empty() {
                            for err in &report.errors {
                                ui::error(&format!("  {}", err));
                            }
                        }
                    }
                    AgentResponse::Error { code, message } => {
                        ui::error(&format!("Node error ({}): {}", code, message));
                    }
                    _ => {
                        ui::warn("Unexpected response type from node.");
                    }
                }
                Ok(())
            })
        }
        CoordinatorCmd::Status { node } => {
            let addr: std::net::SocketAddr = node
                .parse()
                .with_context(|| format!("Invalid node address: {}", node))?;

            run_coordinator_command(async {
                let client = CoordinatorClient::new()?;
                let response = client.send(addr, &AgentRequest::NodeInfo).await?;
                match response {
                    AgentResponse::NodeInfo(info) => {
                        println!("{}", serde_json::to_string_pretty(&info)?);
                    }
                    AgentResponse::Error { code, message } => {
                        ui::error(&format!("Node error ({}): {}", code, message));
                    }
                    _ => {
                        ui::warn("Unexpected response type from node.");
                    }
                }
                Ok(())
            })
        }
        CoordinatorCmd::ListInstances { node, tenant, pool } => {
            let addr: std::net::SocketAddr = node
                .parse()
                .with_context(|| format!("Invalid node address: {}", node))?;

            run_coordinator_command(async {
                let client = CoordinatorClient::new()?;
                let response = client
                    .send(
                        addr,
                        &AgentRequest::InstanceList {
                            tenant_id: tenant.clone(),
                            pool_id: pool,
                        },
                    )
                    .await?;
                match response {
                    AgentResponse::InstanceList(instances) => {
                        if instances.is_empty() {
                            ui::info(&format!("No instances found for tenant '{}'.", tenant));
                        } else {
                            println!("{}", serde_json::to_string_pretty(&instances)?);
                        }
                    }
                    AgentResponse::Error { code, message } => {
                        ui::error(&format!("Node error ({}): {}", code, message));
                    }
                    _ => {
                        ui::warn("Unexpected response type from node.");
                    }
                }
                Ok(())
            })
        }
        CoordinatorCmd::Wake {
            node,
            tenant,
            pool,
            instance,
        } => {
            let addr: std::net::SocketAddr = node
                .parse()
                .with_context(|| format!("Invalid node address: {}", node))?;

            run_coordinator_command(async {
                let client = CoordinatorClient::new()?;
                let response = client
                    .send(
                        addr,
                        &AgentRequest::WakeInstance {
                            tenant_id: tenant,
                            pool_id: pool,
                            instance_id: instance.clone(),
                        },
                    )
                    .await?;
                match response {
                    AgentResponse::WakeResult { success } => {
                        if success {
                            ui::success(&format!("Instance '{}' woken.", instance));
                        } else {
                            ui::error(&format!("Failed to wake instance '{}'.", instance));
                        }
                    }
                    AgentResponse::Error { code, message } => {
                        ui::error(&format!("Node error ({}): {}", code, message));
                    }
                    _ => {
                        ui::warn("Unexpected response type from node.");
                    }
                }
                Ok(())
            })
        }
        CoordinatorCmd::Serve { config } => {
            use mvm_coordinator::config::CoordinatorConfig;

            let config_path = std::path::Path::new(&config);
            let coord_config = CoordinatorConfig::from_file(config_path)?;

            ui::info(&format!(
                "Starting coordinator with {} routes from {}",
                coord_config.routes.len(),
                config
            ));

            run_coordinator_command(async { mvm_coordinator::server::serve(coord_config).await })
        }
        CoordinatorCmd::Routes { config } => {
            use mvm_coordinator::config::CoordinatorConfig;
            use mvm_coordinator::routing::RouteTable;

            let config_path = std::path::Path::new(&config);
            let coord_config = CoordinatorConfig::from_file(config_path)?;
            let table = RouteTable::from_config(&coord_config);

            let header = "IDLE TIMEOUT";
            println!(
                "{:<20} {:<20} {:<15} {:<25} {}",
                "TENANT", "POOL", "LISTEN", "NODE", header
            );
            for (listen, route) in table.routes() {
                println!(
                    "{:<20} {:<20} {:<15} {:<25} {}s",
                    route.tenant_id, route.pool_id, listen, route.node, route.idle_timeout_secs,
                );
            }
            Ok(())
        }
    }
}

fn cmd_dev_cluster(action: DevClusterCmd) -> Result<()> {
    match action {
        DevClusterCmd::Init => crate::dev_cluster::init(),
        DevClusterCmd::Up => crate::dev_cluster::up(),
        DevClusterCmd::Status => crate::dev_cluster::status(),
        DevClusterCmd::Down => crate::dev_cluster::down(),
    }
}

// ============================================================================
// Onboarding command handlers
// ============================================================================

fn cmd_add(action: AddCmd) -> Result<()> {
    match action {
        AddCmd::Host {
            ca,
            signing_key,
            production,
        } => cmd_add_host(ca.as_deref(), signing_key.as_deref(), production),
    }
}

fn cmd_add_host(
    ca_path: Option<&str>,
    signing_key_path: Option<&str>,
    production: bool,
) -> Result<()> {
    use mvm_runtime::security::certs;

    let total_steps = 2 + u32::from(signing_key_path.is_some());

    // Step 1: Bootstrap
    ui::step(1, total_steps, "Bootstrapping environment...");
    cmd_bootstrap(production).with_context(|| "Bootstrap failed")?;

    // Step 2: Initialize mTLS certificates
    ui::step(2, total_steps, "Initializing mTLS certificates...");
    if let Some(ca) = ca_path {
        certs::init_ca(ca)?;
        ui::info("  CA certificate imported.");
    }
    let node_id = format!("mvm-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let paths = certs::generate_self_signed(&node_id)?;
    ui::info(&format!("  Node certificate: {}", paths.node_cert));

    // Step 3 (optional): Copy signing key
    if let Some(key_path) = signing_key_path {
        ui::step(3, total_steps, "Installing coordinator signing key...");
        shell::run_in_vm("sudo mkdir -p /etc/mvm/trusted_keys")?;
        shell::run_in_vm(&format!(
            "sudo cp {} /etc/mvm/trusted_keys/coordinator.pub && \
             sudo chmod 644 /etc/mvm/trusted_keys/coordinator.pub",
            key_path
        ))?;
        ui::info("  Signing key installed.");
    }

    ui::success("\nHost prepared successfully!");
    ui::info("\nNext steps:");
    ui::info("  Start the agent daemon:");
    ui::info("    mvm agent serve --interval-secs 30");
    if signing_key_path.is_none() {
        ui::info("\n  Note: no signing key provided. For production, re-run with --signing-key.");
    }

    Ok(())
}

fn cmd_new(
    template_name: &str,
    name: &str,
    net_id_override: Option<u16>,
    subnet_override: Option<&str>,
    flake_override: Option<&str>,
    config_path: Option<&str>,
) -> Result<()> {
    use mvm_agent::templates;
    use mvm_core::tenant::TenantNet;

    naming::validate_id(name, "Deployment")?;

    let template = templates::get_template(template_name).ok_or_else(|| {
        let available = templates::list_templates().join(", ");
        anyhow::anyhow!(
            "Unknown template '{}'. Available: {}",
            template_name,
            available
        )
    })?;

    // Load optional config file
    let deploy_config = match config_path {
        Some(path) => Some(templates::DeployConfig::from_file(std::path::Path::new(
            path,
        ))?),
        None => None,
    };

    ui::info(&format!(
        "Creating '{}' from template '{}'...\n",
        name, template_name
    ));

    let pool_count = template.pools.len() as u32;
    // Steps: allocate + create tenant + (create pool * N) + (build * N) + scale
    let total_steps = 2 + pool_count + pool_count + 1;
    let mut step = 0u32;

    // Step 1: Allocate network
    step += 1;
    ui::step(step, total_steps, "Allocating network...");
    let net_id = match net_id_override {
        Some(id) => id,
        None => templates::allocate_net_id()?,
    };
    let subnet = match subnet_override {
        Some(s) => s.to_string(),
        None => templates::subnet_from_net_id(net_id),
    };
    let gateway = templates::gateway_from_subnet(&subnet)?;
    ui::info(&format!("  net-id: {}, subnet: {}", net_id, subnet));

    // Step 2: Create tenant
    step += 1;
    let step_msg = format!("Creating tenant '{}'...", name);
    ui::step(step, total_steps, &step_msg);
    let net = TenantNet::new(net_id, &subnet, &gateway);
    tenant::lifecycle::tenant_create(name, net, template.quotas.clone())?;

    // Determine flake: CLI override > config override > template default
    let flake_ref = flake_override
        .map(|s| s.to_string())
        .or_else(|| {
            deploy_config
                .as_ref()
                .and_then(|c| c.overrides.flake.clone())
        })
        .unwrap_or_else(|| template.default_flake.to_string());

    // Create pools (applying config overrides)
    for pool_tmpl in &template.pools {
        step += 1;
        let step_msg = format!("Creating pool '{}/{}'...", name, pool_tmpl.pool_id);
        ui::step(step, total_steps, &step_msg);

        // Apply pool-level overrides from config
        let (vcpus, mem_mib) = apply_pool_overrides(pool_tmpl, deploy_config.as_ref());

        let resources = mvm_core::pool::InstanceResources {
            vcpus,
            mem_mib,
            data_disk_mib: pool_tmpl.data_disk_mib,
        };
        pool::lifecycle::pool_create(
            name,
            pool_tmpl.pool_id,
            &flake_ref,
            pool_tmpl.profile,
            resources,
            pool_tmpl.role.clone(),
        )?;
    }

    // Build pools
    for pool_tmpl in &template.pools {
        step += 1;
        let step_msg = format!("Building '{}/{}'...", name, pool_tmpl.pool_id);
        ui::step(step, total_steps, &step_msg);
        let env = mvm_runtime::build_env::RuntimeBuildEnv;
        mvm_build::build::pool_build(&env, name, pool_tmpl.pool_id, None)?;
    }

    // Scale up
    step += 1;
    ui::step(step, total_steps, "Scaling to running instances...");
    for pool_tmpl in &template.pools {
        let (running, warm) = scale_for_role(pool_tmpl, deploy_config.as_ref());
        pool::lifecycle::pool_scale(name, pool_tmpl.pool_id, running, warm, None)?;
    }

    ui::success(&format!("\nDeployment '{}' created!", name));
    ui::info(&format!("\n  mvm connect {}", name));

    Ok(())
}

/// Apply pool overrides from a DeployConfig, matching by pool_id.
fn apply_pool_overrides(
    pool_tmpl: &mvm_agent::templates::PoolTemplate,
    config: Option<&mvm_agent::templates::DeployConfig>,
) -> (u8, u32) {
    let mut vcpus = pool_tmpl.vcpus;
    let mut mem_mib = pool_tmpl.mem_mib;

    if let Some(cfg) = config {
        let pool_override = match pool_tmpl.pool_id {
            "gateways" => cfg.overrides.gateways.as_ref(),
            "workers" => cfg.overrides.workers.as_ref(),
            _ => None,
        };
        if let Some(ov) = pool_override {
            if let Some(v) = ov.vcpus {
                vcpus = v;
            }
            if let Some(m) = ov.mem_mib {
                mem_mib = m;
            }
        }
    }

    (vcpus, mem_mib)
}

/// Determine scale counts for a pool based on role and config overrides.
fn scale_for_role(
    pool_tmpl: &mvm_agent::templates::PoolTemplate,
    config: Option<&mvm_agent::templates::DeployConfig>,
) -> (Option<u32>, Option<u32>) {
    let default = match pool_tmpl.role {
        mvm_core::pool::Role::Gateway => (1u32, 0u32),
        _ => (2, 1),
    };

    if let Some(cfg) = config {
        let pool_override = match pool_tmpl.pool_id {
            "gateways" => cfg.overrides.gateways.as_ref(),
            "workers" => cfg.overrides.workers.as_ref(),
            _ => None,
        };
        if let Some(ov) = pool_override
            && let Some(n) = ov.instances
        {
            return (Some(n), Some(default.1));
        }
    }

    (
        Some(default.0),
        if default.1 > 0 { Some(default.1) } else { None },
    )
}

fn cmd_deploy(manifest_path: &str, watch: bool, interval: u64) -> Result<()> {
    use mvm_agent::templates;
    use mvm_core::tenant::TenantNet;

    let manifest = templates::DeploymentManifest::from_file(std::path::Path::new(manifest_path))?;

    naming::validate_id(&manifest.tenant.id, "Tenant")?;

    ui::info(&format!("Deploying tenant '{}'...\n", manifest.tenant.id));

    // Check if tenant already exists
    let tenant_exists = tenant::lifecycle::tenant_load(&manifest.tenant.id).is_ok();

    if !tenant_exists {
        // Create tenant
        let net_id = match manifest.tenant.net_id {
            Some(id) => id,
            None => templates::allocate_net_id()?,
        };
        let subnet = match &manifest.tenant.subnet {
            Some(s) => s.clone(),
            None => templates::subnet_from_net_id(net_id),
        };
        let gateway = templates::gateway_from_subnet(&subnet)?;
        let net = TenantNet::new(net_id, &subnet, &gateway);
        tenant::lifecycle::tenant_create(
            &manifest.tenant.id,
            net,
            mvm_core::tenant::TenantQuota::default(),
        )?;
        ui::info(&format!("  Created tenant '{}'", manifest.tenant.id));
    } else {
        ui::info(&format!("  Tenant '{}' already exists", manifest.tenant.id));
    }

    let default_flake = ".".to_string();

    // Create/update pools
    for mp in &manifest.pools {
        naming::validate_id(&mp.id, "Pool")?;

        let pool_exists = pool::lifecycle::pool_load(&manifest.tenant.id, &mp.id).is_ok();

        if !pool_exists {
            let flake_ref = mp.flake.as_deref().unwrap_or(&default_flake);
            let resources = mvm_core::pool::InstanceResources {
                vcpus: mp.vcpus,
                mem_mib: mp.mem_mib,
                data_disk_mib: mp.data_disk_mib,
            };
            pool::lifecycle::pool_create(
                &manifest.tenant.id,
                &mp.id,
                flake_ref,
                &mp.profile,
                resources,
                mp.role.clone(),
            )?;
            ui::info(&format!(
                "  Created pool '{}/{}'",
                manifest.tenant.id, mp.id
            ));

            // Build the pool
            let env = mvm_runtime::build_env::RuntimeBuildEnv;
            mvm_build::build::pool_build(&env, &manifest.tenant.id, &mp.id, None)?;
            ui::info(&format!("  Built pool '{}/{}'", manifest.tenant.id, mp.id));
        }

        // Scale
        let running = mp.desired_running.or(Some(1));
        let warm = mp.desired_warm;
        pool::lifecycle::pool_scale(&manifest.tenant.id, &mp.id, running, warm, None)?;
    }

    ui::success(&format!("\nDeployment '{}' ready!", manifest.tenant.id));

    if watch {
        ui::info(&format!(
            "Watch mode: re-reconciling every {}s (Ctrl+C to stop)",
            interval
        ));
        loop {
            std::thread::sleep(std::time::Duration::from_secs(interval));
            ui::info("Re-checking desired state...");
            for mp in &manifest.pools {
                let running = mp.desired_running.or(Some(1));
                let warm = mp.desired_warm;
                pool::lifecycle::pool_scale(&manifest.tenant.id, &mp.id, running, warm, None)?;
            }
        }
    }

    Ok(())
}

fn cmd_connect(name: &str, json: bool) -> Result<()> {
    naming::validate_id(name, "Deployment")?;

    let config = tenant::lifecycle::tenant_load(name)
        .with_context(|| format!("Deployment '{}' not found", name))?;

    if json {
        let pool_ids = pool::lifecycle::pool_list(name)?;
        let mut pools_info = Vec::new();
        for pid in &pool_ids {
            if let Ok(spec) = pool::lifecycle::pool_load(name, pid) {
                pools_info.push(serde_json::json!({
                    "pool_id": spec.pool_id,
                    "role": spec.role.to_string(),
                    "profile": spec.profile,
                    "desired_running": spec.desired_counts.running,
                    "desired_warm": spec.desired_counts.warm,
                }));
            }
        }
        let out = serde_json::json!({
            "tenant_id": config.tenant_id,
            "gateway_ip": config.net.gateway_ip,
            "subnet": config.net.ipv4_subnet,
            "bridge": config.net.bridge_name,
            "pools": pools_info,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    // Header
    ui::info(&format!("Deployment: {}\n", config.tenant_id));

    // Network
    ui::info("Network:");
    ui::info(&format!("  Gateway:  {}", config.net.gateway_ip));
    ui::info(&format!("  Subnet:   {}", config.net.ipv4_subnet));
    ui::info(&format!("  Bridge:   {}", config.net.bridge_name));

    // Pools
    let pool_ids = pool::lifecycle::pool_list(name)?;
    if !pool_ids.is_empty() {
        ui::info("\nPools:");
        for pid in &pool_ids {
            if let Ok(spec) = pool::lifecycle::pool_load(name, pid) {
                ui::info(&format!(
                    "  {}/{} (role: {}, {}vcpu/{}MiB, running: {}, warm: {})",
                    name,
                    spec.pool_id,
                    spec.role,
                    spec.instance_resources.vcpus,
                    spec.instance_resources.mem_mib,
                    spec.desired_counts.running,
                    spec.desired_counts.warm,
                ));
            }
        }
    }

    // Instances
    let mut has_instances = false;
    for pid in &pool_ids {
        if let Ok(instances) = mvm_runtime::vm::instance::lifecycle::instance_list(name, pid)
            && !instances.is_empty()
        {
            if !has_instances {
                ui::info("\nInstances:");
                has_instances = true;
            }
            for inst in &instances {
                ui::info(&format!(
                    "  {}/{}/{} {:?} ip={}",
                    name, pid, inst.instance_id, inst.status, inst.net.guest_ip
                ));
            }
        }
    }

    if !has_instances {
        ui::info("\nNo instances yet. Pools need to be built and scaled.");
    }

    // Next steps
    ui::info("\nQuick reference:");
    ui::info(&format!(
        "  Set secrets:  mvm tenant secrets set {} --from-file secrets.json",
        name
    ));
    ui::info(&format!(
        "  List instances: mvm instance list --tenant {}",
        name
    ));
    ui::info(&format!(
        "  Scale workers:  mvm pool scale {}/workers --running 4 --warm 2",
        name
    ));

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

/// Parse a role string from the CLI into a Role enum value.
fn parse_role(s: &str) -> Result<mvm_core::pool::Role> {
    use mvm_core::pool::Role;
    match s {
        "gateway" => Ok(Role::Gateway),
        "worker" => Ok(Role::Worker),
        "builder" => Ok(Role::Builder),
        "capability-imessage" => Ok(Role::CapabilityImessage),
        _ => anyhow::bail!(
            "Unknown role '{}'. Valid roles: gateway, worker, builder, capability-imessage",
            s
        ),
    }
}

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
            }
        ));
    }

    #[test]
    fn test_sync_build_script_release() {
        let script = sync_build_script("/home/user/mvm", false, "aarch64");
        assert!(script.contains("--release"));
        assert!(script.contains("CARGO_TARGET_DIR='target/linux-aarch64'"));
        assert!(script.contains("--bin mvm --bin mvm-hostd"));
        assert!(script.contains("cd '/home/user/mvm'"));
    }

    #[test]
    fn test_sync_build_script_debug() {
        let script = sync_build_script("/home/user/mvm", true, "aarch64");
        assert!(!script.contains("--release"));
        assert!(script.contains("CARGO_TARGET_DIR='target/linux-aarch64'"));
        assert!(script.contains("--bin mvm --bin mvm-hostd"));
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
        assert!(script.contains("/target/linux-aarch64/release/mvm-hostd"));
        assert!(script.contains("/usr/local/bin/"));
        assert!(script.contains("install -m 0755"));
    }

    #[test]
    fn test_sync_install_script_debug() {
        let script = sync_install_script("/home/user/mvm", true, "aarch64");
        assert!(script.contains("/target/linux-aarch64/debug/mvm"));
        assert!(script.contains("/target/linux-aarch64/debug/mvm-hostd"));
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
    fn test_build_flake_parses() {
        let cli = Cli::try_parse_from([
            "mvm",
            "build",
            "--flake",
            ".",
            "--profile",
            "minimal",
            "--role",
            "worker",
        ])
        .unwrap();
        match cli.command {
            Commands::Build {
                flake,
                profile,
                role,
                ..
            } => {
                assert_eq!(flake.as_deref(), Some("."));
                assert_eq!(profile, "minimal");
                assert_eq!(role, "worker");
            }
            _ => panic!("Expected Build command"),
        }
    }

    #[test]
    fn test_build_flake_defaults() {
        let cli = Cli::try_parse_from(["mvm", "build", "--flake", "."]).unwrap();
        match cli.command {
            Commands::Build {
                flake,
                profile,
                role,
                ..
            } => {
                assert_eq!(flake.as_deref(), Some("."));
                assert_eq!(profile, "minimal");
                assert_eq!(role, "worker");
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
            "--role",
            "gateway",
            "--cpus",
            "4",
            "--memory",
            "2048",
            "--user",
            "ubuntu",
            "--detach",
        ])
        .unwrap();
        match cli.command {
            Commands::Run {
                flake,
                profile,
                role,
                cpus,
                memory,
                user,
                detach,
            } => {
                assert_eq!(flake, ".");
                assert_eq!(profile, "full");
                assert_eq!(role, "gateway");
                assert_eq!(cpus, 4);
                assert_eq!(memory, 2048);
                assert_eq!(user, "ubuntu");
                assert!(detach);
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
                profile,
                role,
                cpus,
                memory,
                user,
                detach,
            } => {
                assert_eq!(flake, ".");
                assert_eq!(profile, "minimal");
                assert_eq!(role, "worker");
                assert_eq!(cpus, 2);
                assert_eq!(memory, 1024);
                assert_eq!(user, "root");
                assert!(!detach);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_detach_flag() {
        let cli = Cli::try_parse_from(["mvm", "run", "--flake", ".", "--detach"]).unwrap();
        match cli.command {
            Commands::Run { detach, .. } => {
                assert!(detach);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_custom_user() {
        let cli = Cli::try_parse_from(["mvm", "run", "--flake", ".", "--user", "admin"]).unwrap();
        match cli.command {
            Commands::Run { user, .. } => {
                assert_eq!(user, "admin");
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_requires_flake() {
        let result = Cli::try_parse_from(["mvm", "run"]);
        assert!(result.is_err(), "run should require --flake");
    }
}
