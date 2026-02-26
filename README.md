# mvm

Rust CLI for building and running [Firecracker](https://firecracker-microvm.github.io/) microVMs with [Nix](https://nixos.org/) on macOS (via [Lima](https://lima-vm.io/)) and Linux.

```
macOS / Linux Host  -->  Lima VM (Ubuntu)  -->  Firecracker microVM
      mvm CLI              limactl                  /dev/kvm
```

mvm handles the full dev lifecycle: bootstrapping Lima, installing Firecracker, building reproducible VM images from Nix flakes, launching microVMs, and managing reusable templates.

> Looking for multi-tenant fleet orchestration (tenants, pools, agents, coordinators)? See [mvmd](https://github.com/auser/mvmd).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
```

Or build from source:

```bash
git clone https://github.com/auser/mvm.git
cd mvm
cargo build --release
cp target/release/mvm ~/.local/bin/
```

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a step-by-step walkthrough.

```bash
mvm dev        # Bootstrap everything and drop into Lima dev shell
mvm status     # Check what's running
mvm shell      # Open a shell in the Lima VM
mvm stop       # Stop the microVM
mvm destroy    # Tear down everything
```

## Three-Layer Architecture

mvm runs a nested virtualization stack. Understanding the layers is key to working with it:

```
Layer 1: macOS / Linux Host
  - mvm CLI runs here natively
  - All mvm commands are executed from here
  - Your project files live here

Layer 2: Lima VM (Ubuntu)
  - Provides /dev/kvm on macOS
  - Home directory (~) is mounted read/write
  - Nix and Firecracker are installed here
  - `mvm shell` drops you into this layer
  - `mvm build` runs nix build here
  - Skipped entirely on native Linux with KVM

Layer 3: Firecracker microVM
  - Minimal guest OS (Ubuntu by default)
  - Isolated filesystem -- NO host mounts by default
  - Headless -- no SSH, no interactive access
  - Communicates via vsock only
  - Network: 172.16.0.2 (NAT via Lima)
  - Runs as a background daemon process
```

**Important**: Firecracker microVMs (Layer 3) are headless workloads with no SSH access. They communicate via vsock only. To work with your project files in a Linux environment, use `mvm shell` or `mvm dev` (Layer 2), where your home directory is mounted. Use `--volume` flags to pass data directories to microVMs.

## Setup Flow

mvm has three setup commands with increasing levels of automation:

| Command | What it does |
|---------|-------------|
| `mvm bootstrap` | Installs Homebrew dependencies (macOS), Lima, then runs full setup |
| `mvm setup` | Creates the Lima VM, installs Firecracker, downloads kernel + rootfs |
| `mvm dev` | Auto-detects missing components, runs bootstrap/setup as needed, then drops into a Lima shell |

For most users, `mvm dev` is the only command needed -- it handles everything automatically. If `mvm dev` fails because Lima or Firecracker are missing, it will bootstrap them.

### Lima VM Resources

The Lima VM defaults to 8 vCPUs and 16 GiB memory. Override at setup time:

```bash
mvm setup --lima-cpus 4 --lima-mem 8
mvm dev --lima-cpus 4 --lima-mem 8
```

### Recreating the Environment

If things go wrong, recreate from scratch:

```bash
mvm destroy     # Deletes the Lima VM and all microVM data
mvm dev         # Rebuilds everything from scratch
```

Or just rebuild the rootfs without destroying the Lima VM:

```bash
mvm setup --recreate
```

## Building Images

### From a Nix Flake

Build a microVM image from a Nix flake:

```bash
mvm build --flake github:org/app --profile minimal --role worker
```

Or build and immediately run it:

```bash
mvm run --flake github:org/app --profile minimal --cpus 2 --memory 1024
```

`--profile` selects a NixOS configuration profile. `--role` selects the VM role (worker, gateway, builder, capability-imessage). These map to Nix attributes in the flake.

#### Local Flake

Point to a local directory containing a `flake.nix`:

```bash
mvm build --flake . --profile minimal --role worker
mvm run --flake . --cpus 2 --memory 1024
```

Local flakes support watch mode -- rebuilds automatically when `flake.lock` changes:

```bash
mvm build --flake . --profile minimal --watch
```

#### Run Options

```bash
mvm run --flake . --profile minimal --role worker \
    --cpus 4 --memory 2048 \
    --volume ./data:/data:1024 \
    --config runtime.toml
```

MicroVMs are always headless (no SSH). Volumes are specified as `host_path:guest_mount:size_mb`. A runtime config TOML can provide defaults for cpus, memory, and volumes.

### From an Mvmfile

Create an `Mvmfile.toml` in your project:

```toml
[image]
name = "my-app"
base = "ubuntu"

[runtime]
cpus = 2
memory_mb = 1024

[volumes]
data = { host = "./data", guest = "/data", size_mb = 512 }
```

Then build and start:

```bash
mvm build .
mvm start
```

### Starting with a Custom Image

```bash
mvm start path/to/image.elf
mvm start path/to/image.elf --cpus 4 --memory 2048 --volume ./data:/data:512
```

## Templates

Templates are reusable microVM images built from Nix flakes. You can either scaffold a new template from scratch or register an existing Nix flake. Templates are built inside the Lima VM and can be shared via an S3-compatible registry.

### From an Existing Flake

If you already have a Nix flake that produces a microVM image (kernel + rootfs), register and build it directly:

```bash
# Register the flake as a template (resolves local paths to absolute)
mvm template create openclaw --flake ../openclaw --profile minimal --role worker

# Build the image (runs nix build inside the Lima VM)
mvm template build openclaw

# Run a microVM from the built template
mvm run --flake ../openclaw --profile minimal --cpus 2 --memory 1024
```

All `template create` flags have defaults: `--flake .`, `--profile default`, `--role worker`, `--cpus 2`, `--mem 1024`. Local flake paths (like `.` or `../openclaw`) are resolved to absolute paths at creation time so builds work regardless of your working directory.

### Scaffold Workflow

Start from scratch with a scaffolded template:

```bash
# 1. Scaffold a new template in the current directory
mvm template init my-service --local

# 2. Edit the generated flake.nix to add your workload
#    (see "What Gets Scaffolded" below)
cd my-service
$EDITOR flake.nix

# 3. Register the template with mvm
mvm template create my-service

# 4. Build the image (runs nix build inside the Lima VM)
mvm template build my-service

# 5. Run a microVM from the built template
mvm run --flake .
```

### What Gets Scaffolded

`mvm template init my-service --local` creates:

```
my-service/
├── flake.nix       # Nix flake that builds kernel + rootfs via mkGuest
├── baseline.nix    # NixOS guest config (console, drives, networking)
├── .gitignore      # Ignores result symlinks and build artifacts
└── README.md       # Quick-reference for the template workflow
```

**`flake.nix`** pulls in the mvm source as a flake input, which provides:
- The **guest agent** binary (auto-included in every image for health checks and vsock communication)
- The **guest-agent.nix** NixOS module (systemd service for the agent)
- The **guest-integrations.nix** module (register workload health checks)

**`baseline.nix`** configures the guest OS for Firecracker: minimal kernel, serial console, virtio drivers, static networking via kernel cmdline, and mount points for config/secrets/data drives.

### Adding a Workload

To add your own service to the template, create a role module (e.g. `roles/worker.nix`):

```nix
{ pkgs, ... }:
{
  # Import the integration health module so the guest agent
  # monitors your service and reports status via `mvm vm status`.
  imports = [ ../../../nix/modules/guest-integrations.nix ];

  services.mvm-integrations = {
    enable = true;
    integrations.my-worker = {
      healthCmd = "${pkgs.systemd}/bin/systemctl is-active my-worker.service";
      healthIntervalSecs = 10;
      healthTimeoutSecs = 5;
    };
  };

  systemd.services.my-worker = {
    # ... your systemd service definition
  };
}
```

Then add it to `flake.nix` in the `mkGuest` call:

```nix
packages.${system} = {
  default = mkGuest "default" [ ./roles/worker.nix ];
};
```

### Create (Without Scaffold)

If you already have a Nix flake, register it directly:

```bash
# Single template (override defaults as needed)
mvm template create base-worker --flake github:org/app --role worker

# Multiple role variants at once (creates base-worker, base-gateway)
mvm template create-multi base --flake github:org/app --roles worker,gateway
```

### Build

```bash
mvm template build base-worker
mvm template build base-worker --force    # Rebuild even if cached
```

Builds run `nix build` inside the Lima VM (Layer 2) to produce kernel + rootfs artifacts. The **mvm guest agent** is automatically injected into the rootfs after every build, so you don't need to include it manually.

For repeatable multi-role builds, use a TOML config:

```bash
mvm template build base-worker --config templates.toml
```

### Share via Registry

Push and pull templates to/from S3-compatible storage (MinIO, AWS S3, etc.):

```bash
mvm template push base-worker
mvm template pull base-worker
mvm template verify base-worker     # Verify checksums
```

Requires `MVM_TEMPLATE_REGISTRY` environment variable to be set.

### Manage

```bash
mvm template list                   # List all templates
mvm template info base-worker       # Show details + revisions
mvm template delete base-worker     # Remove a template
mvm template init base-worker       # Initialize on-disk layout
```

## Development Workflow

### Lima Shell

Access the Lima VM (Layer 2) where Nix and Firecracker are installed:

```bash
mvm shell                          # Open a shell in the Lima VM
mvm shell --project ~/myproject    # Open shell and cd into project dir
```

Inside the Lima shell, your host home directory (`~`) is mounted read/write. This is where Nix builds run and where Firecracker binaries live. Use this for debugging build issues or inspecting VM state.

### Sync (Build mvm Inside Lima)

Build and install the mvm binary inside the Lima VM from your host source tree:

```bash
mvm sync                # Build release, install to /usr/local/bin/ in Lima
mvm sync --debug        # Debug build (faster compile, slower runtime)
mvm sync --skip-deps    # Skip apt/rustup dependency checks
mvm sync --force        # Rebuild even if versions match
```

This is useful for testing mvm changes inside the Lima environment. The synced binary is available when you `mvm shell` into Lima.

### SSH Configuration

Generate an SSH config entry for connecting to the Lima VM directly:

```bash
mvm ssh-config >> ~/.ssh/config
```

Then connect with `ssh mvm` from any terminal.

## Commands

### Environment Management

| Command | Description |
|---------|-------------|
| `mvm bootstrap` | Full setup from scratch: Homebrew deps (macOS), Lima, Firecracker, kernel, rootfs |
| `mvm setup` | Create Lima VM and install Firecracker assets (requires limactl) |
| `mvm setup --recreate` | Stop microVM, rebuild rootfs from upstream squashfs |
| `mvm dev` | Auto-bootstrap if needed, drop into Lima dev shell |
| `mvm status` | Show platform, Lima VM, Firecracker, and microVM status |
| `mvm destroy` | Tear down Lima VM and all resources (confirmation required) |
| `mvm doctor` | Run system diagnostics and dependency checks |
| `mvm upgrade` | Check for and install mvm updates |
| `mvm upgrade --check` | Only check for updates, don't install |

### MicroVM Lifecycle

| Command | Description |
|---------|-------------|
| `mvm start` | Start the default microVM (headless) |
| `mvm start <image>` | Start a custom image with optional --cpus, --memory, --volume |
| `mvm stop` | Stop the running microVM and clean up |
| `mvm ssh` | Open a shell in the Lima VM (alias for `mvm shell`) |
| `mvm ssh-config` | Print an SSH config entry for the Lima VM |
| `mvm shell` | Open a shell in the Lima VM |
| `mvm sync` | Build mvm from source inside Lima and install to `/usr/local/bin/` |

### Building

| Command | Description |
|---------|-------------|
| `mvm build <path>` | Build from Mvmfile.toml in the given directory |
| `mvm build --flake <ref>` | Build from a Nix flake (local or remote) |
| `mvm build --flake <ref> --watch` | Build and rebuild on flake.lock changes |
| `mvm run --flake <ref>` | Build from flake and boot a headless Firecracker VM |

### Templates

| Command | Description |
|---------|-------------|
| `mvm template create <name>` | Create a single template definition |
| `mvm template create-multi <base>` | Create templates for multiple roles |
| `mvm template build <name>` | Build a template (runs nix build in Lima) |
| `mvm template build <name> --config <toml>` | Build from a TOML config file |
| `mvm template push <name>` | Push to S3-compatible registry |
| `mvm template pull <name>` | Pull from registry |
| `mvm template verify <name>` | Verify template checksums |
| `mvm template list` | List all templates |
| `mvm template info <name>` | Show template details and revisions |
| `mvm template delete <name>` | Delete a template |
| `mvm template init <name>` | Initialize on-disk template layout (`--local` for scaffold in cwd) |

### MicroVM Diagnostics

| Command | Description |
|---------|-------------|
| `mvm vm ping [name]` | Health-check running microVMs via vsock (all if no name given) |
| `mvm vm status [name]` | Query worker status from running microVMs (`--json` for JSON output) |

### Security

| Command | Description |
|---------|-------------|
| `mvm security status` | Show security posture score for the current environment (`--json` for JSON output) |

### Utilities

| Command | Description |
|---------|-------------|
| `mvm completions <shell>` | Generate shell completions (bash, zsh, fish, etc.) |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MVM_DATA_DIR` | Root data directory for templates and builds | `~/.mvm` |
| `MVM_FC_VERSION` | Firecracker version (auto-normalized to `vMAJOR.MINOR`) | Latest stable |
| `MVM_FC_ASSET_BASE` | S3 base URL for Firecracker assets | AWS default |
| `MVM_FC_ASSET_ROOTFS` | Override rootfs filename | Auto-detected |
| `MVM_FC_ASSET_KERNEL` | Override kernel filename | Auto-detected |
| `MVM_BUILDER_MODE` | Builder transport: `auto`, `vsock`, or `ssh` | `auto` |
| `MVM_TEMPLATE_REGISTRY` | S3 endpoint for template push/pull | None |
| `MVM_SSH_PORT` | Lima SSH local port | `60022` |
| `MVM_PRODUCTION` | Enable production mode checks | `false` |

Override the Firecracker version globally or per-command:

```bash
export MVM_FC_VERSION=v1.14.0
mvm setup

# Or per-command
mvm --fc-version v1.14.0 setup
```

## Architecture

mvm is a Cargo workspace with 6 crates:

| Crate | Purpose |
|-------|---------|
| **mvm-core** | Pure types, IDs, config, protocol, signing, routing (no runtime deps) |
| **mvm-guest** | Vsock protocol, integration health checks, guest agent binary |
| **mvm-build** | Nix builder pipeline (dev_build for local, pool_build for fleet) |
| **mvm-runtime** | Shell execution, Lima/Firecracker VM lifecycle, UI, template management |
| **mvm-security** | Security posture evaluation, jailer operations, seccomp profiles |
| **mvm-cli** | Clap CLI, bootstrap, upgrade, doctor, security, template commands |

The root crate is a facade (`src/lib.rs`) that re-exports all sub-crates as `mvm::core`, `mvm::runtime`, `mvm::build`, `mvm::guest`. The binary entry point (`src/main.rs`) delegates to `mvm_cli::run()`.

### How It Works

On macOS, all Linux operations run inside the Lima VM via `limactl shell mvm bash -c "..."`. On Linux with KVM, Lima is skipped and operations run natively. Firecracker microVMs run using `/dev/kvm` for hardware virtualization.

```
Host (macOS/Linux)
  └── Lima VM (Ubuntu, /dev/kvm) -- skipped on native Linux
        └── Firecracker microVM (your workload)
```

**Filesystem access**:
- Lima VM mounts your home directory (`~`) read/write -- your project files are accessible
- Firecracker microVM has an isolated filesystem -- no host mounts by default
- Use `--volume` flags to pass directories to the microVM

**Build pipeline**: `mvm build` and `mvm template build` run `nix build` inside the Lima VM, producing kernel (`vmlinux`) and rootfs (`rootfs.ext4`) artifacts.

### Trait Architecture

The `BuildEnvironment` trait is split into two traits in `mvm-core`:

- **`ShellEnvironment`** (base): `shell_exec()`, `shell_exec_stdout()`, `shell_exec_visible()`, `log_info()`, `log_success()`, `log_warn()`
- **`BuildEnvironment`** (extends `ShellEnvironment`): `load_pool_spec()`, `load_tenant_config()`, `ensure_bridge()`, `setup_tap()`, `teardown_tap()`, `record_revision()`

mvm uses only `ShellEnvironment` (via `dev_build()`). The full `BuildEnvironment` is used by [mvmd](https://github.com/auser/mvmd) for fleet orchestration builds.

## Network Layout (Dev Mode)

```
Firecracker microVM (172.16.0.2/30, eth0)
    | TAP interface (tap0)
Lima VM (172.16.0.1/30, tap0)  --  iptables NAT  --  internet
    | Lima virtualization
Host (macOS / Linux)
```

The microVM has internet access via NAT through the Lima VM. The TAP device connects the microVM to Lima's network namespace.

## Platform Support

| Platform | Architecture | Method |
|----------|-------------|--------|
| macOS | Apple Silicon (aarch64) | Via Lima VM |
| macOS | Intel (x86_64) | Via Lima VM |
| Linux | x86_64, aarch64 | Native (`/dev/kvm`) -- Lima skipped |

## Build from Source

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo test --workspace                   # Run all tests
cargo clippy --workspace -- -D warnings  # Lint (0 warnings required)
```

## Documentation

- [Quick Start](QUICKSTART.md) -- step-by-step guide
- [Development](docs/development.md) -- contributor guide
- [User Guide](docs/user-guide.md) -- writing Nix flakes for microVM images
- [Smoke Tests](docs/SMOKE_TEST.md) -- testing the dev workflow
- [Troubleshooting](docs/troubleshooting.md) -- common issues and fixes

## Related Projects

- [mvmd](https://github.com/auser/mvmd) -- Multi-tenant Firecracker fleet orchestration daemon (tenants, pools, instances, agents, coordinators, security hardening)

## License

Apache 2.0 -- see [LICENSE](LICENSE) for details.
