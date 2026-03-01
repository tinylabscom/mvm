# mvm

Rust CLI for building and running [Firecracker](https://firecracker-microvm.github.io/) microVMs with [Nix](https://nixos.org/) on macOS (via [Lima](https://lima-vm.io/)) and Linux.

```
macOS / Linux Host  -->  Lima VM (Ubuntu)  -->  Firecracker microVM
      mvmctl CLI              limactl                  /dev/kvm
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
cp target/release/mvmctl ~/.local/bin/
```

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a step-by-step walkthrough.

```bash
mvmctl dev        # Bootstrap everything and drop into Lima dev shell
mvmctl status     # Check what's running
mvmctl shell      # Open a shell in the Lima VM
mvmctl stop       # Stop the microVM
mvmctl destroy    # Tear down everything
```

## Three-Layer Architecture

mvm runs a nested virtualization stack. Understanding the layers is key to working with it:

```
Layer 1: macOS / Linux Host
  - mvmctl CLI runs here natively
  - All mvmctl commands are executed from here
  - Your project files live here

Layer 2: Lima VM (Ubuntu)
  - Provides /dev/kvm on macOS
  - Home directory (~) is mounted read/write
  - Nix and Firecracker are installed here
  - `mvmctl shell` drops you into this layer
  - `mvmctl build` runs nix build here
  - Skipped entirely on native Linux with KVM

Layer 3: Firecracker microVM
  - Minimal guest OS (busybox init, built from Nix flakes)
  - Sub-5s boot time -- no systemd, no NixOS overhead
  - Isolated filesystem -- NO host mounts by default
  - Headless -- no SSH, no interactive access
  - Communicates via vsock only
  - Network: 172.16.0.2 (NAT via Lima)
  - Runs as a background daemon process
  - Drives: /dev/vda (rootfs), /dev/vdb (config, ro), /dev/vdc (secrets, ro), /dev/vdd (data, rw)
  - Dev builds support `mvmctl vm exec` for debugging (see below)
```

**Important**: Firecracker microVMs (Layer 3) are headless workloads with no SSH access. They communicate via vsock only. To work with your project files in a Linux environment, use `mvmctl shell` or `mvmctl dev` (Layer 2), where your home directory is mounted. Use `--volume` flags to pass data directories to microVMs. For debugging, dev-mode guest agents support `mvmctl vm exec <name> -- <command>` to run commands inside the microVM via vsock.

## Setup Flow

mvm has three setup commands with increasing levels of automation:

| Command | What it does |
|---------|-------------|
| `mvmctl bootstrap` | Installs Homebrew dependencies (macOS), Lima, then runs full setup |
| `mvmctl setup` | Creates the Lima VM, installs Firecracker, downloads kernel + rootfs |
| `mvmctl dev` | Auto-detects missing components, runs bootstrap/setup as needed, then drops into a Lima shell |

For most users, `mvmctl dev` is the only command needed -- it handles everything automatically. If `mvmctl dev` fails because Lima or Firecracker are missing, it will bootstrap them.

### Lima VM Resources

The Lima VM defaults to 8 vCPUs and 16 GiB memory. Override at setup time:

```bash
mvmctl setup --lima-cpus 4 --lima-mem 8
mvmctl dev --lima-cpus 4 --lima-mem 8
```

### Recreating the Environment

If things go wrong, recreate from scratch:

```bash
mvmctl destroy     # Deletes the Lima VM and all microVM data
mvmctl dev         # Rebuilds everything from scratch
```

Or just rebuild the rootfs without destroying the Lima VM:

```bash
mvmctl setup --recreate
```

## Building Images

### From a Nix Flake

Build a microVM image from a Nix flake:

```bash
mvmctl build --flake github:org/app --profile minimal --role worker
```

Or build and immediately run it:

```bash
mvmctl run --flake github:org/app --profile minimal --cpus 2 --memory 1024
```

`--profile` selects a NixOS configuration profile. `--role` selects the VM role (worker, gateway, builder, capability-imessage). These map to Nix attributes in the flake.

#### Local Flake

Point to a local directory containing a `flake.nix`:

```bash
mvmctl build --flake . --profile minimal --role worker
mvmctl run --flake . --cpus 2 --memory 1024
```

Local flakes support watch mode -- rebuilds automatically when `flake.lock` changes:

```bash
mvmctl build --flake . --profile minimal --watch
```

#### Run Options

```bash
mvmctl run --flake . --profile minimal --role worker \
    --cpus 4 --memory 2048 \
    --volume ./data:/data:1024 \
    --config runtime.toml \
    --config-dir ./my-config \
    --secrets-dir ./my-secrets
```

MicroVMs are always headless (no SSH). Volumes are specified as `host_path:guest_mount:size_mb`. A runtime config TOML can provide defaults for cpus, memory, and volumes.

#### Config and Secrets Injection

Inject custom files onto the guest's config and secrets drives at boot time using `--config-dir` and `--secrets-dir`. Every file in the directory is written to the corresponding drive image before the VM starts.

```bash
# Prepare directories with your application config and secrets
mkdir -p /tmp/my-config /tmp/my-secrets

echo '{"gateway": {"port": 8080}}' > /tmp/my-config/app.json
echo 'API_KEY=sk-...' > /tmp/my-secrets/app.env

# Run with injected files
mvmctl run --template my-app \
    --config-dir /tmp/my-config \
    --secrets-dir /tmp/my-secrets
```

Inside the guest:
- Config files appear at `/mnt/config/` (read-only, mode 0444)
- Secret files appear at `/mnt/secrets/` (read-only, mode 0400)

The same API is available programmatically via `FlakeRunConfig.config_files` and `FlakeRunConfig.secret_files` for library consumers like [mvmd](https://github.com/auser/mvmd).

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
mvmctl build .
mvmctl start
```

### Starting with a Custom Image

```bash
mvmctl start path/to/image.elf
mvmctl start path/to/image.elf --cpus 4 --memory 2048 --volume ./data:/data:512
```

## Templates

Templates are reusable microVM images built from Nix flakes. You can either scaffold a new template from scratch or register an existing Nix flake. Templates are built inside the Lima VM and can be shared via an S3-compatible registry.

### From an Existing Flake

If you already have a Nix flake that produces a microVM image (kernel + rootfs), register and build it directly:

```bash
# Register the flake as a template (resolves local paths to absolute)
mvmctl template create openclaw --flake ../openclaw --profile minimal --role worker

# Build the image (runs nix build inside the Lima VM)
mvmctl template build openclaw

# Run a microVM from the built template
mvmctl run --flake ../openclaw --profile minimal --cpus 2 --memory 1024
```

All `template create` flags have defaults: `--flake .`, `--profile default`, `--role worker`, `--cpus 2`, `--mem 1024`. Local flake paths (like `.` or `../openclaw`) are resolved to absolute paths at creation time so builds work regardless of your working directory.

### Scaffold Workflow

Start from scratch with a scaffolded template:

```bash
# 1. Scaffold a new template in the current directory
mvmctl template init my-service --local

# 2. Edit the generated flake.nix to add your workload
#    (see "What Gets Scaffolded" below)
cd my-service
$EDITOR flake.nix

# 3. Register the template with mvm
mvmctl template create my-service

# 4. Build the image (runs nix build inside the Lima VM)
mvmctl template build my-service

# 5. Run a microVM from the built template
mvmctl run --flake .
```

### What Gets Scaffolded

`mvmctl template init my-service --local` creates:

```
my-service/
├── flake.nix       # Nix flake that builds kernel + rootfs via mkGuest
├── .gitignore      # Ignores result symlinks and build artifacts
└── README.md       # Quick-reference for the template workflow
```

**`flake.nix`** pulls in the mvm flake as an input. `mkGuest` handles everything internally -- the Firecracker kernel, busybox init, guest agent, networking, drive mounting, and service supervision are all built into the image automatically. You just define your services and health checks.

### Writing a Flake

A complete microVM flake:

```nix
{
  inputs = {
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "my-app";
        packages = [ pkgs.curl ];

        # Services are supervised with automatic restart on failure.
        services.my-app = {
          # preStart runs once as root before the service starts.
          preStart = "mkdir -p /tmp/data";

          # The long-running service command.
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";

          # Optional environment variables.
          # env = { MY_VAR = "value"; };
        };

        # Health checks are reported to the host via the guest agent.
        healthChecks.my-app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/ >/dev/null";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
```

The `mkGuest` API:

| Parameter | Description |
|-----------|-------------|
| `name` | VM name (used in image filename) |
| `packages` | Nix packages to include in the rootfs |
| `hostname` | Guest hostname (default: same as `name`) |
| `users.<name>.uid` | User ID (optional, auto-assigned from 1000) |
| `users.<name>.group` | Group name (optional, defaults to user name) |
| `users.<name>.home` | Home directory (optional, defaults to `/home/<name>`) |
| `services.<name>.command` | Long-running service command (supervised with respawn) |
| `services.<name>.preStart` | Optional setup script (runs as root before the service) |
| `services.<name>.env` | Optional environment variables (`{ KEY = "value"; }`) |
| `services.<name>.user` | Optional user to run as (must exist in `users`) |
| `services.<name>.logFile` | Optional log file path (default: `/dev/console`) |
| `healthChecks.<name>.healthCmd` | Health check command (exit 0 = healthy) |
| `healthChecks.<name>.healthIntervalSecs` | How often to run the check (default: 30) |
| `healthChecks.<name>.healthTimeoutSecs` | Timeout for each check (default: 10) |

### Create (Without Scaffold)

If you already have a Nix flake, register it directly:

```bash
# Single template (override defaults as needed)
mvmctl template create base-worker --flake github:org/app --role worker

# Multiple role variants at once (creates base-worker, base-gateway)
mvmctl template create-multi base --flake github:org/app --roles worker,gateway
```

### Build

```bash
mvmctl template build base-worker
mvmctl template build base-worker --force    # Rebuild even if cached
```

Builds run `nix build` inside the Lima VM (Layer 2) to produce kernel + rootfs artifacts. The guest agent, init system, networking, and drive mounting are all built into the image by `mkGuest` -- you don't need to configure any of this manually.

For repeatable multi-role builds, use a TOML config:

```bash
mvmctl template build base-worker --config templates.toml
```

### Share via Registry

Push and pull templates to/from S3-compatible storage (MinIO, AWS S3, etc.):

```bash
mvmctl template push base-worker
mvmctl template pull base-worker
mvmctl template verify base-worker     # Verify checksums
```

Requires `MVM_TEMPLATE_REGISTRY` environment variable to be set.

### Manage

```bash
mvmctl template list                   # List all templates
mvmctl template info base-worker       # Show details + revisions
mvmctl template delete base-worker     # Remove a template
mvmctl template init base-worker       # Initialize on-disk layout
```

## Development Workflow

### Lima Shell

Access the Lima VM (Layer 2) where Nix and Firecracker are installed:

```bash
mvmctl shell                          # Open a shell in the Lima VM
mvmctl shell --project ~/myproject    # Open shell and cd into project dir
```

Inside the Lima shell, your host home directory (`~`) is mounted read/write. This is where Nix builds run and where Firecracker binaries live. Use this for debugging build issues or inspecting VM state.

### Sync (Build mvmctl Inside Lima)

Build and install the mvmctl binary inside the Lima VM from your host source tree:

```bash
mvmctl sync                # Build release, install to /usr/local/bin/ in Lima
mvmctl sync --debug        # Debug build (faster compile, slower runtime)
mvmctl sync --skip-deps    # Skip apt/rustup dependency checks
mvmctl sync --force        # Rebuild even if versions match
```

This is useful for testing mvmctl changes inside the Lima environment. The synced binary is available when you `mvmctl shell` into Lima.

### SSH Configuration

Generate an SSH config entry for connecting to the Lima VM directly:

```bash
mvmctl ssh-config >> ~/.ssh/config
```

Then connect with `ssh mvm` from any terminal.

## Commands

### Environment Management

| Command | Description |
|---------|-------------|
| `mvmctl bootstrap` | Full setup from scratch: Homebrew deps (macOS), Lima, Firecracker, kernel, rootfs |
| `mvmctl setup` | Create Lima VM and install Firecracker assets (requires limactl) |
| `mvmctl setup --recreate` | Stop microVM, rebuild rootfs from upstream squashfs |
| `mvmctl dev` | Auto-bootstrap if needed, drop into Lima dev shell |
| `mvmctl status` | Show platform, Lima VM, Firecracker, and microVM status |
| `mvmctl destroy` | Tear down Lima VM and all resources (confirmation required) |
| `mvmctl doctor` | Run system diagnostics and dependency checks |
| `mvmctl upgrade` | Check for and install mvmctl updates |
| `mvmctl upgrade --check` | Only check for updates, don't install |

### MicroVM Lifecycle

| Command | Description |
|---------|-------------|
| `mvmctl start` | Start the default microVM (headless) |
| `mvmctl start <image>` | Start a custom image with optional --cpus, --memory, --volume |
| `mvmctl stop` | Stop the running microVM and clean up |
| `mvmctl ssh` | Open a shell in the Lima VM (alias for `mvmctl shell`) |
| `mvmctl ssh-config` | Print an SSH config entry for the Lima VM |
| `mvmctl shell` | Open a shell in the Lima VM |
| `mvmctl sync` | Build mvmctl from source inside Lima and install to `/usr/local/bin/` |

### Building

| Command | Description |
|---------|-------------|
| `mvmctl build <path>` | Build from Mvmfile.toml in the given directory |
| `mvmctl build --flake <ref>` | Build from a Nix flake (local or remote) |
| `mvmctl build --flake <ref> --watch` | Build and rebuild on flake.lock changes |
| `mvmctl run --flake <ref>` | Build from flake and boot a headless Firecracker VM |
| `mvmctl run --template <name> --config-dir <path>` | Run with custom config files injected onto the config drive |
| `mvmctl run --template <name> --secrets-dir <path>` | Run with secret files injected onto the secrets drive |

### Templates

| Command | Description |
|---------|-------------|
| `mvmctl template create <name>` | Create a single template definition |
| `mvmctl template create-multi <base>` | Create templates for multiple roles |
| `mvmctl template build <name>` | Build a template (runs nix build in Lima) |
| `mvmctl template build <name> --config <toml>` | Build from a TOML config file |
| `mvmctl template push <name>` | Push to S3-compatible registry |
| `mvmctl template pull <name>` | Pull from registry |
| `mvmctl template verify <name>` | Verify template checksums |
| `mvmctl template list` | List all templates |
| `mvmctl template info <name>` | Show template details and revisions |
| `mvmctl template delete <name>` | Delete a template |
| `mvmctl template init <name>` | Initialize on-disk template layout (`--local` for scaffold in cwd) |

### MicroVM Diagnostics

| Command | Description |
|---------|-------------|
| `mvmctl vm ping [name]` | Health-check running microVMs via vsock (all if no name given) |
| `mvmctl vm status [name]` | Query worker status from running microVMs (`--json` for JSON output) |
| `mvmctl vm inspect <name>` | Deep-dive inspection of a single VM (probes, integrations, worker status) |
| `mvmctl vm exec <name> -- <cmd>` | Run a command inside a running microVM (dev-only, requires `dev-shell` guest agent) |

### Security

| Command | Description |
|---------|-------------|
| `mvmctl security status` | Show security posture score for the current environment (`--json` for JSON output) |

### Utilities

| Command | Description |
|---------|-------------|
| `mvmctl completions <shell>` | Generate shell completions (bash, zsh, fish, etc.) |

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
mvmctl setup

# Or per-command
mvmctl --fc-version v1.14.0 setup
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

The root crate is a facade (`src/lib.rs`) that re-exports all sub-crates as `mvmctl::core`, `mvmctl::runtime`, `mvmctl::build`, `mvmctl::guest`. The binary entry point (`src/main.rs`) delegates to `mvm_cli::run()`.

### How It Works

All Linux operations are routed through a **`LinuxEnv`** abstraction defined in `mvm-core`. On macOS, the default implementation (`LimaEnv`) delegates commands via `limactl shell mvm bash -c "..."`. On Linux with KVM, `NativeEnv` runs commands directly via `bash -c`. The rest of the codebase is unaware of which backend is in use.

```
Host (macOS/Linux)
  └── Linux environment (Lima VM on macOS, native on Linux)
        └── Firecracker microVM (your workload)
```

**Filesystem access**:
- Lima VM mounts your home directory (`~`) read/write -- your project files are accessible
- Firecracker microVM has an isolated filesystem -- no host mounts by default
- Use `--volume` flags to pass data directories to the microVM
- Use `--config-dir` / `--secrets-dir` to inject files onto the config and secrets drives at boot

**Build pipeline**: `mvmctl build` and `mvmctl template build` run `nix build` inside the Linux environment, producing kernel (`vmlinux`) and rootfs (`rootfs.ext4`) artifacts. No initrd is needed -- the kernel boots directly into a busybox init script on the rootfs.

### Trait Architecture

Key abstractions in `mvm-core`:

- **`LinuxEnv`**: Where Linux commands execute -- `run()`, `run_visible()`, `run_stdout()`, `run_capture()`. Implementations: `LimaEnv` (macOS), `NativeEnv` (Linux with KVM).
- **`ShellEnvironment`**: Build-time shell execution -- `shell_exec()`, `shell_exec_stdout()`, `shell_exec_visible()`, `log_info()`, `log_success()`, `log_warn()`
- **`BuildEnvironment`** (extends `ShellEnvironment`): Fleet build orchestration -- `load_pool_spec()`, `load_tenant_config()`, `ensure_bridge()`, `setup_tap()`, `teardown_tap()`, `record_revision()`
- **`VmBackend`**: VM lifecycle abstraction -- `start()`, `stop()`, `status()`, `capabilities()`. Current implementation: `FirecrackerBackend`.

mvm uses `LinuxEnv` for all command execution and `ShellEnvironment` for dev builds (via `dev_build()`). The full `BuildEnvironment` and `VmBackend` dispatch are used by [mvmd](https://github.com/auser/mvmd) for fleet orchestration.

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
