# mvm Quick Start

Get a Firecracker microVM running in under 5 minutes.

## Prerequisites

- macOS (Apple Silicon or Intel) or Linux with KVM
- [Homebrew](https://brew.sh/) (macOS only -- mvm will install it if missing)

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

## 1. Launch the Dev Environment

```bash
mvmctl dev
```

This single command handles everything:
1. Installs Lima (macOS) if not present
2. Creates and starts a Lima VM with nested virtualization
3. Installs Firecracker inside the Lima VM
4. Drops you into the Lima VM shell

Inside the Lima shell, your home directory (`~`) is mounted read/write -- your project files are right there. Nix, Firecracker, and `/dev/kvm` are all available.

Exit the shell with `exit` or `Ctrl+D` -- the Lima VM keeps running in the background.

**Note**: On the first run, `mvmctl dev` downloads ~500MB of assets (Lima VM image). Subsequent runs start in seconds.

## 2. Day-to-Day Commands

```bash
mvmctl status     # Check what's running (Lima VM, Firecracker, microVM)
mvmctl shell      # Open a shell in the Lima VM
mvmctl stop       # Stop the microVM (Lima VM stays running)
mvmctl destroy    # Tear down everything (Lima VM + all data)
```

## 3. Understanding the Layers

mvm runs a three-layer stack:

```
Your macOS/Linux Host
  └── Lima VM (Ubuntu, has /dev/kvm)
        └── Firecracker microVM (your workload)
```

| Layer | Access command | Has your project files? |
|-------|---------------|------------------------|
| Host | Your normal terminal | Yes |
| Lima VM | `mvmctl dev` or `mvmctl shell` | Yes (~ mounted read/write) |
| Firecracker microVM | (headless, no SSH) | No (isolated filesystem) |

Firecracker microVMs are headless workloads with no SSH access -- they communicate via vsock only. The dev environment is the Lima VM. Use `mvmctl dev` or `mvmctl shell` to access it. Your home directory is mounted read/write, so your project files are right there.

## 4. Build from a Nix Flake

Build a microVM image and run it in one command:

```bash
mvmctl run --flake github:org/app --profile minimal --cpus 2 --memory 1024
```

Or build separately:

```bash
mvmctl build --flake . --profile minimal --role worker
mvmctl start
```

The `--profile` selects a NixOS configuration profile and `--role` selects the VM role (worker, gateway, builder). These map to Nix flake attributes.

## 5. Build from Mvmfile.toml

Create an `Mvmfile.toml`:

```toml
[image]
name = "my-app"
base = "ubuntu"

[runtime]
cpus = 2
memory_mb = 1024
```

Then:

```bash
mvmctl build .
mvmctl start
```

## 6. Templates (Reusable Base Images)

Build a base image once and share it across machines:

```bash
# Create a template
mvmctl template create base-worker \
    --flake github:org/app \
    --profile minimal \
    --role worker \
    --cpus 2 --mem 1024

# Build it (runs nix build inside Lima)
mvmctl template build base-worker

# Share via S3-compatible registry
mvmctl template push base-worker
mvmctl template pull base-worker    # On another machine
mvmctl template verify base-worker  # Verify checksums
```

List and inspect templates:

```bash
mvmctl template list
mvmctl template info base-worker
```

## 7. Lima Shell (Development Access)

Access the Lima VM directly -- useful for debugging, running Nix commands, or inspecting Firecracker state:

```bash
mvmctl shell                          # Open a bash shell in the Lima VM
mvmctl shell --project ~/myproject    # Open shell and cd into project
```

Inside the Lima shell, you have:
- Full access to your home directory (same files as your host)
- Nix package manager
- Firecracker binary
- `/dev/kvm` for virtualization

## 8. Sync (Install mvm Inside Lima)

Build and install the mvm binary inside the Lima VM from your local source:

```bash
mvmctl sync                # Release build, install to /usr/local/bin/
mvmctl sync --debug        # Debug build (faster compile)
mvmctl sync --skip-deps    # Skip apt/rustup checks
```

The installed binary is available when you `mvmctl shell` into Lima, useful for running mvm commands that need a Linux environment.

## 9. Run with Volumes

Pass host directories into the Firecracker microVM:

```bash
mvmctl run --flake . --profile minimal \
    --volume ./data:/data:1024 \
    --cpus 2 --memory 1024
```

Volume format: `host_path:guest_mount:size_mb`

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MVM_FC_VERSION` | Override Firecracker version (auto-normalized) |
| `MVM_BUILDER_MODE` | Builder transport: `auto` (default), `vsock`, or `ssh` |
| `MVM_TEMPLATE_REGISTRY` | S3 endpoint for template push/pull |
| `MVM_SSH_PORT` | Lima SSH local port (default: 60022) |

## Diagnostics

```bash
mvmctl doctor    # Check system dependencies and configuration
```

## Troubleshooting

**`Lima VM 'mvm' does not exist`**: Run `mvmctl setup` or `mvmctl dev` (which auto-bootstraps).

**`limactl not found`**: Run `mvmctl bootstrap` to install Lima via Homebrew, or install manually with `brew install lima`.

**Firecracker not installed**: Run `mvmctl setup` to install Firecracker inside the Lima VM.

**Can't access project files inside microVM**: The Firecracker microVM has an isolated filesystem. Use `mvmctl shell` to access the Lima VM where your home directory is mounted, or pass volumes with `--volume`.

**Lima VM is slow**: Adjust resources: `mvmctl destroy && mvmctl dev --lima-cpus 8 --lima-mem 16`.

**Rootfs corrupted**: Rebuild without destroying the Lima VM: `mvmctl setup --recreate`.

## Next Steps

- [README.md](README.md) -- full command reference and architecture
- [User Guide](docs/user-guide.md) -- writing Nix flakes for microVM images
- [Development](docs/development.md) -- contributing to mvm
- [Troubleshooting](docs/troubleshooting.md) -- common issues
- For multi-tenant fleet management, see [mvmd](https://github.com/auser/mvmd)
