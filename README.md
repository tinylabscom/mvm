# mvmctl

Lightweight VM development tool. Build reproducible VM images from Nix flakes, launch them on the best available backend, and manage reusable templates.

| Backend | Platform | Use Case |
|---------|----------|----------|
| [Firecracker](https://firecracker-microvm.github.io/) | Linux (KVM), WSL2 | Production -- hardware isolation, snapshots |
| [Apple Virtualization](https://developer.apple.com/documentation/virtualization) | macOS 26+ (Apple Silicon) | Dev -- sub-second startup |
| [Docker](https://docs.docker.com/get-docker/) | Linux, macOS, Windows, WSL2 | Universal -- works everywhere Docker runs |
| [Lima](https://lima-vm.io/) + Firecracker | macOS <26, Linux without KVM | Legacy fallback |

Backend is auto-selected or forced with `--hypervisor`:

```
Linux (KVM):    mvmctl up  -->  Firecracker microVM (direct)
WSL2 (KVM):     mvmctl up  -->  Firecracker microVM (direct)
macOS 26+:      mvmctl up  -->  Apple Virtualization.framework
Docker:         mvmctl up  -->  Docker container
macOS <26:      mvmctl up  -->  Lima VM  -->  Firecracker microVM
```

All backends consume the same Nix-built ext4 rootfs -- only the runtime differs.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/auser/mvm/main/install.sh | sh
```

Or from source:

```bash
git clone https://github.com/auser/mvm.git && cd mvm
cargo build --release
cp target/release/mvmctl ~/.local/bin/
```

Or via Cargo:

```bash
cargo install mvmctl
```

## Quick Start

```bash
# Build and run a VM from a Nix flake
mvmctl up --flake .

# Run in background with port forwarding
mvmctl up --flake . -d -p 8080:8080

# Run from a pre-built template
mvmctl up --template my-app --name app1

# List running VMs
mvmctl ls

# Stop a VM (or all VMs)
mvmctl down app1
mvmctl down

# Force a specific backend
mvmctl up --flake . --hypervisor apple-container
```

## Architecture

```
Layer 1: Host (macOS / Linux)
  mvmctl CLI runs natively
  Nix builds run in Lima (macOS) or natively (Linux)

Layer 2: VM Backend (auto-selected)
  Firecracker .... KVM microVMs (Linux native, snapshots)
  Apple Container  Virtualization.framework (macOS 26+)
  Lima + FC ...... nested virtualization (macOS <26 fallback)

Layer 3: Guest
  Minimal OS (busybox init, built from Nix flakes)
  Headless -- no SSH, communicates via vsock only
  Drives: /dev/vda (rootfs), /dev/vdb (config), /dev/vdc (secrets), /dev/vdd (data)
```

7-crate Cargo workspace:

| Crate | Purpose |
|-------|---------|
| **mvm-core** | Pure types, IDs, config, protocol, signing, routing |
| **mvm-guest** | Vsock protocol, integration health checks, guest agent binary |
| **mvm-build** | Nix builder pipeline |
| **mvm-runtime** | Shell execution, VM lifecycle, template management |
| **mvm-security** | Security posture evaluation, jailer ops, seccomp profiles |
| **mvm-apple-container** | Apple Virtualization.framework backend (macOS 26+) |
| **mvm-cli** | Clap CLI, bootstrap, update, doctor, template commands |

## Building Images

### From a Nix Flake

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

        services.my-app = {
          command = "${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        healthChecks.my-app = {
          healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
          healthTimeoutSecs = 3;
        };
      };
    };
}
```

Build and run:

```bash
mvmctl build --flake .
mvmctl up --flake . --cpus 2 --memory 1024
```

### Service Builder Helpers

| Helper | Description |
|--------|-------------|
| `mkGuest` | Core image builder -- kernel, init, guest agent, networking, services |
| `mkNodeService` | Node.js service (npm install + esbuild) |
| `mkPythonService` | Python HTTP service (withPackages) |
| `mkStaticSite` | Static files served by busybox httpd |

## Templates

Templates are reusable pre-built VM images. Build once, run anywhere.

```bash
# Create and build a template
mvmctl template create my-app --flake . --profile minimal
mvmctl template build my-app

# Build with snapshot for instant restore (Firecracker only, 1-2s boot)
mvmctl template build my-app --snapshot

# Run from template
mvmctl up --template my-app --name app1

# Run multiple instances with different configs from same snapshot
mvmctl up --template my-app --name prod -v ./prod/config:/mnt/config -p 3000:3000
mvmctl up --template my-app --name staging -v ./staging/config:/mnt/config -p 3001:3000

# Share via S3-compatible registry
mvmctl template push my-app
mvmctl template pull my-app
```

Manage templates:

```bash
mvmctl template list
mvmctl template info my-app
mvmctl template edit my-app --mem 2048
mvmctl template delete my-app
```

## CLI Reference

### VM Lifecycle

| Command | Description |
|---------|-------------|
| `mvmctl up --flake <ref>` | Build and run a VM from a Nix flake (aliases: `run`, `start`) |
| `mvmctl up --template <name>` | Run from a pre-built template |
| `mvmctl up -d` | Run in background (detached, via launchd) |
| `mvmctl up -p HOST:GUEST` | Port mapping (repeatable) |
| `mvmctl up -v host:guest:size` | Volume mount (repeatable) |
| `mvmctl up --hypervisor <backend>` | Force backend: `firecracker`, `apple-container` |
| `mvmctl down [name]` | Stop VMs (by name, or all if omitted) |
| `mvmctl ls` | List running VMs (aliases: `ps`, `status`) |
| `mvmctl ls -a` | Include stopped VMs |
| `mvmctl logs <name>` | View guest console logs (`-f` to follow) |
| `mvmctl forward <name> -p PORT` | Forward a port from a running VM to localhost |

### Building

| Command | Description |
|---------|-------------|
| `mvmctl build --flake <ref>` | Build from a Nix flake |
| `mvmctl build --flake <ref> --watch` | Rebuild on flake.lock changes |
| `mvmctl cleanup` | Remove build artifacts and run Nix GC |

### Templates

| Command | Description |
|---------|-------------|
| `mvmctl template init <name> --local` | Scaffold a new template directory |
| `mvmctl template create <name>` | Register a template definition |
| `mvmctl template build <name>` | Build a template image |
| `mvmctl template build <name> --snapshot` | Build + capture Firecracker snapshot |
| `mvmctl template edit <name>` | Edit template config (--cpus, --mem, --flake, etc.) |
| `mvmctl template push/pull <name>` | Share via S3-compatible registry |
| `mvmctl template list` | List all templates |
| `mvmctl template info <name>` | Show details, sizes, snapshot status |
| `mvmctl template delete <name>` | Remove a template |

### Environment

| Command | Description |
|---------|-------------|
| `mvmctl dev [up]` | Auto-bootstrap and drop into Lima dev shell |
| `mvmctl dev down` | Stop the Lima development VM |
| `mvmctl dev shell` | Open a shell in the running Lima VM |
| `mvmctl dev status` | Show dev environment status |
| `mvmctl doctor` | System diagnostics and dependency checks |
| `mvmctl config show/edit/set` | Manage global config (~/.mvm/config.toml) |

### Utilities

| Command | Description |
|---------|-------------|
| `mvmctl update` | Self-update (`--check` for dry run) |
| `mvmctl uninstall` | Clean uninstall |
| `mvmctl audit tail` | View audit log |
| `mvmctl flake check` | Validate a Nix flake |
| `mvmctl metrics` | Runtime metrics (Prometheus or JSON) |
| `mvmctl completions <shell>` | Generate shell completions |
| `mvmctl shell-init` | Print shell config (completions + aliases) |

## Dev Setup

```bash
cargo build                              # Debug build
cargo test --workspace                   # Run all tests
cargo clippy --workspace -- -D warnings  # Lint (0 warnings required)
```

See [Development Guide](public/src/content/docs/contributing/development.md) for contributor guidelines, CI/CD, and release process.

## Documentation

- [Quick Start](QUICKSTART.md)
- [Documentation Site](https://gomicrovm.com)
- [Writing Nix Flakes](public/src/content/docs/guides/nix-flakes.md) -- mkGuest API
- [Templates](public/src/content/docs/guides/templates.md) -- reusable base images
- [Troubleshooting](public/src/content/docs/guides/troubleshooting.md) -- common issues
- [Contributing](public/src/content/docs/contributing/development.md) -- contributor guide

## License

Apache 2.0 -- see [LICENSE](LICENSE) for details.
