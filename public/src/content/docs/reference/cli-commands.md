---
title: CLI Commands
description: Complete command reference for mvmctl.
---

## Environment Management

| Command | Description |
|---------|-------------|
| `mvmctl bootstrap` | Full setup from scratch: Homebrew deps (macOS), Lima, Firecracker, kernel, rootfs |
| `mvmctl bootstrap --production` | Production mode (skip Homebrew, assume Linux with apt) |
| `mvmctl setup` | Create Lima VM and install Firecracker assets (requires limactl) |
| `mvmctl setup --recreate` | Stop microVM, rebuild rootfs from upstream squashfs |
| `mvmctl setup --force` | Re-run all setup steps even if already complete |
| `mvmctl setup --lima-cpus N --lima-mem N` | Configure Lima VM resources (defaults: 8 CPUs, 16 GiB) |
| `mvmctl dev` | Auto-bootstrap if needed, drop into Lima dev shell |
| `mvmctl dev --project ~/dir` | Auto-bootstrap then cd into a project directory |
| `mvmctl dev --metrics-port PORT` | Bind a Prometheus metrics endpoint (0 = disabled) |
| `mvmctl dev --watch-config` | Reload ~/.mvm/config.toml automatically when it changes |
| `mvmctl status` | Show platform, Lima VM, Firecracker, and microVM status |
| `mvmctl destroy` | Tear down Lima VM and all resources (confirmation required) |
| `mvmctl destroy -y` | Tear down without confirmation prompt |
| `mvmctl doctor` | Run system diagnostics and dependency checks |
| `mvmctl doctor --json` | Output diagnostics as JSON |
| `mvmctl update` | Check for and install mvmctl updates |
| `mvmctl update --check` | Only check for updates, don't install |
| `mvmctl update --force` | Force reinstall even if already up to date |
| `mvmctl update --skip-verify` | Skip cosign signature verification |

## MicroVM Lifecycle

| Command | Description |
|---------|-------------|
| `mvmctl run --flake <ref>` | Build from flake and boot a headless Firecracker VM |
| `mvmctl run --template <name>` | Run from a pre-built template (skip build) |
| `mvmctl run --name <name>` | Specify VM name (auto-generated if omitted) |
| `mvmctl run --profile <variant>` | Flake package variant (e.g. worker, gateway) |
| `mvmctl run --cpus N --memory SIZE` | Override vCPU count and memory (supports 512M, 4G, etc.) |
| `mvmctl run -p HOST:GUEST` | Forward a port mapping into the VM (repeatable) |
| `mvmctl run -e KEY=VALUE` | Inject an environment variable (repeatable) |
| `mvmctl run -v host:guest:size` | Mount a volume into the microVM (repeatable) |
| `mvmctl run --forward` | Auto-forward declared ports after boot (blocks until Ctrl-C) |
| `mvmctl run --hypervisor <backend>` | Hypervisor backend: `firecracker` (default) or `qemu` |
| `mvmctl run --config <path>` | Runtime config (TOML) for persistent resources/volumes |
| `mvmctl run --metrics-port PORT` | Bind a Prometheus metrics endpoint (0 = disabled) |
| `mvmctl run --watch-config` | Reload ~/.mvm/config.toml automatically when it changes |
| `mvmctl run --watch` | Watch flake for changes and auto-rebuild + reboot |
| `mvmctl stop [name]` | Stop a running microVM by name |
| `mvmctl stop --all` | Stop all running VMs |
| `mvmctl remove <name>` | Stop and remove a named microVM (alias: `rm`) |
| `mvmctl up [name]` | Launch microVMs from `mvm.toml` or CLI flags |
| `mvmctl up --flake <ref>` | Launch a single VM without config file |
| `mvmctl up -f <config>` | Path to fleet config (default: auto-discover mvm.toml) |
| `mvmctl down [name]` | Stop microVMs from `mvm.toml`, by name, or all |
| `mvmctl down -f <config>` | Stop only VMs defined in specified config |
| `mvmctl forward <name> -p PORT` | Forward a port from a running microVM to localhost |
| `mvmctl shell` | Open a shell in the Lima VM |
| `mvmctl shell --project ~/dir` | Open shell and cd into a project directory |
| `mvmctl ssh` | Open a shell in the Lima VM (alias for `mvmctl shell`) |
| `mvmctl ssh-config` | Print an SSH config entry for the Lima VM |
| `mvmctl sync` | Build mvmctl from source inside Lima and install to `/usr/local/bin/` |
| `mvmctl sync --debug` | Debug build (faster compile, slower runtime) |
| `mvmctl sync --force` | Rebuild and reinstall even if versions match |
| `mvmctl sync --json` | Output structured JSON events |
| `mvmctl sync --skip-deps` | Skip installing build dependencies |

## Building

| Command | Description |
|---------|-------------|
| `mvmctl build <path>` | Build from Mvmfile.toml in the given directory |
| `mvmctl build --flake <ref>` | Build from a Nix flake (local or remote) |
| `mvmctl build --flake <ref> --profile <variant>` | Build a specific flake package variant |
| `mvmctl build --flake <ref> --watch` | Build and rebuild on flake.lock changes |
| `mvmctl build --json` | Output structured JSON events instead of human-readable output |
| `mvmctl build -o <path>` | Output path for the built .elf image |
| `mvmctl cleanup` | Remove old dev-build artifacts and run Nix garbage collection |
| `mvmctl cleanup --all` | Remove all cached build revisions |
| `mvmctl cleanup --keep <N>` | Keep the N newest build revisions |
| `mvmctl cleanup --verbose` | Print each cached build path that gets removed |

## Templates

| Command | Description |
|---------|-------------|
| `mvmctl template init <name> --local` | Scaffold a new template directory with flake.nix |
| `mvmctl template init <name> --vm` | Scaffold inside the Lima VM (overrides --local) |
| `mvmctl template init <name> --preset <preset>` | Scaffold preset: minimal, http, postgres, worker (default: minimal) |
| `mvmctl template init <name> --dir <path>` | Base directory for local init (default: current dir) |
| `mvmctl template create <name>` | Create a single template definition |
| `mvmctl template create <name> --data-disk SIZE` | Create template with a data disk (10G, 512M, or plain MB; 0 = none) |
| `mvmctl template create-multi <base>` | Create templates for multiple roles (`--roles worker,gateway`) |
| `mvmctl template build <name>` | Build a template (runs nix build in Lima) |
| `mvmctl template build <name> --force` | Rebuild even if cached |
| `mvmctl template build <name> --snapshot` | Build, boot, wait for healthy, and capture a Firecracker snapshot |
| `mvmctl template build <name> --update-hash` | Recompute the Nix fixed-output derivation hash |
| `mvmctl template build <name> --config <toml>` | Build multiple variants from a template config TOML |
| `mvmctl template push <name>` | Push to S3-compatible registry |
| `mvmctl template push <name> --revision <hash>` | Push a specific revision |
| `mvmctl template pull <name>` | Pull from registry |
| `mvmctl template pull <name> --revision <hash>` | Pull a specific revision |
| `mvmctl template verify <name>` | Verify template checksums |
| `mvmctl template verify <name> --revision <hash>` | Verify a specific revision |
| `mvmctl template list` | List all templates (`--json` for JSON) |
| `mvmctl template info <name>` | Show template details and revisions (`--json` for JSON) |
| `mvmctl template edit <name>` | Edit template configuration (--cpus, --mem, --flake, --profile, --role, --data-disk) |
| `mvmctl template delete <name>` | Delete a template (`--force` to skip confirmation) |

## MicroVM Diagnostics

| Command | Description |
|---------|-------------|
| `mvmctl vm ping [name]` | Health-check running microVMs via vsock (all if no name given) |
| `mvmctl vm status [name]` | Query worker status (`--json` for JSON) |
| `mvmctl vm inspect <name>` | Deep-dive inspection (probes, integrations, worker status) (`--json` for JSON) |
| `mvmctl vm exec <name> -- <cmd>` | Run a command inside a running microVM (dev-only) |
| `mvmctl vm exec <name> --timeout <secs>` | Set exec timeout (default: 30s) |
| `mvmctl vm diagnose <name>` | Run layered diagnostics on a VM (works even when vsock is broken) (`--json` for JSON) |
| `mvmctl vm list` | List all running microVMs (`--json` for JSON) |
| `mvmctl logs <name>` | View guest console logs (`-f` to follow, `-n` for line count) |
| `mvmctl logs <name> --hypervisor` | View Firecracker hypervisor logs |

## Security

| Command | Description |
|---------|-------------|
| `mvmctl security status` | Show security posture score (`--json` for JSON) |

## Configuration

| Command | Description |
|---------|-------------|
| `mvmctl config show` | Print current config as TOML |
| `mvmctl config edit` | Open the config file in $EDITOR (falls back to nano) |
| `mvmctl config set <key> <value>` | Set a single config key (e.g. `mvmctl config set lima_cpus 4`) |

## Audit

| Command | Description |
|---------|-------------|
| `mvmctl audit tail` | Show the last 20 audit events from /var/log/mvm/audit.jsonl |
| `mvmctl audit tail -n <N>` | Show the last N audit events |
| `mvmctl audit tail -f` | Follow audit log output (poll until Ctrl-C) |

## Flake Validation

| Command | Description |
|---------|-------------|
| `mvmctl flake check` | Validate a Nix flake before building (current directory) |
| `mvmctl flake check --flake <ref>` | Validate a specific flake path or reference |
| `mvmctl flake check --json` | Output structured JSON instead of human-readable output |

## Utilities

| Command | Description |
|---------|-------------|
| `mvmctl completions <shell>` | Generate shell completions (bash, zsh, fish, powershell) |
| `mvmctl shell-init` | Print shell configuration (completions + dev aliases) to stdout |
| `mvmctl metrics` | Show runtime metrics (Prometheus text format) |
| `mvmctl metrics --json` | Show runtime metrics as JSON |
| `mvmctl cleanup-orphans` | Remove orphaned VM state files (dead PIDs) |
| `mvmctl cleanup-orphans --dry-run` | List orphans without deleting |
| `mvmctl uninstall` | Remove Lima VM, Firecracker, and all mvm state (confirmation required) |
| `mvmctl uninstall -y` | Uninstall without confirmation |
| `mvmctl uninstall --all` | Also remove ~/.mvm/ config dir and /usr/local/bin/mvmctl binary |
| `mvmctl uninstall --dry-run` | Print what would be removed without removing |
| `mvmctl release` | Pre-release checks (deploy guard + cargo publish dry-run) |
| `mvmctl release --dry-run` | Run cargo publish --dry-run for all crates |
| `mvmctl release --guard-only` | Run deploy guard checks only (version, tag, inter-crate deps) |

## Global Options

All commands accept these global options:

| Option | Description |
|--------|-------------|
| `--log-format <human\|json>` | Log format: human (default) or json (structured) |
| `--fc-version <VERSION>` | Override Firecracker version (e.g., v1.14.0) |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MVM_DATA_DIR` | Root data directory for templates and builds | `~/.mvm` |
| `MVM_FC_VERSION` | Firecracker version (auto-normalized to `vMAJOR.MINOR`) | Latest stable |
| `MVM_FC_ASSET_BASE` | S3 base URL for Firecracker assets | AWS default |
| `MVM_FC_ASSET_ROOTFS` | Override rootfs filename | Auto-detected |
| `MVM_FC_ASSET_KERNEL` | Override kernel filename | Auto-detected |
| `MVM_BUILDER_MODE` | Builder transport: `auto`, `vsock`, or `ssh` | `auto` |
| `MVM_TEMPLATE_REGISTRY_ENDPOINT` | S3-compatible endpoint URL for template push/pull | None |
| `MVM_TEMPLATE_REGISTRY_BUCKET` | S3 bucket name for templates | None |
| `MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID` | S3 access key ID | None |
| `MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY` | S3 secret access key | None |
| `MVM_TEMPLATE_REGISTRY_PREFIX` | Key prefix inside the bucket | `mvm` |
| `MVM_TEMPLATE_REGISTRY_REGION` | S3 region | `us-east-1` |
| `MVM_SSH_PORT` | Lima SSH local port | `60022` |
| `MVM_PRODUCTION` | Enable production mode checks | `false` |
| `RUST_LOG` | Logging level (e.g., `debug`, `mvm=trace`) | `info` |
