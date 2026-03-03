---
title: CLI Commands
description: Complete command reference for mvmctl.
---

## Environment Management

| Command | Description |
|---------|-------------|
| `mvmctl bootstrap` | Full setup from scratch: Homebrew deps (macOS), Lima, Firecracker, kernel, rootfs |
| `mvmctl setup` | Create Lima VM and install Firecracker assets (requires limactl) |
| `mvmctl setup --recreate` | Stop microVM, rebuild rootfs from upstream squashfs |
| `mvmctl dev` | Auto-bootstrap if needed, drop into Lima dev shell |
| `mvmctl status` | Show platform, Lima VM, Firecracker, and microVM status |
| `mvmctl destroy` | Tear down Lima VM and all resources (confirmation required) |
| `mvmctl doctor` | Run system diagnostics and dependency checks |
| `mvmctl update` | Check for and install mvmctl updates |
| `mvmctl update --check` | Only check for updates, don't install |

## MicroVM Lifecycle

| Command | Description |
|---------|-------------|
| `mvmctl start` | Start the default microVM (headless) |
| `mvmctl start <image>` | Start a custom image with optional --cpus, --memory, --volume |
| `mvmctl stop` | Stop the running microVM and clean up |
| `mvmctl stop --snapshot` | Create a snapshot before stopping (for instant restart) |
| `mvmctl shell` | Open a shell in the Lima VM |
| `mvmctl shell --project ~/dir` | Open shell and cd into a project directory |
| `mvmctl sync` | Build mvmctl from source inside Lima and install to `/usr/local/bin/` |
| `mvmctl sync --debug` | Debug build (faster compile, slower runtime) |
| `mvmctl ssh-config` | Print an SSH config entry for the Lima VM |

## Building

| Command | Description |
|---------|-------------|
| `mvmctl build <path>` | Build from Mvmfile.toml in the given directory |
| `mvmctl build --flake <ref>` | Build from a Nix flake (local or remote) |
| `mvmctl build --flake <ref> --watch` | Build and rebuild on flake.lock changes |
| `mvmctl run --flake <ref>` | Build from flake and boot a headless Firecracker VM |
| `mvmctl run --template <name>` | Run from a pre-built template |
| `mvmctl run --config-dir <path>` | Inject config files onto the config drive |
| `mvmctl run --secrets-dir <path>` | Inject secret files onto the secrets drive |
| `mvmctl run --volume host:guest:size` | Mount a volume into the microVM |

## Snapshots

| Command | Description |
|---------|-------------|
| `mvmctl snapshot create <name>` | Snapshot a running VM (pause → snapshot → resume) |
| `mvmctl snapshot delete <name>` | Remove snapshot files for a VM |

## Templates

| Command | Description |
|---------|-------------|
| `mvmctl template init <name> --local` | Scaffold a new template directory with flake.nix |
| `mvmctl template create <name>` | Create a single template definition |
| `mvmctl template create-multi <base>` | Create templates for multiple roles |
| `mvmctl template build <name>` | Build a template (runs nix build in Lima) |
| `mvmctl template build <name> --force` | Rebuild even if cached |
| `mvmctl template warm <name>` | Auto-warm: boot → health wait → snapshot → store |
| `mvmctl template push <name>` | Push to S3-compatible registry |
| `mvmctl template pull <name>` | Pull from registry |
| `mvmctl template verify <name>` | Verify template checksums |
| `mvmctl template list` | List all templates |
| `mvmctl template info <name>` | Show template details and revisions |
| `mvmctl template edit <name>` | Edit template configuration (--cpus, --mem, --flake, etc.) |
| `mvmctl template delete <name>` | Delete a template |

## MicroVM Diagnostics

| Command | Description |
|---------|-------------|
| `mvmctl vm ping [name]` | Health-check running microVMs via vsock |
| `mvmctl vm status [name]` | Query worker status (`--json` for JSON) |
| `mvmctl vm inspect <name>` | Deep-dive inspection (probes, integrations, worker status) |
| `mvmctl vm exec <name> -- <cmd>` | Run a command inside a running microVM (dev-only) |
| `mvmctl vm diagnose <name>` | Run layered diagnostics on a VM |
| `mvmctl logs <name>` | View guest console logs |
| `mvmctl logs <name> --hypervisor` | View Firecracker hypervisor logs |

## Security

| Command | Description |
|---------|-------------|
| `mvmctl security status` | Show security posture score (`--json` for JSON) |

## Utilities

| Command | Description |
|---------|-------------|
| `mvmctl completions <shell>` | Generate shell completions (bash, zsh, fish) |

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
| `RUST_LOG` | Logging level (e.g., `debug`, `mvm=trace`) | `info` |
