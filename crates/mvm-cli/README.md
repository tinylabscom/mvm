# mvm-cli

Clap-based CLI commands, bootstrap workflow, diagnostics, update mechanism, and template management. This is a **pure library crate** — the `mvmctl` binary lives in the root package and calls `mvm_cli::run()`.

## Modules

| Module | Purpose |
|--------|---------|
| `commands` | Main CLI entry point (`run()`), all command definitions and handlers |
| `bootstrap` | Full environment setup (Homebrew/apt, Lima, Nix, Firecracker) |
| `doctor` | System diagnostics and dependency checks (`mvmctl doctor`) |
| `update` | Self-update from GitHub releases |
| `template_cmd` | Template CRUD commands (create, list, build, delete, push, pull) |
| `logging` | Log format configuration (`LogFormat::Human` / `LogFormat::Json`) |
| `ui` | Terminal UI helpers (colored messages, spinners, prompts, status tables) |
| `fleet` | Fleet management commands |
| `http` | HTTP client utilities (for update checks) |

## Commands

| Command | Description |
|---------|-------------|
| `mvmctl bootstrap` | Full setup from scratch |
| `mvmctl setup` | Create Lima VM, install Firecracker |
| `mvmctl dev` | Launch Lima dev environment (auto-bootstraps) |
| `mvmctl start [image]` | Start headless Firecracker microVM |
| `mvmctl stop [name]` | Stop a running microVM |
| `mvmctl shell` | Open a shell in the Lima VM |
| `mvmctl sync` | Build mvmctl from source inside Lima and install |
| `mvmctl build --flake .` | Build microVM image from Nix flake |
| `mvmctl run --flake .` | Build + start microVM |
| `mvmctl status` | Show Lima and microVM status |
| `mvmctl logs <name>` | Show microVM console or hypervisor logs |
| `mvmctl doctor [--json]` | System diagnostics |
| `mvmctl update` | Check for and install latest version |
| `mvmctl template <action>` | Manage global templates |

## Global Flags

- `--log-format <human|json>` — Output format (default: human)
- `--fc-version <version>` — Override Firecracker version

## Dependencies

- `mvm-core`, `mvm-runtime`, `mvm-build`, `mvm-guest`
