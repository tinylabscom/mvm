# mvm-cli

Clap-based CLI commands, bootstrap workflow, diagnostics, update mechanism, and template management. This is a **pure library crate** — the `mvm` binary lives in the root package and calls `mvm_cli::run()`.

## Modules

| Module | Purpose |
|--------|---------|
| `commands` | Main CLI entry point (`run()`), all command definitions and handlers |
| `bootstrap` | Full environment setup (Homebrew/apt, Lima, Nix, Firecracker) |
| `doctor` | System diagnostics and dependency checks (`mvm doctor`) |
| `update` | Self-update from GitHub releases |
| `template_cmd` | Template CRUD commands (create, list, build, delete, push, pull) |
| `logging` | Log format configuration (`LogFormat::Human` / `LogFormat::Json`) |
| `ui` | Terminal UI helpers (colored messages, spinners, prompts, status tables) |
| `fleet` | Fleet management commands |
| `http` | HTTP client utilities (for update checks) |

## Commands

| Command | Description |
|---------|-------------|
| `mvm bootstrap` | Full setup from scratch |
| `mvm setup` | Create Lima VM, install Firecracker |
| `mvm dev` | Launch Lima dev environment (auto-bootstraps) |
| `mvm start [image]` | Start headless Firecracker microVM |
| `mvm stop [name]` | Stop a running microVM |
| `mvm shell` | Open a shell in the Lima VM |
| `mvm sync` | Build mvm from source inside Lima and install |
| `mvm build --flake .` | Build microVM image from Nix flake |
| `mvm run --flake .` | Build + start microVM |
| `mvm status` | Show Lima and microVM status |
| `mvm logs <name>` | Show microVM console or hypervisor logs |
| `mvm doctor [--json]` | System diagnostics |
| `mvm update` | Check for and install latest version |
| `mvm template <action>` | Manage global templates |

## Global Flags

- `--log-format <human|json>` — Output format (default: human)
- `--fc-version <version>` — Override Firecracker version

## Dependencies

- `mvm-core`, `mvm-runtime`, `mvm-build`, `mvm-guest`
