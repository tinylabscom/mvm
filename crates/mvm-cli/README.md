# mvm-cli

Clap-based CLI commands, bootstrap workflow, diagnostics, update mechanism, and template management. This is a **pure library crate** — the `mvmctl` binary lives in the root package and calls `mvm_cli::run()`.

## Modules

| Module | Purpose |
|--------|---------|
| `commands` | Main CLI entry point (`run()`), all command definitions and handlers |
| `bootstrap` | Full environment setup and machine infrastructure readiness |
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
| `mvmctl bootstrap` | Full setup plus builder VM and workload-kernel acquisition |
| `mvmctl build image --flake .` | Build a microVM image from a Nix flake |
| `mvmctl run --flake .` | Build + start a microVM |
| `mvmctl console <name>` | Interactive PTY over vsock (dev-mode only) |
| `mvmctl template <action>` | Manage global templates (`create`, `build`, `list`) |
| `mvmctl image <action>` | Browse / search / fetch the bundled image catalog |
| `mvmctl network <action>` | Manage named dev networks |
| `mvmctl doctor [--json]` | System diagnostics |
| `mvmctl update` | Check for and install latest version |

## Global Flags

- `--log-format <human|json>` — Output format (default: human)
- `--fc-version <version>` — Override Firecracker version

## Dependencies

- `mvm-core`, `mvm`, `mvm-build`, `mvm-agentd`
