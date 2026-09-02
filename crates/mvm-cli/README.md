# mvm-cli

`mvm-cli` implements the `mvmctl` command-line product as a library. It owns
argument parsing, command dispatch, terminal/JSON presentation, bootstrap and
diagnostics, but the executable entry point remains in the root `mvmctl`
package.

## Who uses it

The root binary calls `mvm_cli::run()`. `xtask` enables it only to generate man
pages, and `mvm-conformance` invokes the resulting command surface. No
lower-level runtime crate depends on the CLI, which keeps presentation and
process-exit behavior out of reusable libraries.

## How it works

1. Clap parses the command tree and global output/settings flags.
2. Dispatch converts raw arguments into validated domain requests.
3. Handlers call `mvm-client`, build, runtime, capture, MCP, host-daemon, and
   filesystem APIs rather than duplicating their business rules.
4. Results are rendered through one human/JSON output boundary.
5. Signals and cleanup guards coordinate cancellation without losing the
   underlying lifecycle result.

Bootstrap and `doctor` inspect host capabilities and explain missing
dependencies. Machine commands perform admission preview and artifact checks
before mutation. Embedded host binaries are extracted from a verified manifest
when that release feature is enabled.

## Main areas

| Area | Representative modules |
|---|---|
| Command surface | `commands`, `commands::dispatch` |
| Machine execution | `exec`, `exec::launch_plan`, `exec::session` |
| Setup and diagnosis | `bootstrap`, `doctor` |
| Presentation | `ui`, `display`, `json_out`, `logging` |
| Templates and registry | `template_cmd`, `template_registry` |
| Host assets | `host_binaries`, `runtime_overlay` command helpers |
| Automation | `commands::ops::mcp`, `watch`, completions commands, `ts_runner` |
| Performance | `bench`, launch-contract exports |

## Features

Default features enable the builder VM and pure image writer used by normal
local workflows. Optional features cover test support, release channels,
embedded host binaries, libkrun, trusted APFS, S3 template registries, the wasm
backend, custom DNS, and live HVF validation. Feature selection must preserve
the distinction between user, host, and development closures in the root
package.

## Developing

Run `cargo test -p mvm-cli`. Every new flag or subcommand needs parser/help and
integration coverage, including JSON output and invalid input. Commands that
boot or manage microVMs run in the approved runtime environment; ordinary
library tests run on the host.
