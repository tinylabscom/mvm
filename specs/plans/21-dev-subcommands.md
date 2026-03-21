# Plan: Dev Subcommands

## Context

The `dev` command was a monolithic action that bootstrapped, started Lima, and dropped into a shell all at once. There was no way to stop the Lima dev environment or check its status without using `limactl` directly. The top-level `shell` command duplicated part of `dev`'s functionality.

## Changes

### CLI restructuring

Replaced the flat `Dev { ... }` variant with `Dev { action: Option<DevCmd> }` and a new `DevCmd` enum:

- `dev up` — bootstrap + start Lima + drop into shell (all current `dev` behavior)
- `dev down` — stop the Lima VM gracefully
- `dev shell` — open shell in running Lima VM (moved from top-level `shell`)
- `dev status` — show Lima VM status + tool versions (Firecracker, Nix, mvmctl)

Bare `mvmctl dev` defaults to `dev up` for backward compatibility.

Removed the top-level `Shell` command in favor of `dev shell`.

### Runtime additions

Added `lima::stop_vm()` and `lima::stop()` to mvm-runtime (mirrors existing `start_vm`/`start` pattern).

### Files modified

- `crates/mvm-runtime/src/vm/lima.rs` — `stop_vm()`, `stop()`, updated error message
- `crates/mvm-cli/src/commands.rs` — `DevCmd` enum, dispatch, `cmd_dev_down()`, `cmd_dev_status()`, removed `Shell` variant
- `tests/cli.rs` — updated tests for new subcommand structure
- `README.md`, `CLAUDE.md`, site docs — updated command references
