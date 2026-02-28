# Agent Working Agreement

## Lima VM Requirement

All Nix builds, Firecracker operations, and Linux-specific commands MUST be run inside the Lima VM. Use `limactl shell mvm -- <command>` to execute commands inside the VM. The Lima VM name is `mvm`.

Examples:
- `limactl shell mvm -- nix build .#packages.aarch64-linux.default`
- `limactl shell mvm -- nix path-info -rsh /nix/store/<hash>`
- `limactl shell mvm -- ls -lh /Users/auser/.mvm/templates/`

The `cargo run` commands (e.g. `cargo run -- template build`) automatically delegate to the Lima VM via `mvm_runtime::shell::run_in_vm()`, but direct Nix commands must be run via `limactl shell mvm`.

## Definition of Done

No task is complete without tests. Every feature, bug fix, or refactor must include:

1. **Tests first**: Write or update tests covering the new/changed behavior before marking a task done. Unit tests for logic, integration tests for CLI and cross-crate interactions.
2. **All tests green**: Run `cargo test --workspace` and confirm zero failures. New tests must pass alongside all existing tests.
3. **Zero clippy warnings**: Run `cargo clippy --workspace -- -D warnings` and fix all findings before calling a feature done.
4. **Compiling workspace**: Run `cargo check --workspace` (or full `cargo test`/`cargo build`) and fix any errors before you finish. Never leave the workspace in a non-compiling state.
5. **Update sprint spec**: After completing any phase, task, or sub-task, update `specs/SPRINT.md` to reflect the current status. Check off completed items (`- [x]`), update phase status labels (e.g. `**Status: COMPLETE**`), and add any new test counts or notes. The sprint spec must always accurately reflect what has been implemented.

## Test Expectations

- New types: serde roundtrip tests, default value tests where applicable.
- New protocol/wire code: roundtrip through mock I/O (e.g. `UnixStream::pair()`), error path tests (invalid input, wrong keys, malformed data).
- New CLI flags/commands: integration tests in `tests/cli.rs` verifying help text and argument parsing.
- Security code: positive path (valid data accepted), negative path (tampered/invalid data rejected), and edge cases (replay, wrong key, expired session).
- If a function can fail, test that it fails correctly (returns `Err`, not panic).
