# Agent Working Agreement

## Lima VM Requirement

All Nix builds, Firecracker operations, `mvmctl` commands, test execution, clippy checks, and Linux-specific commands MUST be run inside the Lima VM. Use `limactl shell mvm -- <command>` to execute commands inside the VM. The Lima VM name is `mvm`.

If the Lima VM is not running, boot it with:
```bash
cargo run -- dev
```

Once running, access it with:
```bash
limactl shell mvm
```

Examples:
- `limactl shell mvm -- cargo run --quiet -- template build openclaw --force`
- `limactl shell mvm -- cargo run --quiet -- run --template openclaw --name oc`
- `limactl shell mvm -- cargo run --quiet -- logs oc`
- `limactl shell mvm -- cargo run --quiet -- stop oc`
- `limactl shell mvm -- nix build .#packages.aarch64-linux.default`
- `limactl shell mvm -- nix path-info -rsh /nix/store/<hash>`
- `limactl shell mvm -- cargo test --workspace`
- `limactl shell mvm -- cargo clippy --workspace -- -D warnings`
- `limactl shell mvm -- cargo check --workspace`

**Important:** `mvmctl` (via `cargo run`) commands like `template build`, `run`, `stop`, `logs`, and `status` must be run inside the Lima VM — they talk to Firecracker which only runs inside Linux. `cargo test`, `cargo clippy`, and `cargo check` must also run inside the Lima VM to ensure correct Linux-target compilation and test execution. The `cargo run -- dev` bootstrap command is the only one that runs on the macOS host directly.

## Definition of Done

No task is complete without tests. Every feature, bug fix, or refactor must include:

1. **Tests first**: Write or update tests covering the new/changed behavior before marking a task done. Unit tests for logic, integration tests for CLI and cross-crate interactions.
2. **All tests green**: Run `cargo test --workspace` and confirm zero failures. New tests must pass alongside all existing tests.
3. **Zero clippy warnings/errors**: Run `cargo clippy --workspace -- -D warnings` and fix all findings before calling a feature done. Never suppress a clippy lint with `#[allow(...)]` — fix the underlying issue instead.
4. **Compiling workspace**: Run `cargo check --workspace` (or full `cargo test`/`cargo build`) and fix any errors before you finish. Never leave the workspace in a non-compiling state.
5. **Update sprint spec**: After completing any phase, task, or sub-task, update `specs/SPRINT.md` to reflect the current status. Check off completed items (`- [x]`), update phase status labels (e.g. `**Status: COMPLETE**`), and add any new test counts or notes. The sprint spec must always accurately reflect what has been implemented.

## Test Expectations

- New types: serde roundtrip tests, default value tests where applicable.
- New protocol/wire code: roundtrip through mock I/O (e.g. `UnixStream::pair()`), error path tests (invalid input, wrong keys, malformed data).
- New CLI flags/commands: integration tests in `tests/cli.rs` verifying help text and argument parsing.
- Security code: positive path (valid data accepted), negative path (tampered/invalid data rejected), and edge cases (replay, wrong key, expired session).
- If a function can fail, test that it fails correctly (returns `Err`, not panic).

## No `unwrap()` in Production Code

**NEVER** use `.unwrap()` in production code. Always use `.expect("descriptive message")` instead, so that if a panic occurs, the error message explains what went wrong and where. `.unwrap()` is only acceptable in test code (`#[cfg(test)]` modules and `tests/` directories).

## Documentation

When adding, changing, or removing user-facing features (CLI commands, flags, config options, behavior), update the corresponding site documentation in `public/src/content/docs/`. Key files:

- `reference/cli-commands.md` — complete CLI command reference
- `guides/` — user guides (networking, templates, nix-flakes, config-secrets, troubleshooting)
- `getting-started/` — quickstart, installation, first-microvm
- `contributing/development.md` — contributor guide

Documentation must stay in sync with the code. Do not mark a task as done if the docs are stale.

## Screenshots & Temporary Files

**NEVER** save screenshots, images, or any binary artifacts to the project root or any directory within the repository. Always save screenshots and temporary files to `/tmp/` (e.g. `/tmp/screenshot.png`, `/tmp/page-snapshot.png`). This prevents binary files from polluting the git history.

When using Playwright or other browser tools, explicitly set the output path to `/tmp/`:
- Screenshots: `filename: "/tmp/screenshot.png"`
- Snapshots: `filename: "/tmp/snapshot.md"`

If you accidentally save files to the repo, delete them immediately before committing.
