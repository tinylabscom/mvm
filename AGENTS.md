# Agent Working Agreement

## Lima VM Requirement

All Nix builds, Firecracker operations, `mvmctl` commands, test execution, clippy checks, and Linux-specific commands MUST be run inside the Lima VM. Use `limactl shell mvm-builder -- <command>` to execute commands inside the VM. The Lima VM name is `mvm-builder` (renamed from `mvm` in W7.2).

If the Lima VM is not running, boot it with:
```bash
cargo run -- dev
```

Once running, access it with:
```bash
limactl shell mvm-builder
```

Examples:
- `limactl shell mvm-builder -- cargo run --quiet -- template build openclaw --force`
- `limactl shell mvm-builder -- cargo run --quiet -- run --template openclaw --name oc`
- `limactl shell mvm-builder -- cargo run --quiet -- logs oc`
- `limactl shell mvm-builder -- cargo run --quiet -- stop oc`
- `limactl shell mvm-builder -- nix build .#packages.aarch64-linux.default`
- `limactl shell mvm-builder -- nix path-info -rsh /nix/store/<hash>`
- `limactl shell mvm-builder -- cargo test --workspace`
- `limactl shell mvm-builder -- cargo clippy --workspace -- -D warnings`
- `limactl shell mvm-builder -- cargo check --workspace`

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

## Privacy & Security

Privacy and security are **critical priorities** for this project and must be considered in every decision. All code changes, architecture decisions, and feature additions must be evaluated through a security lens:

- **Never log, store, or expose sensitive data** (secrets, tokens, keys, credentials, user data) in plaintext — in code, logs, config files, or error messages.
- **Validate and sanitize all inputs** at system boundaries (CLI args, config files, network data, vsock messages).
- **Apply least privilege** — processes, microVMs, and agents should have only the minimum permissions they need.
- **Default to secure configurations** — encryption on, auth required, restrictive permissions. Users opt out of security, never opt in.
- **Guard secrets in transit and at rest** — use signing, encryption, and secure channels (vsock, not plaintext TCP) for sensitive communication.
- **No hardcoded secrets** — tokens, keys, and credentials must come from environment variables, secure config, or runtime injection. Never commit secrets to the repository.
- **Consider attack surface** in every feature — new network listeners, file permissions, IPC channels, and CLI commands are all potential vectors.
- **Security tests are mandatory** — every security-relevant code path must have tests for both the positive path (valid data accepted) and negative path (tampered, expired, unauthorized data rejected).

## Clippy: Zero Warnings, Always

**ALWAYS** run `cargo clippy --workspace -- -D warnings` after every code change and fix every finding before committing or declaring a task done. Clippy warnings are treated as errors — the CI pre-commit hook enforces this and will block commits.

Rules:
- **Never suppress a lint with `#[allow(...)]`** — fix the underlying issue instead. If you think a suppression is genuinely necessary, explain why in a comment and get explicit approval.
- **Fix warnings immediately** — do not accumulate clippy debt. A warning introduced now becomes harder to diagnose later.
- **Common findings to watch for**: `clippy::too_many_arguments` (refactor into a params struct), `clippy::redundant_closure`, `clippy::needless_pass_by_value`, `clippy::single_match` → `if let`, unused imports/variables.
- **After adding new code**, run clippy before moving on — don't wait until the end of a task.

## No `unwrap()` in Production Code

**NEVER** use `.unwrap()` in production code. Always use `.expect("descriptive message")` instead, so that if a panic occurs, the error message explains what went wrong and where. `.unwrap()` is only acceptable in test code (`#[cfg(test)]` modules and `tests/` directories).

## Documentation

Documentation is a **first-class deliverable**. Every code change that touches user-facing behavior MUST include corresponding doc updates in the same commit or PR. Stale docs are bugs.

### When to update docs

- **Adding a CLI command, subcommand, or flag** → update `reference/cli-commands.md` with the new entry
- **Changing command behavior or defaults** → update both `reference/cli-commands.md` and any affected guides
- **Adding/removing environment variables** → update the Environment Variables table in `reference/cli-commands.md`
- **Adding/changing config options** → update `guides/config-secrets.md`
- **Changing network layout or vsock behavior** → update `guides/networking.md`
- **Changing template workflow** → update `guides/templates.md`
- **Changing Nix flake API (mkGuest)** → update `guides/nix-flakes.md`
- **Changing build/install steps** → update `getting-started/installation.md` and `contributing/development.md`

### Key doc files

- `public/src/content/docs/reference/cli-commands.md` — complete CLI command reference (every command, flag, and env var)
- `public/src/content/docs/reference/architecture.md` — workspace structure, dependency graph, key abstractions
- `public/src/content/docs/reference/filesystem.md` — drive model, rootfs layout, host-side paths
- `public/src/content/docs/reference/guest-agent.md` — guest agent, vsock protocol, probes
- `public/src/content/docs/guides/` — user guides (networking, templates, nix-flakes, config-secrets, troubleshooting)
- `public/src/content/docs/getting-started/` — quickstart, installation, first-microvm
- `public/src/content/docs/contributing/development.md` — contributor guide

### Rules

1. **Do not mark a task as done if docs are stale.** This is part of the Definition of Done.
2. **CLI reference must match the code.** If `commands.rs` has it, `cli-commands.md` must have it — same flags, same defaults, same descriptions.
3. **Verify after adding commands.** After adding or modifying any Clap command/subcommand/flag, diff `crates/mvm-cli/src/commands.rs` against `public/src/content/docs/reference/cli-commands.md` to confirm they match.
4. **Guides must reflect current behavior.** Don't document aspirational features — only what's implemented and working.

## Screenshots & Temporary Files

**NEVER** save screenshots, images, or any binary artifacts to the project root or any directory within the repository. Always save screenshots and temporary files to `/tmp/` (e.g. `/tmp/screenshot.png`, `/tmp/page-snapshot.png`). This prevents binary files from polluting the git history.

When using Playwright or other browser tools, explicitly set the output path to `/tmp/`:
- Screenshots: `filename: "/tmp/screenshot.png"`
- Snapshots: `filename: "/tmp/snapshot.md"`

If you accidentally save files to the repo, delete them immediately before committing.
