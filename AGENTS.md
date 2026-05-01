# Agent Working Agreement

## Lima VM Requirement

All Nix builds, Firecracker operations, `mvmctl` runtime commands (anything that boots, talks to, or manages microVMs), and Linux-specific syscalls MUST be run inside the Lima VM. Use `limactl shell mvm-builder -- <command>` to execute commands inside the VM. The Lima VM name is `mvm-builder` (renamed from `mvm` in W7.2).

**Run cargo on the macOS host wherever it compiles cleanly.** `cargo test`, `cargo check`, and `cargo build` should default to the host so worktrees don't deadlock on the single shared Lima VM (cargo target-dir contention, registry locks, and `.git/index` cross-mount races are real and have caused us to lose work). Tests that genuinely need Linux — vsock, jailer/seccomp, dm-verity, network namespaces, anything that pokes at `/dev/kvm` or `/proc/net` — should be gated with `#[cfg(target_os = "linux")]` and only those sub-targets are run inside Lima. Workspace-wide `cargo clippy --workspace --all-targets -- -D warnings` is still expected to pass inside Lima before merge, since clippy needs to see the Linux-gated code paths.

**git always runs on the macOS host, never inside Lima.** The repo is shared with the Lima VM via 9p/virtiofs and the two sides do not share git's lock semantics — running `git` from inside Lima while another worktree is also doing git work on the host produces "unable to write new index file" deadlocks. Only cargo/nix/firecracker/mvmctl operations cross into the VM.

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

**Important:** `mvmctl` (via `cargo run`) commands like `template build`, `run`, `stop`, `logs`, and `status` must be run inside the Lima VM — they talk to Firecracker which only runs inside Linux. `cargo test` / `cargo check` / `cargo build` should run on the macOS host by default (see "Run cargo on the macOS host" above); only `cargo clippy --workspace --all-targets` and tests gated on `target_os = "linux"` need Lima. `cargo run -- dev` always runs on the macOS host directly.

## Worktree Workflow for Features

Every feature, refactor, or non-trivial bug fix MUST be developed in a git worktree, never on the main checkout. This isolates in-flight work from the main checkout's `~/.mvm` registry, build cache, and dev VM state.

### Creating the worktree

```bash
git worktree add ../mvm-<feature-slug> -b feat/<feature-slug>
cd ../mvm-<feature-slug>
```

Branch names follow the existing pattern (`feat/<slug>`, `fix/<slug>`, `chore/<slug>`).

### Isolating mutable state

Worktrees share `~/.mvm`, `~/.cache/mvm`, `~/.cargo`, `~/.rustup`, the Lima VM, the Nix store, and any pushed registries with the main checkout. Per-worktree isolation is achieved by overriding three env vars for the duration of a command:

```bash
MVM_DATA_DIR="$PWD/.mvm-test"      \
CARGO_TARGET_DIR="$PWD/.mvm-test/target" \
CARGO_HOME="$PWD/.mvm-test/cargo"  \
  cargo test --workspace
```

- `MVM_DATA_DIR` redirects mvmctl's templates, sockets, microVM registry, snapshots, and signing keys away from `~/.mvm`.
- `CARGO_TARGET_DIR` gives the worktree its own `target/` so two worktrees compiling at once don't fight over output paths or rustc invocation locks.
- `CARGO_HOME` gives the worktree its own cargo registry/cache and (most importantly) its own `.package-cache` lock — without this, two concurrent `cargo test` invocations across worktrees serialize on `~/.cargo/registry/.package-cache` and one will block until the other finishes downloading or resolving.

A `bin/dev` wrapper, `scripts/dev-env.sh`, and `just dev-*` recipes that bake all three in are planned but not yet committed — until they land, set the env vars explicitly in worktrees, or `direnv allow` an `.envrc` that exports them.

### What still collides between worktrees

Even with per-worktree isolation, a few resources are shared and can cause concurrent commands to interfere:

- **`.git/objects/`, `.git/packed-refs`, and the shared hooks dir.** Each `git worktree add` directory has its own index, HEAD, and refs (in `.git/worktrees/<name>/`), but the object store and packed refs are one set. Concurrent `git status` is fine (read-only); concurrent `git stash`, `git commit`, and especially `git rebase` from multiple worktrees can race on `.git/packed-refs` and the shared `.git/hooks/` invocation context. Don't run heavy hooks (full `cargo test --workspace`) on every commit — the pre-commit hook should be limited to formatting + fast checks.
- **The Lima VM's `/var/lib/mvm/`, `br-mvm` bridge, and TAP devices.** Vary microVM and TAP names between worktrees if you need two microVMs running at the same time.
- **The Nix store inside Lima.** This is shared by design (warm cache) and Nix's own locking handles it.

### Lima VM sharing

The Lima VM (`mvm-builder`) is shared across worktrees by design — **never fork it per worktree**. It is expensive to boot, and the Nix store inside it is the warm cache that makes builds fast; a per-worktree VM would duplicate tens of GB of store, re-download the kernel/rootfs, and multiply boot time with no isolation benefit. There is also no second VM name baked into the codebase: `mvmctl`, the `Justfile`, CI, and AGENTS.md examples all hard-code `mvm-builder`, and `RuntimeBuildEnv` / `run_on_vm` route through `mvm_runtime::config::VM_NAME`.

The `MVM_DATA_DIR` override is what isolates per-feature state — templates, sockets, the microVM registry, snapshots, signing keys. Anything that would otherwise land in `~/.mvm` ends up under the worktree.

State that *does* live inside the shared Lima VM (`/var/lib/mvm/`, the `br-mvm` bridge, TAP devices, in-flight microVMs) is the only collision surface between worktrees. If two worktrees need to run microVMs concurrently, give them distinct microVM and TAP names — do not spin up a second Lima VM.

### Optional: direnv

Users who already have direnv installed can opt in:

```bash
cp .envrc.example .envrc
direnv allow
```

This is a convenience, not a requirement. Once the `bin/dev` / `just dev-*` wrappers land, those will be the default; until then, set `MVM_DATA_DIR` inline as shown above.

### Cleaning up

After the feature merges:

```bash
git worktree remove ../mvm-<feature-slug>
```

### When NOT to use a worktree

Trivial single-line changes (typo fixes, doc word swaps, dependency bumps) can land directly on a topic branch in the main checkout. The worktree rule applies to anything that touches code, runtime state, or the registry.

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
