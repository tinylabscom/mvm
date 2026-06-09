# Agent Working Agreement

## Builder VM Requirement

All Nix builds/evals, Firecracker operations, `mvmctl` runtime commands (anything that boots, talks to, or manages microVMs), and Linux-specific syscalls MUST run inside the project builder VM, not a Lima VM. Do not use `limactl` for this repo. The builder VM is the current Linux execution boundary for Nix and microVM work.

> **Exception (2026-05-31, owner-approved): Lima is permitted _strictly_ as a test-environment KVM provider** — e.g. a virtual `/dev/kvm` for Firecracker / Linux-KVM E2E tests that cannot run on the builder VM or on GitHub-hosted runners (which have no KVM). It is modeled as a **test/dev-tier `VmBackend`** (admission-visible, **refused by prod admission** — like the Docker fallback tier), so it can never silently run a production workload, and it is never used for builds/evals. Broader Lima use is a separate future decision (ADR-066 / Plan 117 §A28).

**Run cargo on the macOS host wherever it compiles cleanly.** `cargo test`, `cargo check`, and `cargo build` should default to the host so worktrees don't deadlock on shared builder state (cargo target-dir contention, registry locks, and `.git/index` cross-mount races are real and have caused us to lose work). Tests that genuinely need Linux — vsock, jailer/seccomp, dm-verity, network namespaces, anything that pokes at `/dev/kvm` or `/proc/net` — should be gated with `#[cfg(target_os = "linux")]` and only those sub-targets are run inside the builder VM. Workspace-wide `cargo clippy --workspace --all-targets -- -D warnings` is still expected to pass in the Linux builder environment before merge, since clippy needs to see the Linux-gated code paths.

**git only runs from the main `mvm/` checkout, never from inside a worktree directory and never from inside the builder VM.** The main checkout is the single git operator for the whole repo. To act on a worktree's branch, use `git -C /path/to/.worktrees/mvm-<slug> <cmd>` from the main checkout — that drives the worktree's index/HEAD/refs while keeping the running git process anchored at the main checkout. Reasons: (1) only one git process at a time touches `.git/objects`, `.git/packed-refs`, and the shared `.git/hooks/` invocation context, eliminating the cross-worktree contention that has caused us to lose work; (2) VM/shared-filesystem lock semantics can deadlock against host-side git. Cargo/nix/firecracker/mvmctl commands still run from each worktree's own directory — only `git` is centralized.

**Important:** `mvmctl` (via `cargo run`) commands like `build`, `up`, `down`, `logs`, and `ls` must be run inside the builder VM — they talk to Linux-only microVM tooling. `cargo test` / `cargo check` / `cargo build` should run on the macOS host by default (see "Run cargo on the macOS host" above); only `cargo clippy --workspace --all-targets`, Nix eval/build checks, and tests gated on `target_os = "linux"` need the builder VM.

## Worktree Workflow for Features

> **Active exception — the cleanup rewrite.** The in-progress complete refactor (`specs/plans/117-cleanup-and-rearchitecture-brief.md`, branch `cleanup-rearchitecture`) runs on a **single long-lived branch, not worktrees**, and all stale worktrees are being cleaned up first so it starts from a clean state. The worktree workflow below is the standard for **all work after** the rewrite lands — and the rewrite's own plans instruct future sessions to return to it.

Every feature, refactor, or non-trivial bug fix is developed in a git worktree — code edits and cargo invocations happen inside the worktree directory. Git operations (status, add, commit, stash, rebase, push, fetch, pull, hook execution) happen from the main `mvm/` checkout, with `-C` pointing at the worktree when needed. The main checkout is the single git operator; worktree directories are code+build sandboxes only.

### Never commit directly to `main`

`main` is updated only via merged pull requests — never by `git commit` against the local `main` branch, even from the main checkout, even for docs-only changes, even with `--no-verify`. Reasons:

- **Safety against parallel agents.** Multiple agents share `.git/`. Any agent that pulls/rebases/`reset --hard origin/main` (a routine recovery move) silently discards local-only commits on main. Branches that exist on `origin` cannot be wiped this way.
- **CI gating.** The full clippy + nextest + supply-chain + flake-check matrix only runs on PRs. A direct commit ships untested.
- **Audit trail.** PR descriptions, CI status, review comments, and merge events form the project's history. A local commit pushed to main loses all of it.

If you have changes intended for `main`, push them to a branch and open a PR — even a one-line typo fix. The repo's GitHub settings are not branch-protected, so the convention is the only thing keeping main clean.

The only `git` commands that should ever target `main` directly are read-only (`git log main`, `git show main:path`) or routine sync (`git fetch origin`, `git pull --ff-only origin main`).

### Creating the worktree

All worktrees live in a `.worktrees/` directory that sits as a sibling of the main checkout — never directly next to the main checkout. This keeps the parent directory (which holds the rest of the ecosystem repos) free of feature-branch clutter and makes it obvious at a glance which directories are real repos vs. transient sandboxes.

From the main `mvm/` checkout:

```bash
cd /Users/auser/work/tinylabs/mvmco/mvm
mkdir -p ../.worktrees                # one-time, if it doesn't already exist
git worktree add ../.worktrees/mvm-<feature-slug> -b feat/<feature-slug>
```

Then switch terminals/agents into the worktree directory for code work:

```bash
cd ../.worktrees/mvm-<feature-slug>
# edit code, run cargo, run mvmctl from here
```

Branch names follow the existing pattern (`feat/<slug>`, `fix/<slug>`, `chore/<slug>`).

### Doing git work for a worktree

Always from the main `mvm/` checkout, with `-C` pointing at the worktree:

```bash
cd /Users/auser/work/tinylabs/mvmco/mvm
git -C ../.worktrees/mvm-<feature-slug> status
git -C ../.worktrees/mvm-<feature-slug> add path/to/file
git -C ../.worktrees/mvm-<feature-slug> commit -m "..."
git -C ../.worktrees/mvm-<feature-slug> push -u origin feat/<feature-slug>
```

This serializes all git activity through one process and keeps `.git/objects`, `.git/packed-refs`, and the hooks dir from being touched by multiple agents at once. The pre-commit hook fires once per commit, in the main checkout — no concurrent-hook fan-out.

Agents working inside a worktree directory should not invoke `git` directly. If you need git state, ask the operator at the main checkout, or run a read-only `git -C <main-checkout> status` if you must.

### Isolating mutable state

Worktrees share `~/.mvm`, `~/.cache/mvm`, `~/.cargo`, `~/.rustup`, the builder VM, the Nix store, and any pushed registries with the main checkout. Per-worktree isolation is achieved by overriding three env vars for the duration of a command:

```bash
MVM_DATA_DIR="$PWD/.mvm-test"      \
CARGO_TARGET_DIR="$PWD/.mvm-test/target" \
CARGO_HOME="$PWD/.mvm-test/cargo"  \
  cargo test --workspace
```

- `MVM_DATA_DIR` redirects mvmctl's templates, sockets, microVM registry, snapshots, and signing keys away from `~/.mvm`.
- `CARGO_TARGET_DIR` gives the worktree its own `target/` so two worktrees compiling at once don't fight over output paths or rustc invocation locks.
- `CARGO_HOME` gives the worktree its own cargo registry/cache and (most importantly) its own `.package-cache` lock — without this, two concurrent `cargo test` invocations across worktrees serialize on `~/.cargo/registry/.package-cache` and one will block until the other finishes downloading or resolving.

Four things are committed to make this convenient:

- **`scripts/dev-env.sh`** exports all three vars (resolved relative to the worktree root, so it works from any subdir). Source it once at the top of a shell: `source scripts/dev-env.sh`.
- **`bin/dev`** is a wrapper that sources `scripts/dev-env.sh` and execs `cargo run --quiet -- "$@"`. Use it for any one-off `mvmctl` call: `bin/dev build`, `bin/dev exec ...`.
- **`just dev-test` / `just dev-clippy` / `just dev-check`** invoke cargo with the env sourced.
- **`.envrc.example`** sources `scripts/dev-env.sh` for direnv users (`cp .envrc.example .envrc && direnv allow`).

One-time per clone: run `just install-hooks` from the main checkout to point `core.hooksPath` at `.githooks/`. The committed pre-commit hook (`.githooks/pre-commit`) is intentionally light — it formats Rust code and checks Nix formatting, nothing else — so it doesn't block worktree workflows. Heavy gates (workspace clippy, full tests, supply-chain checks) run in CI.

### What still collides between worktrees

Even with per-worktree isolation, a few resources are shared and can cause concurrent commands to interfere:

- **`.git/objects/`, `.git/packed-refs`, and the shared hooks dir.** Each `git worktree add` directory has its own index, HEAD, and refs (in `.git/worktrees/<name>/`), but the object store, packed refs, and hooks dir are one set. The "git only runs from the main checkout" rule (see the top of this doc) is what keeps these from colliding — never bypass it. Even with that rule, the pre-commit hook still gets invoked on every commit, so keep it limited to formatting + fast checks; don't run a full `cargo test --workspace` from inside a hook.
- **The builder VM's `/var/lib/mvm/`, `br-mvm` bridge, and TAP devices.** Vary microVM and TAP names between worktrees if you need two microVMs running at the same time.
- **The Nix store inside the builder VM.** This is shared by design (warm cache) and Nix's own locking handles it.

### Builder VM sharing

The builder VM is shared across worktrees by design — **never fork it per worktree**. It is expensive to boot, and the Nix store inside it is the warm cache that makes builds fast; a per-worktree VM would duplicate tens of GB of store, re-download the kernel/rootfs, and multiply boot time with no isolation benefit.

The `MVM_DATA_DIR` override is what isolates per-feature state — templates, sockets, the microVM registry, snapshots, signing keys. Anything that would otherwise land in `~/.mvm` ends up under the worktree.

State that *does* live inside the shared builder VM (`/var/lib/mvm/`, the `br-mvm` bridge, TAP devices, in-flight microVMs) is the only collision surface between worktrees. If two worktrees need to run microVMs concurrently, give them distinct microVM and TAP names — do not spin up a second builder VM.

### Optional: direnv

Users who already have direnv installed can opt in:

```bash
cp .envrc.example .envrc
direnv allow
```

This is a convenience for users who already have direnv installed; the `bin/dev` / `just dev-*` wrappers work without it.

### Cleaning up

After the feature merges:

```bash
git worktree remove ../.worktrees/mvm-<feature-slug>
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
6. **Tick the plan checkboxes**: as you complete each task or sub-task, check it off (`- [x]`) in the active plan under `specs/plans/<N>-*.md`. **The plan's checkboxes are the source of truth for progress** — a resumed or parallel session reads the last unchecked box to know exactly where to pick the work back up. Never mark a box done before its tests are green. Keep the plan and `specs/SPRINT.md` in sync.

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

## Reuse First; Compose Small, Testable Units

**Never reimplement functionality that already exists.** Before writing anything,
search for an existing helper, type, trait impl, or crate that already does the
job — `grep`/`rg` the workspace, check the facade re-exports, read the module the
work belongs in. Duplicated logic drifts out of sync, doubles the test surface,
and is the single most common source of bugs in this repo. If an existing helper
is *almost* right, extend or generalize it — don't fork a second copy.

- **Use the helpers.** All `~/.mvm` **and** `~/.cache/mvm` paths go through
  `mvm-core::config` helpers (`vm_state_dir`, `mvm_keys_dir`, `mvm_cache_dir`, …) —
  **never** build them inline with `std::env::var("HOME")` + `.join(...)`, which
  silently ignores `MVM_DATA_DIR` / `MVM_CACHE_DIR` / XDG and breaks parallel-worktree
  isolation. Shell/VM ops go through the `ShellEnvironment`/`BuildEnvironment` traits.
  Find the established helper and call it; if one is missing, add it where it belongs
  and call it from every site.
- **Small, single-purpose functions.** Prefer many small functions that each do
  one thing and are trivially unit-testable over one large function with branches
  and side effects tangled together. If you can't write a focused test for it, it
  is too big — split it.
- **Test the code — always, no exceptions.** Every new or changed function, type,
  trait impl, and code path ships with tests in the same change: positive path,
  negative/error path, and edge cases. This is not optional and not deferrable —
  "no task is done without tests" (see "Definition of Done" and "Test
  Expectations"). Write the test alongside (or before) the code, not after the
  fact. A helper you extracted to be testable that has no test is not done. If a
  function can fail, prove it returns `Err` (never panics) with a test.
- **Make illegal states unrepresentable.** Lean on the type system: newtypes over
  bare `String`/`u64` IDs, enums over stringly-typed flags, `Option`/`Result` over
  sentinel values. Push invariants into types so the compiler enforces them and
  fewer runtime checks (and tests) are even needed.
- **Don't over-abstract (YAGNI).** Reach for a trait/builder/generic when there is
  a *real* second case or genuine construction complexity — not speculatively. The
  goal is the simplest design that's reusable and testable, not maximal
  indirection. Match the existing pattern; don't invent a framework.
- **Builder pattern for multi-field construction.** Types with more than a couple
  of fields (especially optional ones) get a builder rather than a long positional
  constructor. This also kills `clippy::too_many_arguments` at the source instead
  of suppressing it.
- **Traits for behavior that varies.** When behavior differs by backend, env, or
  mode, express it as a trait with impls (see `VmBackend`, `ShellEnvironment`) —
  never a `match` on an enum scattered across call sites. One impl is one path,
  not the only path (see "Never lock into a single VMM").
- **Structs over loose tuples/params.** Group related values into a named struct
  (a config/params struct) so the shape is documented and testable, rather than
  threading bare arguments through many layers.

When in doubt, find the existing pattern in the codebase and follow it exactly —
match the surrounding naming, idiom, and module layout. Consistency is a feature.

## No Placeholders in Plans or Code

**NEVER** write placeholders in plans, ADRs, or code that ships. This includes:

- Literal `TBD`, `TODO: fill in`, `<PLACEHOLDER>`, `PLACEHOLDER_*` strings in checked-in files
- "Engineer adapts this to existing code" / "Concrete diff depends on existing structure" markers in plans
- Stub function bodies that exist only to silence the compiler (`let _ = (a, b);` followed by an explanatory comment)
- Schema entries marked "the reviewer must fill in the real value"
- Pseudo-code or "shape sketches" inside a plan that's supposed to ship to execution

Rules:

- **Before writing a plan task that touches existing code**, read the existing file with the Read tool and use what you find. Every code block in the plan is the real, complete code that goes into the commit.
- **When you don't know a value** (e.g., a SHA256 of a binary you can't execute), either compute it before writing the plan (via WebSearch / curl / etc.) or refactor the plan so the value isn't needed until execution time **and** the executing task spells out exactly how to compute it (the command, the source, the verification).
- **When the surrounding code structure is genuinely unknown** (e.g., a refactor of a file you haven't read), **stop and read it** before continuing the plan. Don't write "engineer adapts" — read it yourself.
- **For configs/fixtures that need operator-supplied values at install time** (not at code-write time), use a `Result::Err("missing operator config; see <docs>")` shape, not a placeholder string in a checked-in default file. The error message itself documents the gap.

Why this rule exists: placeholders push the work that hasn't been done onto the next reader (a subagent, a future contributor, or the reviewer). They look like progress but they're not. Plans that ship with placeholders are plans that aren't actually plans — they're outlines pretending to be plans.

## Documentation

Documentation is a **first-class deliverable**. Every code change that touches user-facing behavior MUST include corresponding doc updates in the same commit or PR. Stale docs are bugs.

### When to update docs

- **Adding a CLI command, subcommand, or flag** → update `reference/cli-commands.md` with the new entry
- **Changing command behavior or defaults** → update both `reference/cli-commands.md` and any affected guides
- **Adding/removing environment variables** → update the Environment Variables table in `reference/cli-commands.md`
- **Adding/changing config options** → update `guides/config-secrets.md`
- **Changing network layout or vsock behavior** → update `guides/networking.md`
- **Changing the manifest / build / registry workflow** → update `guides/manifests.md`
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
