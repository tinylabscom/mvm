# Agent Working Agreement

Backing: shipped-source
Validation: check-sprint-append

## Builder VM Requirement

All Nix builds/evals, Firecracker operations, `mvmctl` runtime commands (anything that boots, talks to, or manages microVMs), and Linux-specific syscalls MUST run inside the project builder VM, not a Lima VM. Do not use `limactl` for this repo. The builder VM is the current Linux execution boundary for Nix and microVM work.

> **Exception (2026-05-31, owner-approved): Lima is permitted _strictly_ as a test-environment KVM provider** — e.g. a virtual `/dev/kvm` for Firecracker / Linux-KVM E2E tests that cannot run on the builder VM or on GitHub-hosted runners (which have no KVM). It is modeled as a **test/dev-tier `VmBackend`** (admission-visible, **refused by prod admission** — like the Docker fallback tier), so it can never silently run a production workload, and it is never used for builds/evals. Broader Lima use is a separate future decision (ADR-022 / Plan 117 §A28).

> **Exception (2026-08-10, user-authorized for Plan 314):** Native macOS
> HVF live lifecycle tests and teardown benchmarks may run on the macOS host
> because the Linux builder VM cannot provide Hypervisor.framework. This is
> limited to explicit HVF test/benchmark commands in the Plan 314 worktree;
> Nix builds/evals, Firecracker operations, Linux-specific checks, and all
> other `mvmctl` runtime commands remain subject to the builder-VM rule. Do
> not use Lima for this HVF exception.

> **Exception (2026-08-13, owner-approved):** `mvmctl machine run --hypervisor wasm`
> (or any other `mvmctl` invocation explicitly targeting the `wasm` backend) may run
> on the macOS host. The wasm backend runs a `wasm32-wasip1` module under host
> `wasmtime`; it does not boot a Linux microVM, needs no KVM, and does not touch
> Firecracker / jailer / seccomp / network-namespace tooling. All other `mvmctl`
> runtime commands remain subject to the builder-VM rule.

**Run cargo on the macOS host wherever it compiles cleanly.** `cargo test`, `cargo check`, and `cargo build` should default to the host so worktrees don't deadlock on shared builder state (cargo target-dir contention, registry locks, and `.git/index` cross-mount races are real and have caused us to lose work). Tests that genuinely need Linux — vsock, jailer/seccomp, dm-verity, network namespaces, anything that pokes at `/dev/kvm` or `/proc/net` — should be gated with `#[cfg(target_os = "linux")]` and only those sub-targets are run inside the builder VM. Workspace-wide `cargo clippy --workspace --all-targets -- -D warnings` is still expected to pass in the Linux builder environment before merge, since clippy needs to see the Linux-gated code paths.

**git only runs from the main `mvm/` checkout, never from inside a worktree directory and never from inside the builder VM.** The main checkout is the single git operator for the whole repo. To act on a worktree's branch, use `git -C /path/to/.worktrees/mvm-<slug> <cmd>` from the main checkout — that drives the worktree's index/HEAD/refs while keeping the running git process anchored at the main checkout. Reasons: (1) only one git process at a time touches `.git/objects`, `.git/packed-refs`, and the shared `.git/hooks/` invocation context, eliminating the cross-worktree contention that has caused us to lose work; (2) VM/shared-filesystem lock semantics can deadlock against host-side git. Cargo/nix/firecracker/mvmctl commands still run from each worktree's own directory — only `git` is centralized.

**Important:** `mvmctl` (via `cargo run`) commands like `build`, `up`, `down`, `logs`, and `ls` must be run inside the builder VM — they talk to Linux-only microVM tooling. The exception is an explicit `--hypervisor wasm` target, which may run on the macOS host. `cargo test` / `cargo check` / `cargo build` should run on the macOS host by default (see "Run cargo on the macOS host" above); only `cargo clippy --workspace --all-targets`, Nix eval/build checks, and tests gated on `target_os = "linux"` need the builder VM.

## Worktree Workflow for All Changes

Every change is developed in a git worktree, including documentation, typo fixes,
dependency bumps, features, refactors, and bug fixes. Code edits and cargo
invocations happen inside the worktree directory. Git operations (status, add,
commit, stash, rebase, push, fetch, pull, hook execution) happen from the main
`mvm/` checkout, with `-C` pointing at the worktree when needed. The main checkout
is the single git operator; worktree directories are code+build sandboxes only.

### Keep the main checkout on synchronized `main`

The main `mvm/` checkout is a control plane for git operations and must always
remain checked out on `main`. Never create, check out, or do change work on a
topic branch there, even temporarily. Create every topic branch in its worktree
with `git worktree add ... -b <branch>`, or attach an existing branch with
`git worktree add ... <branch>`.

At the start and end of every task, verify that the main checkout is clean, is on
`main`, and is synchronized with `origin/main`. Run `git fetch origin` followed
by `git pull --ff-only origin main` from the main checkout whenever synchronization
is needed. If a topic branch is accidentally checked out there, first preserve
all changes and confirm the branch is clean, then switch the main checkout back
to `main`, synchronize it, and attach the topic branch to a worktree before doing
any further work.

### Never commit directly to `main`

`main` is updated only via merged pull requests — never by `git commit` against the local `main` branch, even from the main checkout, even for docs-only changes, even with `--no-verify`. Reasons:

- **Safety against parallel agents.** Multiple agents share `.git/`. Any agent that pulls/rebases/`reset --hard origin/main` (a routine recovery move) silently discards local-only commits on main. Branches that exist on `origin` cannot be wiped this way.
- **CI gating.** The full clippy + nextest + supply-chain + flake-check matrix only runs on PRs. A direct commit ships untested.
- **Audit trail.** PR descriptions, CI status, review comments, and merge events form the project's history. A local commit pushed to main loses all of it.

If you have changes intended for `main`, push them to a branch and open a PR — even a one-line typo fix. The repo's GitHub settings are not branch-protected, so the convention is the only thing keeping main clean.

The only `git` commands that should ever target `main` directly are read-only (`git log main`, `git show main:path`) or routine sync (`git fetch origin`, `git pull --ff-only origin main`).

After any pull request merge, immediately sync the local main checkout before doing anything else: `git fetch origin` followed by `git pull --ff-only origin main`. Do not leave local `main` behind the merged PR state.

PR titles and bodies must never include the assistant/tool branding. Keep PR metadata focused on the code change itself.

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

Worktrees share `~/.mvm`, `~/.cargo`, `~/.rustup`, the builder VM, the Nix store, and any pushed registries with the main checkout. Per-worktree isolation is achieved by overriding three env vars for the duration of a command:

```bash
MVM_HOME="$PWD/.mvm-test"          \
CARGO_TARGET_DIR="$PWD/.mvm-test/target" \
CARGO_HOME="$PWD/.mvm-test/cargo"  \
  cargo test --workspace
```

- `MVM_HOME` redirects mvmctl's entire state tree — templates, sockets, caches, the microVM registry, snapshots, and signing keys — away from `~/.mvm`.
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

The `MVM_HOME` override is what isolates per-feature state — templates, sockets, the microVM registry, snapshots, signing keys. Anything that would otherwise land in `~/.mvm` ends up under the worktree.

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

### No worktree exceptions

All changes use a worktree. There is no docs-only, one-line, dependency-bump, or
other trivial-change exception that permits checking out a topic branch in the
main checkout.

## Definition of Done

No task is complete without tests. Every feature, bug fix, or refactor must include:

1. **Tests first**: Write or update tests covering the new/changed behavior before marking a task done. Unit tests for logic, integration tests for CLI and cross-crate interactions.
2. **All tests green**: Run `cargo test --workspace` and confirm zero failures. New tests must pass alongside all existing tests.
3. **Zero clippy warnings/errors**: Run `cargo clippy --workspace -- -D warnings` and fix all findings before calling a feature done. Never suppress a clippy lint with `#[allow(...)]` — fix the underlying issue instead.
4. **Compiling workspace**: Run `cargo check --workspace` (or full `cargo test`/`cargo build`) and fix any errors before you finish. Never leave the workspace in a non-compiling state. **`--all-targets` is not exhaustive**: it silently skips targets behind `required-features` (the `mvm-conformance` cucumber runner needs `--features bdd`), and on macOS it cannot compile `cfg(target_os = "linux")` files at all — including Linux-gated *test* files, which `just check-linux` also misses because that recipe is `--lib` only. Changing the shape of a shared type (adding a struct field, a trait method, an enum variant) therefore needs `just check-gated` before pushing. Skipping it surfaces in CI as `check-nextest-groups` failing with "cargo nextest list failed", which names neither the file nor the field.
5. **Update sprint spec**: After completing any phase, task, or sub-task, update `specs/SPRINT.md` to reflect the current status. Check off completed items (`- [x]`), update phase status labels (e.g. `**Status: COMPLETE**`), and add any new test counts or notes. The sprint spec must always accurately reflect what has been implemented.
6. **Tick the plan checkboxes**: as you complete each task or sub-task, check it off (`- [x]`) in the active plan under `specs/plans/`. New plans are named by slug, not number (`2026-08-15-<slug>.md`) — see CLAUDE.md §"Naming a new plan" for why, and `xtask check-plan-names` enforces it. **The plan's checkboxes are the source of truth for progress** — a resumed or parallel session reads the last unchecked box to know exactly where to pick the work back up. Never mark a box done before its tests are green. Keep the plan and `specs/SPRINT.md` in sync.
7. **Update the refactor rollup**: when you land, merge, or descope a workstream in any in-flight plan, tick/strike the matching box in `specs/REFACTOR-STATUS.md` in the **same** change and bump its "Last updated" date. It is a quick cross-plan index, not the source of truth — if it disagrees with a `specs/plans/` doc, the plan doc wins; fix the rollup. The plan checkboxes (item 6), `specs/SPRINT.md` (item 5), and `specs/REFACTOR-STATUS.md` move together — never update one and leave the others stale.

## Test Expectations

- Broad product coverage: cover as much of the product as practical with behavior-driven development (BDD) tests that exercise user-visible workflows end to end. Add or update BDD scenarios whenever behavior changes, while retaining focused unit and integration tests for lower-level logic and failure paths.
- New types: serde roundtrip tests, default value tests where applicable.
- New protocol/wire code: roundtrip through mock I/O (e.g. `UnixStream::pair()`), error path tests (invalid input, wrong keys, malformed data).
- New CLI flags/commands: integration tests in `tests/cli.rs` verifying help text and argument parsing.
- Security code: positive path (valid data accepted), negative path (tampered/invalid data rejected), and edge cases (replay, wrong key, expired session).
- If a function can fail, test that it fails correctly (returns `Err`, not panic).

## Waiting Model: Events, Timers, and Reconciliation

Choose a wait primitive from the condition being observed; do not introduce a
poll loop merely because the surrounding API is synchronous.

- **Owned live resources use events.** When mvm owns a process, child handle,
  socket, pipe, eventfd, kqueue filter, pidfd, or other stable wait handle, arm
  that observer before triggering the transition and block on the event. Keep a
  bounded deadline, a compatibility fallback for unsupported hosts, and a final
  identity/state verification before cleanup.
- **Time conditions use timers.** TTL expiry, leases, retry backoff, health
  cadence, debounce windows, and watchdog deadlines are timer-driven by
  definition. Use a monotonic clock and make cancellation explicit.
- **Crash recovery and external state use reconciliation.** State owned by a
  different process, a remote service, or a previous crashed owner may have no
  trustworthy live event. Re-read and reconcile it at a bounded cadence; make
  every pass idempotent and safe under stale or duplicated observations.
- **Durable markers are evidence, not wakeups.** A file or database record may
  remain the cross-process source of truth while an owned event accelerates the
  foreground path. Never delete or trust durable state solely because a
  best-effort notification fired.
- **Measure before converting compatibility polls.** Boot/readiness markers and
  attach/recovery paths may retain bounded polling until profiling shows a user-
  visible latency or CPU cost and an ownership-safe event exists. Record why a
  remaining poll is timer-driven, externally owned, or a recovery fallback.

An event-driven change does not imply adopting a repository-wide async runtime.
Use the smallest event primitive that matches the existing ownership boundary.

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
- **`#[allow(clippy::too_many_arguments)]` is banned outright — no exceptions, anywhere.** This one has *no* "explain and get approval" escape hatch. The instant a function trips the lint, introduce a **dedicated struct with a builder** (the Rust best practice) that carries those arguments, and pass the built value instead of the loose list. Give the struct a `::builder()` entry point (or `#[derive(Default)]` + `with_*` setters) with one setter per field and a `build()` that returns the validated value, then thread that single value through. A plain positional params struct is the bare minimum; the standing preference is the builder. The *only* legitimate suppression for this lint is on **bindgen-generated FFI** (e.g. `crates/deps/libkrun-sys/src/sys.rs`), which we never hand-edit. If you find an existing suppression in hand-written code, convert it to a builder as part of your change.
- **Fix warnings immediately** — do not accumulate clippy debt. A warning introduced now becomes harder to diagnose later.
- **Common findings to watch for**: `clippy::too_many_arguments` (build a params struct + builder — see the hard rule above), `clippy::redundant_closure`, `clippy::needless_pass_by_value`, `clippy::single_match` → `if let`, unused imports/variables.
- **After adding new code**, run clippy before moving on — don't wait until the end of a task.

## No `unwrap()` in Production Code

**NEVER** use `.unwrap()` in production code. Always use `.expect("descriptive message")` instead, so that if a panic occurs, the error message explains what went wrong and where. `.unwrap()` is only acceptable in test code (`#[cfg(test)]` modules and `tests/` directories).

## No Spec References in Code Comments

**NEVER** cite a plan, ADR, PR, sprint, or workstream in a code comment. Process artifacts (`Plan 200`, `ADR-007`, `PR #1234`, `Sprint 52`, `W2.4`) belong in specs, commit messages, and PR descriptions — not in the source. The `check-no-spec-refs-in-comments` lint (`xtask/src/check_no_spec_refs_in_comments.rs`, a CI Lint-job gate) extracts comment text and fails the build on any such reference, so a citation that builds locally will still break the GitHub action.

Keep the *reasoning* in the comment, drop the *citation*. Write the invariant or the "why" the comment is explaining, not the spec number that motivated it:

- Bad: `// Plan 200 PR2: enforce uniform host:port L4 policy here`
- Good: `// Enforce uniform host:port L4 policy — untrusted workloads never reach the network unless admitted`

Spec numbers are still fine in string literals that are genuinely runtime data (error messages, audit-log fields) — the lint only scans comment text. When you need to record *why* a decision was made for future readers, put it in the commit message or the owning spec doc and link the code from there, not the other way around.

## Reuse First; Compose Small, Testable Units

**Never reimplement functionality that already exists.** Before writing anything,
search for an existing helper, type, trait impl, or crate that already does the
job — `grep`/`rg` the workspace, check the facade re-exports, read the module the
work belongs in. Duplicated logic drifts out of sync, doubles the test surface,
and is the single most common source of bugs in this repo. If an existing helper
is *almost* right, extend or generalize it — don't fork a second copy.

- **Use the helpers.** All `~/.mvm` paths go through `mvm-core::config`
  helpers (`mvm_home`, `vm_state_dir`, `mvm_keys_dir`, `mvm_cache_dir`, …) —
  **never** build them inline with `std::env::var("HOME")` + `.join(...)`, which
  silently ignores `MVM_HOME` and breaks parallel-worktree
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

## Rust Best Practices

Use the [Rust Engineering Best Practices](https://gist.github.com/auser/c3161f55a8393faa8af5ddda68c6befa)
as the development reference for every Rust change in this repo: write new code
toward those practices and pull existing code their way as you touch it. Where a
dedicated section in this file states a stricter or repository-specific rule
(Clippy suppressions, `unwrap()`, reuse-first), this file governs; the points
below extend the external guide, never relax it.

### API & type design

- Prefer a struct with a builder over a function with many inputs — this is also
  how we kill `clippy::too_many_arguments` at the source (see "Clippy: Zero
  Warnings, Always" and "Reuse First").
- Implement a trait where there is more than one version of a behavior; don't
  scatter a `match` across call sites.
- Never add a duplicative function for a feature that already exists — find the
  helper and extend it (see "Reuse First").
- Accept borrowed types in signatures: `&str` over `String`, `&[T]` over
  `Vec<T>`, `impl AsRef<Path>` over `PathBuf`. Return owned types only when the
  caller needs ownership.
- Use the newtype pattern instead of stringly-typed or primitive-obsessed APIs
  (`UserId(u64)`, not a bare `u64`).
- Make invalid states unrepresentable: enums over boolean flags and option-soup
  structs.
- Derive `Debug`, `Clone`, `PartialEq`, `Default` where they make sense; add
  `#[must_use]` where a dropped return value is a bug.
- Keep visibility minimal — default private, `pub(crate)` before `pub`. Mark
  public enums/structs `#[non_exhaustive]` when their variants/fields may grow.
- Match exhaustively; avoid `_ =>` catch-alls on enums we own so a new variant
  breaks the build at every site that must handle it.

### Idioms & error handling

- Propagate with `Result`/`Option` and `?`. Never `unwrap()` in production;
  `.expect("message")` only where an invariant makes failure impossible (see
  "No `unwrap()` in Production Code").
- `thiserror` for library error types; `anyhow`/`eyre` only at application
  boundaries. Never `Box<dyn Error>` in a public API.
- Carry context on errors (`.with_context(...)` / `.map_err(...)`) rather than
  letting a bare I/O error bubble up.
- Prefer iterators and combinators over index loops; `if let` / `let else` over
  nested matches where it reads clearer.
- Minimize macros — reach for functions and the standard conversion traits
  (`From`, `TryFrom`, `AsRef`) first.
- Take `&self` over `&mut self`, and non-mutating APIs, where possible.
- Prefer `Cow<'_, str>` when a function sometimes borrows and sometimes
  allocates.
- Confine `unsafe` to small blocks, each with a `// SAFETY:` comment justifying
  every invariant it relies on.
- Avoid `as` for lossy numeric casts — use `TryFrom` / `try_into()` and handle
  the error. Where arithmetic can overflow, choose the behavior explicitly
  (`checked_*` / `saturating_*` / `wrapping_*`) rather than leaning on a
  debug-only panic.
- Prefer `.get()` / `.first()` / `.last()` over slice indexing in fallible
  contexts; index only where the bound is locally provable.
- Library code returns `Result` rather than panicking on bad input. Where a
  panic is a deliberate contract, document it under a `# Panics` heading.
- Avoid mutable global state; when a global is genuinely needed use
  `std::sync::OnceLock` / `LazyLock`, not `lazy_static` or `once_cell`.
- Use RAII guard types (`Drop`) for cleanup instead of teardown functions a
  caller can forget — but never rely on `Drop` for correctness across a
  `mem::forget`.
- Scope any `#[allow(...)]` to the smallest item and say why in a comment — but
  the standing rule is to fix the lint, not suppress it, and
  `#[allow(clippy::too_many_arguments)]` is banned outright (see "Clippy: Zero
  Warnings, Always").

### Dependencies & tooling

- Keep the dependency set small; audit a crate's transitive tree before adding
  it, and keep crates current so semver drift doesn't accumulate.
- Run `cargo audit` (advisories), `cargo deny` (licenses, bans, duplicate
  versions), and `cargo machete` (unused deps).
- Run clippy aggressively: `cargo clippy --workspace --all-targets
  --all-features -- -D warnings`. Prefer enabling `clippy::pedantic` /
  `clippy::nursery` through the `[lints]` table and allowing individual lints
  with justification over disabling whole groups.
- Enforce `cargo fmt --check` in CI; never hand-format.
- Declare and test against an explicit MSRV (`rust-version` in `Cargo.toml`).
- Gate optional functionality behind cargo features and keep default features
  minimal — e.g. `mvm-core` carries no async runtime by default; `tokio` is
  opt-in behind a feature.

### Async (Tokio)

- No blocking calls in an async context: `tokio::fs` over `std::fs`; offload
  CPU-bound work with `spawn_blocking` or a dedicated pool (`rayon`).
- Bound concurrency explicitly with `tokio::sync::Semaphore` / `JoinSet` instead
  of spawning unbounded tasks.
- Race futures with `tokio::select!` and keep every branch cancellation-safe;
  document cancellation safety on public async functions.
- Never hold a `std::sync::Mutex` guard — or any lock — across an `.await`. Use
  `tokio::sync::Mutex` only when unavoidable, and prefer channels over shared
  mutable state.
- Don't mark a function `async` if it never awaits; keep async functions small
  to avoid state-machine bloat.
- Pin futures correctly — `Box::pin` over `Box::new`, and `std::pin::pin!` /
  `pin_mut!` for stack pinning when reusing a future across loop iterations.
- Propagate cancellation and shutdown gracefully (`CancellationToken`); don't
  orphan or leak tasks on drop.

### Serialization, data & security

- Treat a serialized format as public API: pin field names with
  `#[serde(rename_all = ...)]`, put `#[serde(deny_unknown_fields)]` on inbound
  types where forward-compat isn't required (already the standing rule for every
  host↔guest type), and version wire formats deliberately.
- Validate at the boundary, then trust the type — deserialize into strict domain
  types (newtypes, enums), not loosely-typed maps threaded through the codebase.
- Never derive a plain `Debug` on a type holding secrets; redact the fields or
  wrap it. Zeroize key material on drop (`zeroize`) and compare secrets in
  constant time (`subtle`). See "Privacy & Security".
- Never log secrets, tokens, or PII; audit `tracing` fields at the boundary
  where they enter.
- Handle time explicitly: store and compute in UTC, convert to local only at
  presentation, and use a monotonic clock (`Instant`) for durations — never
  wall-clock time.

### Performance

- Readability first; measure before optimizing.
- Avoid needless `.clone()` / `.to_owned()`, and if a clone is required say why
  in a comment. Watch for accidental `String` allocation in hot paths.
- Pre-allocate with `Vec::with_capacity` / `String::with_capacity` when the size
  is known up front.
- Don't reach for `Arc<Mutex<T>>` by default — only after a simpler ownership
  structure has genuinely failed.
- Benchmark performance-sensitive code with `criterion` and keep the benchmarks
  in the repo.

### Testing & documentation

- Give every public item a `///` doc comment, with a runnable example where
  practical — it doubles as a doctest (`cargo test --workspace --doc`).
- Unit tests alongside the code (`#[cfg(test)]`), integration tests in `tests/`,
  and property tests (`proptest`) for parsing/serialization. Test the error
  paths, not just the happy path; `unwrap()` is fine inside tests. (See
  "Definition of Done" and "Test Expectations".)
- Use `tracing` with structured fields, not `println!`/`log`; instrument async
  functions with `#[tracing::instrument]` where spans aid debugging.
- Keep `cargo doc --no-deps` warning-free (`#![warn(missing_docs)]` on
  libraries).
- Run Miri (`cargo +nightly miri test`) over any code that contains `unsafe`.
- Fuzz anything that parses untrusted input (`cargo-fuzz`) and keep the corpus
  in the repo.
- Make tests deterministic: no sleeps for synchronization (use channels/notify),
  and inject clocks and randomness so a test can control them.

### Release & supply chain

- Commit `Cargo.lock` for binaries and applications so builds reproduce.
- Run `cargo-semver-checks` before publishing any library release to catch an
  accidental breaking change.
- Tune the release profile deliberately: `lto = "thin"` (or `"fat"` for a final
  binary), `codegen-units = 1`, `strip = true`; consider `panic = "abort"` for a
  binary that doesn't need unwinding.
- Keep CI green across the matrix that matters — stable + MSRV, and the feature
  combinations that matter (`cargo hack --feature-powerset` for a many-feature
  library).

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

**NEVER** write scratch, temporary, or intermediate files anywhere inside the repository working tree — not the project root, not a subdirectory, not a hidden dotfile (`.foo.txt`), not even a gitignored path. This applies to **every** kind of agent-created scratch, not just screenshots/binaries: analysis lists, command output, intermediate JSON/TSV, logs, ad-hoc scripts, `git merge-file` inputs, etc.

Always write such files under `/tmp/` instead (e.g. `/tmp/screenshot.png`, `/tmp/worktree-audit.txt`). This keeps the working directory clean and keeps junk out of git. If you need three-way-merge scratch or similar, use `/tmp/`, never the repo.

When using Playwright or other browser tools, explicitly set the output path to `/tmp/`:

- Screenshots: `filename: "/tmp/screenshot.png"`
- Snapshots: `filename: "/tmp/snapshot.md"`

If you accidentally save files to the repo, delete them immediately before committing.

<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->
