# Agent Working Agreement

Backing: shipped-source
Validation: check-sprint-append

This file is the short, always-applicable rule index loaded into every session.
The fuller AI-assisted issue-to-PR playbook lives in
`public/src/content/docs/contributing/ai-coding-workflow.md`; human environment
setup in `public/src/content/docs/contributing/development.md`. If you change
anything this file describes, update this file in the same change.

## Execution boundaries

**Builder VM requirement.** All Nix builds/evals, Firecracker operations,
`mvmctl` runtime commands (anything that boots, talks to, or manages microVMs),
and Linux-specific syscalls MUST run inside the project builder VM — never a
Lima VM; do not use `limactl` for this repo. The builder VM is the Linux
execution boundary. Owner-approved exceptions:

- **Lima as a test-environment KVM provider only** — a virtual `/dev/kvm` for
  Firecracker / Linux-KVM E2E tests that cannot run on the builder VM or
  GitHub-hosted runners. Modeled as a test/dev-tier `VmBackend`, refused by
  prod admission (like the Docker fallback tier). Never for builds/evals.
- **Native macOS HVF live lifecycle tests and teardown benchmarks** — explicit
  HVF test/benchmark commands, because the Linux builder VM cannot provide
  Hypervisor.framework. All other runtime commands still require the builder VM.
- **`mvmctl machine run --hypervisor wasm` (or any explicit `wasm` backend
  target)** — runs a `wasm32-wasip1` module under host `wasmtime`; no KVM, no
  Firecracker/jailer/seccomp/netns tooling. May run on the macOS host.

**Cargo defaults to the macOS host.** `cargo test` / `check` / `build` run on
the host so worktrees do not deadlock on shared builder state. Tests needing
Linux (vsock, jailer/seccomp, dm-verity, network namespaces, `/dev/kvm`,
`/proc/net`) are gated `#[cfg(target_os = "linux")]` and only those sub-targets
run inside the builder VM. `mvmctl` via `cargo run` (`build`, `up`, `down`,
`logs`, `ls`) runs inside the builder VM (explicit `wasm` target excepted).

## Git: one operator, one main

**Git runs only from the main `mvm/` checkout** — never from inside a worktree
directory, never from inside the builder VM. Act on a worktree's branch with
`git -C /path/to/.worktrees/mvm-<slug> <cmd>` from the main checkout. This
serializes the shared `.git/objects`, packed refs, and hooks and eliminates the
contention that has caused lost work. Cargo/nix/firecracker/mvmctl run from each
worktree's own directory; only `git` is centralized.

**The main checkout stays on synchronized `main`.** Verify at the start and end
of every task: clean, on `main`, synced with `origin/main`
(`git fetch origin && git pull --ff-only origin main`). Never do change work on
a topic branch there; if one lands there accidentally, preserve changes, switch
back, sync, and attach the branch to a worktree. After any PR merge, sync main
immediately. The only git commands targeting `main` are read-only (`git log`,
`git show`) or routine sync.

**Never commit directly to `main`.** Main advances only via merged PRs —
including docs-only and typo fixes. Reasons: parallel agents sharing `.git` can
wipe local-only commits with routine recovery moves; the full
clippy/nextest/supply-chain matrix only runs on PRs; PR history is the audit
trail. Push to a branch and open a PR.

**No assistant or tool attribution in pull requests.** Never name an AI
assistant, coding agent, model, or tool (Claude Code, Codex, Kimi, Qwen Code,
etc.) in PR titles, bodies, contributor lists, acknowledgements, commit
trailers, or generated-by notices; no assistant `Co-authored-by` trailers.

## Worktree workflow for all changes

Every change — code, docs, dependency bumps, refactors, bug fixes — is
developed in a git worktree. No docs-only or trivial-change exception.

```bash
cd /Users/auser/work/tinylabs/mvmco/mvm   # main checkout
git worktree add ../.worktrees/mvm-<slug> -b feat/<slug>
cd ../.worktrees/mvm-<slug>               # code + cargo live here
```

Branch names: `feat/<slug>`, `fix/<slug>`, `chore/<slug>` (docs topics:
`docs/<slug>`). All git work happens from the main checkout:
`git -C ../.worktrees/mvm-<slug> status|add|commit|push`. Agents inside a
worktree do not invoke `git` directly; a read-only `git -C <main> status` is
acceptable. Remove the worktree after merge (`git worktree remove ...`).

**Isolate mutable state** per worktree by overriding three env vars (or just
`source scripts/dev-env.sh`, resolved relative to the worktree root; `bin/dev`
wraps `cargo run` with the same env; `.envrc.example` covers direnv users):

```bash
MVM_HOME="$PWD/.mvm-test"                 # mvmctl state tree: templates, sockets,
                                          # registry, snapshots, keys
CARGO_TARGET_DIR="$PWD/.mvm-test/target"  # own target dir (no rustc lock contention)
CARGO_HOME="$PWD/.mvm-test/cargo"         # own registry + .package-cache lock
```

**Still shared between worktrees** — vary microVM and TAP names if two worktrees
run microVMs concurrently: `.git/objects` + packed refs + hooks (the git rule
above is what keeps these safe), the builder VM's `/var/lib/mvm/`, `br-mvm`
bridge, and TAP devices; the Nix store (shared by design; Nix locking handles
it). The builder VM itself is shared across worktrees — **never fork a
per-worktree VM** (boot cost, duplicated tens-of-GB store, warm-cache loss).

One-time per clone: `just install-hooks` points `core.hooksPath` at
`.githooks/`. The pre-commit hook runs `cargo fmt --all` (auto-restaging),
scoped stable clippy `-D warnings`, `nix fmt` for staged `.nix` files, and
`actionlint` for workflow changes — never the full test suite; heavy gates run
in CI (`MVM_SKIP_CLIPPY=1` bypasses the clippy pass).

## Definition of Done

No task is complete without all of:

1. **Tests first** — new/changed behavior covered before the task is marked
   done: unit tests for logic, integration tests for CLI/cross-crate behavior.
2. **All tests green** — `cargo test --workspace`, zero failures.
3. **Zero clippy warnings** — `cargo clippy --workspace -- -D warnings`.
4. **Compiling workspace** — `cargo check --workspace` clean. `--all-targets` is
   not exhaustive: it skips `required-features` targets and cannot compile
   `cfg(target_os = "linux")` files on macOS — including Linux-gated _test_
   files — so any change to a shared type's shape (field, trait method, enum
   variant) needs `just check-gated` before pushing.
5. **Sprint spec** — `specs/SPRINT.md` reflects the new state (checked boxes,
   status labels, test counts).
6. **Plan checkboxes** — tick each finished task in the active plan under
   `specs/plans/` (slug-named, e.g. `2026-08-15-<slug>.md`). The plan's boxes
   are the source of truth for progress; never tick before tests are green.
7. **Refactor rollup** — tick/strike the matching entry in
   `specs/REFACTOR-STATUS.md` in the same change and bump its "Last updated".
   Items 5–7 move together; if the rollup disagrees with a plan doc, the plan
   wins — fix the rollup.

## Test expectations

- Broad BDD coverage of user-visible workflows (`mvm-conformance`, `--features
  bdd`); add/update scenarios when behavior changes, and keep focused unit and
  integration tests for lower-level logic and failure paths.
- New types: serde roundtrip tests, default-value tests where applicable.
- New protocol/wire code: roundtrip through mock I/O (`UnixStream::pair()`),
  error-path tests (invalid input, wrong keys, malformed data).
- New CLI flags/commands: integration tests in `tests/cli.rs` (help text,
  argument parsing).
- Security code: positive path, negative path (tampered/invalid rejected), and
  edge cases (replay, wrong key, expired session).
- If a function can fail, test that it fails correctly (`Err`, not panic).

## Waiting model

Pick the wait primitive from the condition being observed:

- **Owned live resources → events.** Processes, child handles, sockets, pipes,
  eventfd, kqueue filters, pidfd: arm the observer before triggering the
  transition, block on the event; keep a bounded deadline, a compatibility
  fallback, and a final identity/state verification before cleanup.
- **Time conditions → timers.** TTLs, leases, backoff, health cadence,
  watchdogs: monotonic clock, explicit cancellation.
- **Crash recovery / external state → reconciliation.** State owned by another
  process, service, or a crashed predecessor has no trustworthy live event:
  re-read at a bounded cadence; every pass idempotent under stale/duplicated
  observations.
- **Durable markers are evidence, not wakeups.** A file/record may be the
  cross-process source of truth while an owned event accelerates the foreground
  path; never delete or trust durable state solely because a best-effort
  notification fired.
- **Measure before converting compatibility polls.** Boot/readiness markers and
  attach/recovery paths may keep bounded polling until profiling shows a
  user-visible cost and an ownership-safe event exists; record why a remaining
  poll is timer-driven, externally owned, or a recovery fallback.

An event-driven change does not imply a repo-wide async runtime — use the
smallest event primitive matching the existing ownership boundary.

## Privacy & security

Every change is evaluated through a security lens:

- Never log, store, or expose secrets/tokens/keys/credentials/user data in
  plaintext — in code, logs, config, or error messages.
- Validate and sanitize all inputs at system boundaries (CLI args, config
  files, network data, vsock messages).
- Least privilege everywhere; default to secure configurations (encryption on,
  auth required, restrictive permissions) — users opt out, never opt in.
- Guard secrets in transit and at rest; signing, encryption, and secure
  channels (vsock, not plaintext TCP) for sensitive communication.
- No hardcoded secrets — environment, secure config, or runtime injection only.
- Consider attack surface in every feature: listeners, file permissions, IPC
  channels, CLI commands.
- Security tests are mandatory for every security-relevant path (positive,
  negative, edge).

## Clippy: zero warnings, always

Run `cargo clippy --workspace -- -D warnings` after every code change; the CI
pre-commit hook treats warnings as errors.

- **Never suppress with `#[allow(...)]`** — fix the underlying issue; a
  genuinely necessary suppression needs a comment and explicit approval.
- **`#[allow(clippy::too_many_arguments)]` is banned outright, everywhere.**
  The instant a function trips it, introduce a dedicated params struct with a
  builder (`::builder()` or `#[derive(Default)]` + `with_*` setters + validated
  `build()`) and thread that value through. The only legitimate suppression is
  bindgen-generated FFI (`crates/deps/libkrun-sys/src/sys.rs`); convert any
  existing hand-written suppression to a builder as you touch it.
- Fix warnings immediately; common findings: `too_many_arguments` (→ builder),
  `redundant_closure`, `needless_pass_by_value`, `single_match` → `if let`,
  unused imports/variables.

## No `unwrap()` in production code

Never `.unwrap()` in production code — use `.expect("descriptive message")` so a
panic explains what failed and where. `unwrap()` is acceptable only in test code
(`#[cfg(test)]` modules and `tests/`).

## No spec references in code comments

Never cite a plan, ADR, PR, sprint, or workstream in a code comment — process
artifacts belong in specs, commit messages, and PR descriptions. The
`check-no-spec-refs-in-comments` lint (a CI gate) fails the build on any such
reference. Keep the _reasoning_, drop the _citation_. Spec numbers remain fine
in string literals that are genuinely runtime data (error messages, audit-log
fields); the lint scans comment text only. Record why-a-decision-was-made in the
commit message or the owning spec, and link the code from there.

## Reuse first; compose small, testable units

Never reimplement existing functionality. Before writing anything, search for
an existing helper, type, trait impl, or crate that does the job — grep the
workspace, check facade re-exports, read the module the work belongs in. If a
helper is almost right, extend it; don't fork a second copy. Duplicated logic
drifts, doubles the test surface, and is the most common source of bugs here.

- **Use the helpers.** All `~/.mvm` paths go through `mvm-core::config`
  helpers (`mvm_home`, `vm_state_dir`, `mvm_keys_dir`, `mvm_cache_dir`, …) —
  never build them from `std::env::var("HOME")` + `.join(...)`, which ignores
  `MVM_HOME` and breaks worktree isolation. Shell/VM ops go through the
  `ShellEnvironment`/`BuildEnvironment` traits.
- **Small, single-purpose functions** you can write a focused test for; if you
  can't test it, split it. A helper extracted to be testable ships with tests
  in the same change — positive, negative, and edge paths.
- **Make illegal states unrepresentable** — newtypes over bare `String`/`u64`,
  enums over stringly-typed flags, `Option`/`Result` over sentinels.
- **Don't over-abstract (YAGNI).** Traits/builders/generics for a real second
  case or genuine construction complexity, not speculatively.
- **Builder pattern** for multi-field construction (also kills
  `too_many_arguments` at the source).
- **Traits for behavior that varies** (`VmBackend`, `ShellEnvironment`) — never
  a `match` scattered across call sites. One impl is one path, not the only
  path.
- **Structs over loose tuples/params**; **match exhaustively** on owned enums —
  no `_ =>` catch-alls, so new variants break the build where they must be
  handled.
- Follow the existing pattern — match surrounding naming, idiom, and layout.

## Rust best practices

[External best-practices guide](https://gist.github.com/auser/c3161f55a8393faa8af5ddda68c6befa);
where this file states a stricter rule (clippy, `unwrap()`, reuse-first), this
file governs.

- **API & types**: builder over many-input functions; trait for multiple
  behaviors; borrowed args (`&str`, `&[T]`, `impl AsRef<Path>`), return owned
  only when needed; newtypes; `#[must_use]` where dropping is a bug; minimal
  visibility (`pub(crate)` before `pub`); `#[non_exhaustive]` on growing
  public shapes; derive `Debug`, `Clone`, `PartialEq`, `Default` where sensible.
- **Idioms & errors**: propagate with `?`; `thiserror` in libraries,
  `anyhow`/`eyre` only at app boundaries; context on errors
  (`.with_context`/`.map_err`); iterators over index loops; `if let`/`let else`;
  minimize macros — prefer functions and `From`/`TryFrom`/`AsRef`; `&self` over
  `&mut self`; `Cow<'_, str>` for maybe-borrowed strings; `unsafe` confined to
  small blocks each with a `// SAFETY:` comment; `TryFrom`/`try_into()` over
  lossy `as`; explicit `checked_*`/`saturating_*` where arithmetic can
  overflow; `.get()`/`.first()` over slice indexing in fallible contexts;
  libraries return `Result` rather than panicking (document deliberate panics
  under `# Panics`); `OnceLock`/`LazyLock` for real globals; RAII `Drop` guards
  for cleanup (never rely on `Drop` across `mem::forget`).
- **Dependencies & tooling**: small audited dependency set (`cargo audit`,
  `cargo deny`, `cargo machete`); aggressive clippy
  (`--all-targets --all-features`; pedantic/nursery via `[lints]` with
  per-lint justification over group disables); `cargo fmt --check` in CI;
  explicit MSRV; minimal default features behind cargo features (`mvm-core`
  carries no async runtime by default).
- **Async (Tokio)**: no blocking calls in async context (`tokio::fs`, offload
  CPU work with `spawn_blocking`/`rayon`); bound concurrency with `Semaphore` /
  `JoinSet`; no repo-wide runtime for event-driven changes (see Waiting model).
