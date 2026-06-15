# Plan 185 — deferred-work handoff (next session)

Plan 185 (idiomatic Rust hygiene audit, `specs/plans/185-idiomatic-rust-hygiene.md`)
has Phases 1–3 done, Phase 5 Task 8 first-pass + Task 9 done. This note is the
start-of-session prompt for the remaining work. The plan doc is the source of
truth; this is the orientation + a copy-paste prompt.

## Done so far (on `main`)

- **Phase 1** TestEnv migration (mvm-core/mvm-hostd/mvm-build/libkrun-sys/mvm-cli;
  host-gated mvm-backend env tests deferred to CI/Linux).
- **Phase 2** poison-lock policy decided + applied (env serializers folded into
  `TestEnv`; runtime state locks fail-closed).
- **Phase 3** naming/typed-selectors: `DeviceMapperBackend` (#892),
  `VmEgressProxy`/`SupervisorEgressProxy` (#894), typed `BackendKind` selectors (#895).
- **Phase 5 Task 8** first pass: `SAFETY:` invariants on the 12 simple-syscall
  mvm-guest blocks (#899). **Task 9** closed by verification (#901).

## Remaining (this is the work)

1. **Phase 5 Task 8 — deeper `unsafe` clusters** (one reviewed file per PR; write
   only invariants you can actually verify — a wrong soundness claim is worse than
   none):
   - `crates/mvm-guest/src/console.rs` (~16, PTY/termios). ⚠️ The post-fork child
     block calls `putenv` (can `malloc`) after `fork()` — its soundness depends on
     the guest being single-threaded at console-fork time. **Verify that threading
     assumption first**; if it doesn't hold, the right fix is to drop the malloc
     path (pre-built `environ`) rather than write a false SAFETY note.
   - `crates/mvm-guest/src/bin/mvm-verity-init.rs` (~13, dm-verity ioctls).
   - `crates/mvm-guest/src/bin/mvm-guest-agent.rs` (~5).
   - `crates/mvm-vm-host/src/vz_objc.rs` (~100, objc2 `msg_send` FFI) — biggest, and
     hot Plan-152 territory; do it while the vz work is quiet, and lean on Task 8
     Step 2 (isolate FFI behind small safe wrappers) rather than annotating 100 raw
     blocks in place.
   - Detection helper (missing `SAFETY:` within 3 lines above an `unsafe`):
     `awk '/unsafe[ ]*\{|unsafe fn/{x=0;for(i=1;i<=4;i++)if(prev[i]~/SAFETY:/)x=1;if(!x)print NR": "$0}{prev[4]=prev[3];prev[3]=prev[2];prev[2]=prev[1];prev[1]=$0}' <file>`

2. **Phase 4 — function shape** (Task 6 params-structs/builders, Task 7 splits). Be
   conservative per the plan's own guardrails: only where it buys tests or clarity,
   never churn-for-style. The obvious long-arg fns (`run_attached_with_mounts` etc.)
   are *already* struct-grouped behind `BuilderVmRunConfig`; real candidates need
   per-function judgment. Egregious >7-arg cases are already clippy-gated.

3. **Phase 6 — error shapes / fixtures / docs** (Tasks 10–13): thiserror-vs-anyhow
   boundaries, stop matching error *strings* in tests where typed errors exist,
   consolidate duplicated fixtures, rustdoc pass.

4. **Phase 7 — closeout** (Task 14): workspace-wide `cargo test`/`check`/`clippy`
   green in the required env, reconcile plan + rollup + SPRINT, close the plan.
   ⚠️ mvm-backend tests SIGKILL under macOS amfid — the workspace test gate must run
   on CI/Linux; document that as the host-specific blocker per the plan guardrail.

## Working conventions (this repo / this host)

- **Worktree, not the main checkout.** `git worktree add -b <branch> ../<dir> origin/main`.
  Parallel sessions race the index. After any `cd`, re-verify `pwd`+branch before commits.
- **Toolchain: Homebrew `rustc` (1.95) shadows rustup (1.96) on this Mac.** Pin it:
  `export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$HOME/.cargo/bin:$PATH"`,
  use an isolated `CARGO_TARGET_DIR=/tmp/<x>-target` and `MVM_SKIP_EMBED_BINARIES=1`.
  For Linux-gated guest code, verify with `cargo clippy -p <crate> --target aarch64-unknown-linux-musl`.
- **mvm-backend tests SIGKILL on macOS (amfid signal 9)** — clippy/compile only locally; defer test runs to CI.
- **Gates** (match CI, not just `clippy -p`): `cargo fmt --all -- --check`,
  `cargo clippy --all-targets -- -D warnings`, `xtask check-no-spec-refs-in-comments`
  (NO plan/PR/ADR citations in *code* comments), `xtask check-spec-numbers`,
  `check-core-runtime-free`. CI Lint uses **nightly** rustfmt (`rustup run nightly cargo fmt --all`).
- **`specs/REFACTOR-STATUS.md`: never edit the header "Last updated" line** — it's the
  rebase conflict hotspot. Detail/glance lines are safe. Keep plan checkboxes +
  REFACTOR-STATUS + SPRINT in sync in the SAME PR.
- **PR cadence:** branch off origin/main → fmt/clippy/lint → `gh pr create` →
  `gh pr merge <n> --auto` (squash; repo uses a merge queue). Auto-merge clears when
  main advances → re-enqueue with `gh pr merge <n> --auto`. Rebase only on real
  conflict (usually the plan-doc Task block when a sibling PR touched it).
- **Style:** write like an expert human (terse, why-comments only). No `Co-Authored-By: Claude` trailer.

## Copy-paste prompt

> Continue Plan 185 (`specs/plans/185-idiomatic-rust-hygiene.md`). Phases 1–3,
> Phase 5 Task 8 first-pass, and Task 9 are done on main. Pick up the deferred work
> in `specs/notes/plan-185-deferred-handoff.md`, starting with **Phase 5 Task 8's
> deeper unsafe clusters** — do `crates/mvm-guest/src/bin/mvm-verity-init.rs` first
> (smaller, self-contained), then `console.rs` (verify the post-fork threading
> assumption before annotating the putenv block). One file per PR; write only
> SAFETY invariants you can actually verify; isolate FFI behind small safe wrappers
> where Step 2 applies. Follow the working conventions in the handoff note (worktree
> off origin/main, pin rustup toolchain + isolated target dir, keep edits off the
> REFACTOR-STATUS header, keep plan/rollup/SPRINT in sync per PR, arm auto-merge +
> re-enqueue when it clears). Keep `specs/REFACTOR-STATUS.md` and `specs/SPRINT.md`
> current as each slice lands.
