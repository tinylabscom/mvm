# Plan 231 — Radical simplification: two surfaces, minimal API, human-readable

**Status: PROPOSED — ON HOLD. DO NOT START until the owner explicitly says to move forward.**
**Created: 2026-07-07**
**Companion:** `specs/SPRINT.md` Sprint 64 (the working checklist) · Phase 0 is
[Plan 230](230-two-surface-consolidation.md) (two product surfaces + lint).

## The initial prompt (verbatim — the reason this plan exists)

> I need you to simplify the heck out of this already overly complex project.
> Look at all the different crates and look at what we can cut. In addition, I
> want all publicly exposed structs and functions to be as simple as possible.
>
> We've grown out of control because of primarily AI development paths. Since AI
> is pretty bad at development, it built things we don't need, left cruft all
> around the project, and didn't look at the things already implemented
> (duplicative features and functions). This is a problem.
>
> If we leave this project as ugly and complex as it is, I'll get fired. I need
> you to help me simplify this project so it looks like an expert human developer
> can understand it, so that everything is tested, and it uses best-practice rust
> development.
>
> With that being said, we _cannot_ sacrifice any security concerns, keeping
> auditability in-place. Make sure we have the best UX/DX available and can be
> used as a library.
>
> In addition, can you look at the cli surface and simplify that as much as
> possible.
>
> Please document this work in @specs/SPRINT.md -- and another thing here is we
> want to be able to run a network of mvm using `mvmd` -- we're trying to
> simplify this project and make sure that we can keep it realistic, as small as
> we can, and as human-readable and editable as possible.

## One-line goal

Shrink the project to the smallest, most human-readable form a single expert
developer can hold in their head — and the smallest **dependency / attack
surface** — preserving **every** security claim and enabling a **network of mvm
hosts driven by `mvmd`**. Fewer dependencies is not tidiness; each one is
supply-chain risk (P7).

## Non-negotiable invariants (a change that touches any of these is rejected)

- All 15 security claims in `specs/claims/catalog.md` stay green;
  `xtask check-claim-catalog` and every witness keep passing.
- The **process moat** stays intact — separate signer / broker / substitution /
  audit-signer processes are load-bearing for claims 12/13. "Simpler" never
  means "one process."
- **vsock-only auditable data plane** — no guest networking is introduced; the
  substitution / PII-mask / audit seam stays on vsock.
- dm-verity sealed prod (claim 3); no-console / no-`do_exec` prod gates
  (claims 4/15) unchanged.
- Exactly two **product** surfaces (`host` / `user`); internal library knobs live
  on the `check-two-surfaces` `INTERNAL` allowlist, never as a third surface.

## Methodology — how we avoid re-making the mess

- **Incremental, CI-green at every step.** No big-bang. Each phase independently
  shippable and reversible.
- **Evidence-driven cuts.** A deletion needs proof it is unreachable or
  duplicative: `cargo machete`, `cargo udeps`, `#![warn(unreachable_pub)]`, rustc
  `dead_code`, `cargo public-api` snapshots. No "looks unused" guesses.
- **Reuse-first.** Before simplifying a function, find the existing helper and
  merge into it — duplicated logic is this repo's most common bug source.
- **Tests are the safety net.** No coverage regressions; every simplified public
  item keeps or gains a focused test. If it can't be unit-tested, it's too big —
  split it.
- **Ratchets, not vibes.** Keep `check-closure-budget`; ADD a crate-count budget,
  per-crate `cargo public-api` snapshot gates, and `cargo machete` to CI so the
  reductions can't silently reverse.

## Sequencing — when this runs (the gates)

This plan does **not** start on merge. Two gates first:

1. **Gate 1 — Phase 0 lands.** [Plan 230](230-two-surface-consolidation.md)
   (#1520) merges: two-surface features + `check-two-surfaces` lint. This is the
   decision rule and anti-regrowth ratchet the rest hangs off; nothing starts
   before it lands.
2. **Gate 2 — 0.17.0 ships.** The narrow HVF-default release (Plan 228) goes out
   first. A workspace-wide sweep is exactly the cross-cutting churn that makes a
   narrow release risky, and it would collide with the many in-flight
   worktrees/PRs. Do it when the tree is quiet.

Then: a **~20-minute scoping call** to settle the four decisions below, then run
the phases — **P1 first** (cheap, subtractive, produces the numbers that
validate or right-size the whole effort before the riskier phases).

## Phases (each independently shippable)

- [~] **P0 — Two-surface spine (in flight, Plan 230).** `host`/`user`/`dev`
  umbrellas + `check-two-surfaces`. Feature set 14 → 9 (2 product + 7 internal).
- [ ] **P1 — Dead-code & dependency sweep.** machete/udeps/`unreachable_pub`
  across all crates; delete unreachable code + unused deps; quantify LOC/dep
  reduction; wire `cargo machete` into CI. *Start here.*
- [ ] **P2 — Public-API minimization.** Per-crate `cargo public-api` snapshot;
  `pub` → `pub(crate)` where nothing external consumes it; collapse re-exports so
  the root `src/lib.rs` facade is the one library surface; gate diffs on the
  snapshot.
- [ ] **P3 — Crate audit & consolidation.** Evidence-based merge/removal
  assessment (the 32 → 15 fold already happened, so careful not aggressive);
  target crate map; low-risk merges only. **Non-goal:** merging the process-moat
  bin crates.
- [ ] **P4 — CLI surface simplification.** Inventory every verb + flag; delete
  dead verbs, collapse aliases, route user verbs through `MvmClient`
  (Plan 230 WS-4); snapshot `--help` in `tests/cli.rs`. Target: a small,
  orthogonal verb set learnable in one sitting.
- [ ] **P5 — `mvmd` fleet enablement (network of mvm).** The `MvmClient` facade
  (`LocalBackend` + remote `GatewayBackend`) cleanly drives a network of mvm
  hosts from `mvmd`: `mvmd` links the `user` surface (remote) to orchestrate, the
  `host` surface where it runs hosts. Cross-repo build contract already proven
  (mvmd links `mvmctl` with the internal `hostd-transport` knob, `cargo check`
  green). Smoke test: `mvmd` orchestrates ≥2 mvm hosts through the facade.
- [ ] **P6 — Docs + DX.** README / CLAUDE.md / rustdoc describe exactly two
  surfaces + the library API; every public item carries a doc example (green
  under `just test-doc`); `just` recipes for the common flows.
- [ ] **P7 — Dependency surface reduction (security-driven).** The workspace
  carries ~734 crates — every one is attack surface and a potential supply-chain
  CVE, which is a direct, stated security concern (not just tidiness). Beyond
  P1's *unused*-dep removal, audit the *used* deps: for each direct dependency,
  measure how much of it we actually consume. Categorize:
  **(a) unused** → remove (P1); **(b) barely-used** (a single function or a
  handful) → reimplement in-house behind a small, focused, tested module **or**
  swap for a lighter-weight / `std` alternative; **(c) heavy-but-justified** →
  keep, with a one-line rationale recorded. Prioritize by risk: unmaintained
  crates, large transitive footprints, duplicate crates at multiple versions, and
  categories that pull broad native/parsing surface. Every removal/replacement is
  evidence-driven (`cargo tree -i`, actual call-site count) and tested, and must
  **not** weaken any security claim — claim 7's `cargo-audit` + `deny.toml`
  posture is the backstop, and a reimplementation is only worth it when it is
  *simpler and auditable*, never a subtle re-bug. Ratchet: a **dependency-count
  budget** in CI so the total can't silently grow, plus `cargo deny` on every PR.
  - [x] **Slice 1 (2026-07-08):** removed `inquire` workspace-wide. Evidence:
    only three prompt call-sites remained (`mvm::ui::confirm`, the destructive
    `DELETE-EVERYTHING` prompt, and secret entry). Replaced them with tiny
    in-house prompt helpers over `std::io` + `libc` termios echo suppression
    for hidden secret input, preserving the no-echo secret posture. Result:
    `inquire` and its transitive terminal stack (`crossterm`,
    `crossterm_winapi`, `signal-hook`, `signal-hook-mio`, `fuzzy-matcher`,
    `derive_more`, `document-features`, `convert_case`, `litrs`,
    `unicode-segmentation`) drop out of `Cargo.lock`. Verified with
    `cargo fmt --check`, `cargo check -p mvm-cli -p mvm-backend`, targeted
    `mvm-backend` UI tests, `cargo test -p mvm-cli --lib`, and
    `cargo clippy -p mvm-cli -p mvm-backend --lib --tests -- -D warnings`.
  - [ ] **Slice 2 (2026-07-08):** removed `colored` and stale direct manifest
    edges from `mvm`. Evidence: `colored` had one real consumer
    (`mvm-backend::base::ui`) and `mvm` still declared `colored` /
    `indicatif` directly even though `mvm::ui` is only a re-export of
    `mvm-backend::base::ui`. Replaced the `colored` calls with a tiny
    terminal-aware ANSI helper inside `mvm-backend::base::ui`, keeping
    color off for non-TTY output and preserving the existing spinner path
    (`indicatif`). Result: `colored` drops out of `Cargo.lock`, the direct
    `mvm` manifest no longer carries dead `colored` / `indicatif` edges,
    and `mvm-hostd`'s `web_search` path no longer relies on reqwest's
    optional `.query()` method (it now builds query URLs explicitly, which
    keeps the lean reqwest feature set intact). Verified with
    `cargo fmt --check`, `cargo check -p mvm-cli -p mvm-backend -p mvm-hostd`,
    targeted `mvm-backend` UI tests, targeted `mvm-hostd` web-search tests,
    and `cargo clippy -p mvm-cli -p mvm-backend -p mvm-hostd --lib --tests -- -D warnings`.
    Final closeout is pending a less-restricted host run of
    `cargo test -p mvm-cli --lib`; in this sandbox the remaining failures are
    permission-denied test fixtures that bind local sockets / write under
    `/var/tmp`, not compile or logic regressions from this slice.
  - [x] **Slice 3 (2026-07-08):** unified `which` to the workspace's single
    `which 7` version. Evidence: `cargo tree -p mvmctl -i which@6.0.3` showed
    `mvm-build` as the lone remaining `which 6` root, and its call-sites only
    use the stable `which::which(...)` API already used elsewhere in the
    workspace. Swapped `crates/mvm-build/Cargo.toml` from `which = "6"` to
    `which.workspace = true`, which drops `which 6` from `Cargo.lock` and
    reduces the `mvmctl` normal-dependency closure count from 859 to 853.
    Verified with `cargo fmt --check`, `cargo check -p mvm-build -p mvm-cli -p mvm-backend`,
    `cargo clippy -p mvm-build -p mvm-cli -p mvm-backend --lib --tests -- -D warnings`,
    and closure remeasurement via `cargo tree`.
  - [x] **Slice 4 (2026-07-08):** removed `indicatif` from the shared CLI/UI
    path. Evidence: `cargo tree -p mvmctl -i indicatif` showed a single UI-only
    root through `mvm-backend::base::ui` and the thin CLI wrapper; call-sites
    only use a cloneable spinner with `set_message` and `finish_and_clear`.
    Replaced it with a tiny in-house spinner handle in
    `mvm-backend::base::ui`, updated the CLI wrapper to re-export that handle,
    and swapped the dev-builder heartbeat type plumbing accordingly. Result:
    `indicatif` drops out of `Cargo.lock`, along with its exclusive closure
    pieces such as `console` and `unit-prefix`, and the `mvmctl`
    normal-dependency closure count falls from 853 to 845. Verified with
    `cargo fmt --check`, `cargo check -p mvm-cli -p mvm-backend`,
    targeted `mvm-backend` UI tests, `cargo clippy -p mvm-cli -p mvm-backend --lib --tests -- -D warnings`,
    and closure remeasurement via `cargo tree`.

Likely order: **P1 → P7 → P2 → P4 → P3 → P5 → P6** — P1 and P7 are the
dependency/attack-surface pair and run first (P1 removes what's unused, P7
shrinks what's barely-used); the larger structural surgery follows the scoping
call.

## Scoping decisions to confirm before P3/P4 (front-loaded)

Judgment calls that need an owner decision before cutting — recorded so execution
doesn't guess:

1. **Crate-merge aggressiveness** — target crate count; which of the 15 are in
   scope vs frozen (e.g. `mvm-verify` is deliberately standalone / wasm-clean).
2. **Public-API hiding vs consumers** — how much to make `pub(crate)` given
   `mvmd` and `mvm-studio` link internal crates; the snapshot must reflect the
   real external contract, not an aspirational one.
3. **CLI verbs to delete outright vs deprecate** — nothing is in production, so
   hard deletion is on the table; confirm the keep-list.
4. **One sprint vs several** — P1/P2 are safe and fast; P3/P4 are larger.
5. **Reimplement-vs-replace threshold (P7)** — at what usage does a dep get cut:
   e.g. "≤ N call-sites of a single function → reimplement or drop." Confirm the
   threshold and the target dependency count (from ~734).

## Exit criteria

- Measurable reductions recorded here as each phase lands: LOC, crate count,
  public-item count, dependency count.
- All 15 claims green; full `cargo nextest run --workspace` + doctests green;
  `cargo clippy --workspace -- -D warnings` clean.
- CLI verb count reduced with a snapshot test guarding it.
- `mvmd` orchestrates a network of ≥2 mvm hosts via the facade (smoke test).
- Dependency count materially reduced from ~734 (target set in the scoping call);
  barely-used deps reimplemented or replaced with a recorded rationale.
- New CI ratchets live: crate-count budget, **dependency-count budget**,
  `cargo public-api` snapshots, `cargo machete`, `cargo deny`.

## Note on Phase 0 coupling

The two-surface feature-forwards and the lint's `INTERNAL` allowlist name
specific sub-crates. Any P3 crate merge/rename must update both in the same
change (mechanical). This is the one place Phase 0 touches later phases; noted so
it isn't a surprise.
