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
developer can hold in their head — preserving **every** security claim and
enabling a **network of mvm hosts driven by `mvmd`**.

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

Likely order: **P1 → P2 → P4 → P3 → P5 → P6** (safe/fast first; larger surgery
after the scoping call).

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

## Exit criteria

- Measurable reductions recorded here as each phase lands: LOC, crate count,
  public-item count, dependency count.
- All 15 claims green; full `cargo nextest run --workspace` + doctests green;
  `cargo clippy --workspace -- -D warnings` clean.
- CLI verb count reduced with a snapshot test guarding it.
- `mvmd` orchestrates a network of ≥2 mvm hosts via the facade (smoke test).
- New CI ratchets live: crate-count budget, `cargo public-api` snapshots,
  `cargo machete`.

## Note on Phase 0 coupling

The two-surface feature-forwards and the lint's `INTERNAL` allowlist name
specific sub-crates. Any P3 crate merge/rename must update both in the same
change (mechanical). This is the one place Phase 0 touches later phases; noted so
it isn't a surprise.
