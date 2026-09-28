# Agent efficiency overhaul: how we work with Claude, Codex, and Kimi

Backing: shipped-source
Validation: transcript-reanalysis

**Status:** IN PROGRESS — Phase 1 complete; Phases 2–10 not started.

## Problem

A quantified analysis of ~120 sampled transcripts across the three agent
stores (`~/.claude/projects` 3.4 GB, `~/.codex/sessions` 9.0 GB,
`~/.kimi/sessions` 821 MB) shows the dominant costs are harness behaviors,
not model quality:

| Signal | Claude | Codex | Kimi |
|---|---|---|---|
| Avg tool calls / session | 117 | 240 | 532 |
| Tool failure rate | 21% | 18% | 11% |
| Sessions with retry loops (identical back-to-back calls) | 8% | 18% | 30% |
| Sessions with ≥5 tool errors | — | — | 33/40 |

Specific pathologies observed verbatim in transcripts:

- Same command re-run 16× back-to-back after failures (Kimi, `mvmctl build`).
- `sleep 240 && gh pr checks` polling loops (Kimi); one Codex session issued
  **957 `wait` calls**.
- `cargo test --workspace` mentioned 567× across 15 Claude sessions, often
  immediately after a failure, instead of re-running the one failing test.
- Kimi: 83% of 21k sampled tool calls were `Shell` (peak 1,830 calls in one
  session); 100+ char `cd … && export MVM_HOME=… CARGO_TARGET_DIR=…` prefixes
  repeated 8–16× per session.
- Codex: avg 192 reasoning items/session; transcripts up to 54 MB.
- Subagents launched into environments that immediately block them
  (workspace-boundary denials) and return "blocked" summaries.

## Goal

Cut median session length and token spend by ~⅓, and reduce tool failure
rate to <5%, by changing the *harness and working agreements* — not by
switching models. Every item below is either a config/setting change, an
`AGENTS.md`-level working agreement, or a small script/tool — none require
product code changes.

## Baseline & re-measurement

The analysis script lives at `scripts/agent-transcript-analysis.py` and is checked in for reproducible re-measurement:

```sh
python3 scripts/agent-transcript-analysis.py 60
```

Success = retry-loop session share <5% (all tools), scoped-test adoption,
zero `sleep`-polling patterns in new transcripts, Kimi Shell share <60%.

---

## Phase 1 — Kill the retry loop (highest impact)

- [x] **1.1 Diagnose-before-retry rule in `AGENTS.md`.** Add a working
  agreement: an identical command may never be re-issued after a failure
  without an intervening *different* investigation call (read the full error,
  inspect state, change one thing). One-line rule, applies to all three tools
  since all read this repo's `AGENTS.md`.
- [x] **1.2 Kimi: harness retry dedup.** Kimi has no visible retry guard;
  file/track with Kimi CLI maintainers or wrap long-running commands via
  `bin/dev` (which already centralizes env). Practical step: extend
  `scripts/dev-env.sh` with a `mvm_run` helper that logs the last failed
  command per worktree and refuses blind re-runs.
- [x] **1.3 Measure (baseline recorded).** N=60 re-measurement with the
  checked-in script, seed 42, recorded 2026-09-28 — the "before" snapshot:
  - Claude: 5,894 calls (avg 98/session), 21% error-keyword rate,
    3/60 retry-loop sessions (5%), 673 `cargo test --workspace` mentions
    in 22 sessions.
  - Codex: 31,443 calls (avg 524/session), 24% failure rate, 14/60
    retry-loop sessions (23%), 1,682 duplicate calls, 380 reasoning
    items/session, 14 sessions >5 MB (max 203 MB).
  - Kimi: 24,803 calls (avg 413/session), 12% error rate, 16/60
    retry-loop sessions (27%), 148 duplicate calls, 84% Shell share
    (20,847/24,803).
  Target: <5% of sampled sessions with ≥2 back-to-back identical calls on
  the after-sample; re-run two weeks after the agreements land.

## Phase 2 — Event-driven waits, never sleep-polling

- [x] **2.1 Ban `sleep N && <check>` in `AGENTS.md`** next to the existing
  "Waiting Model" section, which already prescribes events/timers/
  reconciliation — the agents aren't following it because nothing makes the
  cost visible.
- [x] **2.2 CI-watching recipe.** Added to `AGENTS.md`: use `gh pr checks
  --watch` (event-driven) or background tasks instead of sleep loops; cap any
  remaining bounded poll at 5 iterations with escalating backoff.
- [x] **2.3 Codex anti-example recorded.** Full-store scan (1,411 Codex
  sessions): 48,387 `wait` calls total, five sessions each issued >1,200
  sequential waits (max 2,213, `rollout-2026-08-03T17-54-43-019fca44`);
  869 `sleep >=5s` calls across 55 sessions. Kimi: 1,041 `sleep >=5s` calls
  across 109 wires, 44 wires with sleep-polls (worst: 184 sleeps in session
  `132ddba61eed4a5a`). These are the "before" numbers for 2.4.
- [ ] **2.4 Measure.** Re-scan with the same full-store script; target: zero new sessions with `wait` counts >50 or `sleep >=5s` polls, and total wait calls trending to <5,000 (from 48,387).

## Phase 3 — Scoped test runs by default

- [ ] **3.1 `AGENTS.md` test-loop agreement.** Failure loop must be:
  run scoped test → read failure → fix → re-run *same scoped test* →
  workspace sweep once before declaring done. `cargo test --workspace` is a
  pre-merge/CI gate, not a debugging tool. (`AGENTS.md` already says host
  default for cargo; this adds the scoping rule.)
- [ ] **3.2 Add a `just test-scoped <pkg> <filter>` recipe** (or document the
  exact `cargo nextest run -p …` one-liner) so the cheap path is also the
  easy path.
- [ ] **3.3 Measure.** Count `cargo test --workspace` occurrences per session
  in new transcripts; target: ≤1 per session (the final sweep).

## Phase 4 — Route exploration through graft, not raw Shell/Grep

- [ ] **4.1 Graft adoption audit (done — findings below).** Graft MCP is
  configured for **Cursor** (`.cursor/mcp.json`) and **Codex**
  (`~/.codex/config.toml [mcp_servers.graft]`), and Claude has the project
  skill (`.claude/skills/graft/SKILL.md`). **Kimi has no graft configured at
  all**, yet Kimi is the heaviest raw-tool user (1,190 Grep + 1,135 ReadFile
  calls in the sample). No sampled transcript showed meaningful graft usage.
- [ ] **4.2 Wire graft into Kimi.** Add the graft MCP server to
  `~/.kimi/config.toml` (same `graft mcp` command as Cursor/Codex).
- [ ] **4.3 Make graft the first move in `AGENTS.md`.** All three tools read
  this file; add: "For any codebase question — where code lives, who calls
  it, what breaks — query graft *before* Grep/Glob." The project graft skill
  already says this for Claude; promote it to the shared file.
- [ ] **4.4 Measure.** Kimi Shell share of tool calls <60%; Grep+Glob calls
  per session down 50% in new transcripts.

## Phase 5 — Persistent shell state

- [ ] **5.1 One shell setup per worktree.** Working agreement: at the start
  of a session `source scripts/dev-env.sh` once; never re-export
  `MVM_HOME`/`CARGO_TARGET_DIR`/`CARGO_HOME` inline per command. (`bin/dev`
  already exists for one-off `mvmctl` calls.)
- [ ] **5.2 Trim `cd worktree && …` prefixes.** Agreement that commands run
  from the worktree root (the session cwd), not via repeated absolute-`cd`
  prefixes; the repeated-prefix pattern in transcripts is a copy-paste drift
  risk.
- [ ] **5.3 Measure.** No `MVM_HOME=` inline prefixes in new transcripts
  beyond the first setup.

## Phase 6 — Cap reasoning bloat (Codex)

- [ ] **6.1 Codex config:** investigate `model_reasoning_effort` /
  reasoning-effort settings to reduce 192-item reasoning chains; prefer
  act-after-at-most-one-reasoning-item for mechanical phases.
- [ ] **6.2 Working agreement:** reasoning without a tool call is capped —
  after 2 consecutive reasoning turns, take an action (tool call, question to
  user, or commit to a hypothesis and test it).
- [ ] **6.3 Measure.** Avg reasoning items/session <100; no session >10 MB.

## Phase 7 — Recovery discipline (diagnose → change one thing → scoped re-run)

- [ ] **7.1 Codify the recovery sequence** in `AGENTS.md` (extends 1.1 to
  non-identical retries): full error read, root-cause hypothesis, single
  change, scoped verification. Error clustering (33/40 Kimi sessions with
  ≥5 errors) shows retries without diagnosis are the norm.
- [ ] **7.2 Failure journal per long session:** when a session accumulates
  3+ failures on one task, the agent must write a 3-line failure journal
  (what failed / why / next single change) before the next attempt.
- [ ] **7.3 Measure.** Tool failure rate <5% in new transcripts; error
  clustering (≥5 errors/session) <10% of sessions.

## Phase 8 — Background tasks for long operations

- [ ] **8.1 Agreement:** anything expected to run >60 s (builds, CI watches,
  test sweeps) goes to a background task with notification, not a foreground
  blocking call. Kimi already has the capability (used only 142× vs 17.6k
  Shell calls).
- [ ] **8.2 CI-watch recipe:** `gh pr checks <n> --watch` or background +
  notification; never `sleep`-then-check (closes the loop with Phase 2).
- [ ] **8.3 Measure.** Long-command foreground Shell calls with
  timeout >120 s: near zero in new transcripts.

## Phase 9 — Context hygiene in long sessions

- [ ] **9.1 Mid-session state snapshot.** Working agreement: at each phase
  boundary, emit a 10-line snapshot (decisions made, files touched, next
  step, blockers) so compaction doesn't destroy intent. Compaction events
  already observed in Claude transcripts; >5 MB Codex transcripts risk
  truncation.
- [ ] **9.2 Session budget awareness:** when a session crosses ~50 tool
  calls without reaching its goal, stop and re-plan (write the plan to a
  todo list) rather than continuing to burn context.
- [ ] **9.3 Measure.** Sessions >5 MB fraction reduced; user "where were we"
  corrections zero (currently 0 observed, keep it that way).

## Phase 10 — Subagent pre-flight discipline

- [ ] **10.1 Pre-flight checklist in every subagent prompt:** target paths
  inside workspace boundary, required env vars present, read-only vs
  write scope declared. All three transcript-analysis subagents in the
  2026-09-28 session blocked immediately on workspace-boundary denials —
  wasted launches.
- [ ] **10.2 Capability declaration:** subagent prompt must state which
  tools it will use and why; operator approves with full information.
- [ ] **10.3 Measure.** Zero "blocked — access denied" subagent summaries in
  new transcripts.

---

## Non-goals

- No model/provider switching.
- No product-code changes to mvm itself.
- No new heavy dependencies; the harness changes are agreements, config, and
  at most small justfile/helper additions.

## Rollout

1. Land `AGENTS.md` working-agreement changes (Phases 1–3, 5, 7–10 are mostly
   this file) in one PR — they are text edits.
2. Config changes (Kimi graft MCP, Codex reasoning effort) land locally in
   `~/.kimi/config.toml` / `~/.codex/config.toml` — not repo files; record
   them in this plan's validation notes.
3. Re-run `python3 scripts/agent-transcript-analysis.py 60` on a fresh sample after two weeks
   of normal use; append before/after numbers to this plan.

## Appendix: analysis script

The quantified baseline was produced by sampling 40 transcripts per tool
(seed 42) and counting tool calls, error-keyword results, back-to-back
duplicate calls, and per-session command repetition with the checked-in
`scripts/agent-transcript-analysis.py`, so the re-measurement stays
reproducible from a checkout.
