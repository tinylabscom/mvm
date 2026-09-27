# Plan: Cumulative action ledger — per-run budgets beyond AI tokens

Backing: shipped-source
Validation: check-sprint-append

## Status

**Not started.** Drafted 2026-09-24 from the sandbox-hardening grade card
(LinkedIn "7 ways to lock down AI agent sandboxes" assessment, idea 4: *track
cumulative actions across turns, not just single tool calls*).

Motivating gap, stated plainly: a per-call or per-second rule has no memory. The
existing `EgressRateGuard` caps *speed* (100 req/s token bucket); a looping or
compromised guest can stay under the rate forever and drain an API key, a
secret-substitution quota, or a destination's patience across thousands of
requests. The AI-token budget (`AiBudgetTracker`) already answers this for LLM
spend; every other host-observable action channel has rate limits but no
cumulative ceiling.

## Why

The `$20 refund × 6` attack from the grade card is caught today **only** when
the repeated action flows through the AI-metered egress seam. The general form —
any repeated host-observable action — has no cumulative limit anywhere:

- Egress flows opened and bytes relayed (`gateway.flow_opened` /
  `flow.egress.allowed` events exist; nothing totals them).
- DNS queries (per-query audit exists; `NetworkLimits` caps concurrent
  bindings, not lifetime totals).
- Secret substitutions (`secret.substituted` events; a compromised guest could
  burn a third-party API quota under a bound host, or probe the substitution
  oracle).
- Stdin/stream grants (`stream.input_granted` events; nothing totals them).
- Collected output (`OutputGrant.max_bytes` caps one collection; nothing caps
  lifetime totals across resumes).

This plan generalizes the proven `AiBudgetTracker` shape — per-dimension
saturating counters plus an `exceeded` latch, refusal pre-forward, audited — to
those channels. It deliberately does **not** try to count in-guest tool calls
the host cannot observe; the ledger counts what crosses the seams mvm already
owns.

## Design position

**Extend, don't fork.** The AI meter is the template, not a component to
replace: provider-specific usage extraction stays in `AiBudgetTracker`. The new
piece is a generic cumulative ledger next to it.

### Signing channel — the one deliberate divergence from AiBudget

`AiPolicy` rides unsigned channels (machine spec `[network.ai]`,
`EndpointConfig` JSON). That was acceptable because token spend is
guest-visible anyway. A cumulative *action* ceiling enforced host-side must be
tamper-evident, or a compromised guest can just raise it: carry
`action_budget: Option<ActionBudget>` **in the signed `ExecutionPlan`**
(additive `#[serde(default, skip_serializing_if = "Option::is_none")]`,
following the `grants` field precedent whose doc at
`execution_plan.rs:84-91` states exactly why grants ride signed), and project
it into `EndpointConfig` the way `network_limits` is projected
(`network_endpoint.rs:234-239`).

### Type shape

`ActionBudget` in `crates/mvm-contract/src/policy/` — all fields `Option<u64>`,
`None` = unlimited, additive `#[serde(default)]`:

| Dimension | Fed by | Enforced at |
|---|---|---|
| `max_egress_flows` | flow open | egress pipeline, pre-forward |
| `max_egress_bytes` | bytes relayed (in+out) | egress pipeline, pre-forward |
| `max_dns_queries` | per-query | DNS supervisor |
| `max_secret_substitutions` | `secret.substituted` | substitution service |
| `max_stdin_grants` | `stream.input_granted` | input gate |
| `max_output_bytes` / `max_output_entries` | collection totals | `PreparedOutputs::collect` |

Cumulative counters use `saturating_add`; a request that crosses the ceiling is
recorded but the **next** one is refused — the exact `AiBudgetTracker::record`
semantics at `ai_meter.rs:247`, chosen so a single oversized response can never
strand an in-flight flow.

### Default posture

Default is **no budget** (`None`), preserving current behavior. This is a
blast-radius/cost control layered on top of isolation, not an isolation
boundary — the deny-by-default posture lives in `NetworkPolicy` and is
unchanged. When a budget *is* set, it is enforced strictly, and its presence is
signed into the plan, so "no budget on this run" is attributable the same way
`stream_retention` is.

### Audit and receipts

- Refusal emits `host.action.budget_exceeded` following the
  `host.ai.budget_exceeded` two-event pattern (`pipeline.rs:52-56` refusal +
  `ai_budget.rs:79` audit), with host-chosen fixed refusal words so the audit
  line cannot carry guest bytes.
- Events are unbound (sentinel plan id) with an `instance_id` label, matching
  the existing AI/secret events — the endpoint deliberately holds no
  `ExecutionPlan` (`audit_recorder.rs:90-98` documents why). Do not thread plan
  context into the endpoint in this plan.
- Refusal storms reuse `RetryStormSuppressor` semantics
  (`audit_dedup.rs:1-57`).
- Run totals extend `UsageCapture` (`mvm-core/src/usage_capture.rs`) with new
  `Metric` fields (`#[serde(default)]`, keep the struct `Copy`) so totals land
  in the existing receipt-export path (`receipt_export.rs:122`) for free.

### Explicit non-goals (v1)

- Per-conversation scoping — budgets are per-VM lifetime, same as `AiBudget`.
- Dollar/cost conversion or anomaly detection (separate research note).
- Guest-visible budgets or in-guest enforcement.
- Replacing or merging `AiBudgetTracker` (it stays; the ledger is the generic
  sibling).

## Phases

### Phase 0 — Contract and claim scaffolding

- [x] `ActionBudget` type + `Default` in `mvm-contract/src/policy/` (own
  module), re-exported host-side; serde roundtrip and default-value tests.
- [x] Additive signed-plan field on `ExecutionPlan` with doc-comment precedent
  style; plan-bytes/schema-stability test (existing plan fixtures unchanged).
- [x] `secrets_from_signed_json`-style extractor: add
  `action_budget_from_signed_json` next to `secrets_from_signed_json`
  (`signing.rs:84`).
- [x] Claim **MVM-SEC-22** row in `model/claims.toml` (level `build`,
  suite `s37_cumulative_ledger`), suite skeleton
  `features/suites/s37_cumulative_ledger/`; `xtask check-conformance` and
  `check-claim-catalog` green.

### Phase 1 — Ledger core

- [ ] `ActionLedger` in `mvm-hostd/src/supervisor/` — per-dimension
  `AtomicU64` + `exceeded` latch, `record(dim, n) -> Status` and
  `check(dim) -> bool`; generalize the `AiBudgetTracker` shape without touching
  it.
- [ ] Unit tests: saturating adds, strict `>` ceiling, latch latches, zero
  budget refuses the first request, `None` dimension never refuses,
  per-dimension independence. If a function can fail, a test proves
  refusal/`Err`, not panic.

### Phase 2 — Enforcement at the five seams

- [ ] Egress pipeline: flows + bytes fed from the flow-open/relay path;
  refusal = `WireResponse::Refused` pre-forward + audit (mirror
  `pipeline.rs:52-56`).
- [ ] DNS supervisor: `max_dns_queries` at the per-query decision point.
- [ ] Substitution service: `max_secret_substitutions` at the
  `secret.substituted` emit site.
- [ ] Input gate: `max_stdin_grants` at `stream/input_gate.rs:278`.
- [ ] Output collection: `max_output_bytes`/`max_output_entries` totals in
  `PreparedOutputs::collect`, reusing the existing `OutputOutcome::Refused`
  path (`outputs.rs:257-264`).
- [ ] Mock-I/O pipeline tests per seam (positive under budget, negative over
  budget refused + audited, edge: exact-ceiling pass then next-request
  refusal).

### Phase 3 — CLI, admission, receipts

- [ ] `--action-budget dim=n,...` flag resolved in admission next to
  `resolve_ai_policy` (`run_network.rs:43-47`); wired at the same call sites as
  `--ai-token-budget`.
- [ ] `UsageCapture` extension + receipt-export coverage test.
- [ ] CLI integration tests in `tests/cli.rs` (flag parsing, plan carries the
  budget, unknown dimension name rejected).

### Phase 4 — Live witness, BDD, docs

- [ ] Live CI gate test mirroring `egress_secret_leak_gate.rs`: drive a canary
  workload over a tiny `max_egress_flows` budget and assert refusal + audit
  line; Linux-gated, runs in the builder VM.
- [ ] BDD scenarios in `s37_cumulative_ledger` beyond the registration
  skeleton; escalate the claim level only when the live witness lands
  (honesty rules in `model/claims.toml` header).
- [ ] Public docs (`public/src/content/docs/`) section + `specs/SPRINT.md` and
  `specs/REFACTOR-STATUS.md` updates in the landing PR.
- [ ] Full definition-of-done sweep: `cargo test --workspace`,
  `cargo clippy --workspace -- -D warnings`, `just check-gated` (shared-type
  change), Linux-gated tests in the builder VM.

## Open questions

1. Should `max_secret_substitutions` count per-secret-name or globally? Global
   (simpler) is proposed; per-name is a later additive field.
2. Should budget enforcement be fail-closed at the *endpoint* if the signed
   plan and `EndpointConfig` disagree (e.g. projected budget missing)?
   Proposed: yes — a plan that mandated a budget and an endpoint that lost it
   must refuse startup, not run unbudgeted.
