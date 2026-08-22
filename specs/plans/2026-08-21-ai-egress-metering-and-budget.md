# AI egress metering and token budgets

Backing: shipped-source
Validation: check-sprint-append

## Status

**COMPLETE**

Builds on the seam identified in Plan 313 (egress token accounting). Plan 313
remains responsible for streaming response relay (Phase 1) and opt-in
compaction (Phase 5). This plan covers provider-reported token metering,
per-VM budget enforcement, and the user-facing policy surface.

## Goal

Give every microVM real, provider-reported AI token accounting and an optional
spend ceiling at the host egress seam.

- Meter input, output, and total tokens for calls to OpenAI and Anthropic.
- Export per-VM Prometheus counters and emit chain-signed audit records.
- Let a workload declare a token budget; block further AI egress once it is
  exhausted.
- Keep the design extensible: adding Codex, Antigravity, or other providers is
  a one-line macro declaration.

## Non-goals

- Local token estimation (no tokenizer dependency; provider-reported usage is
  authoritative).
- Streaming response relay improvements (covered by Plan 313 Phase 1).
- Prompt compaction (covered by Plan 313 Phase 5).
- Cost/pricing conversion — only raw token counts.

## Design

### Seam

The host substitution endpoint (`mvm-hostd/src/supervisor/network_endpoint_proxy.rs`)
terminates bound-host TLS and already inspects cleartext request/response bodies
for secret substitution and redaction. It is the single chokepoint for every
guest backend (Firecracker, libkrun, HVF), so metering here is universal.

### Policy shape

`AiPolicy` lives inside `NetworkPolicy` so it travels with the egress grant.

`NetworkPolicy::Preset` and `NetworkPolicy::AllowList` each gain an optional
`ai` field. Default is off and unbounded.

TOML authoring:

```toml
[network]
type = "allowlist"
rules = ["api.openai.com:443", "api.anthropic.com:443"]

[network.ai]
metering = true
budget = { max_total_tokens = 1_000_000 }
```

### Provider extraction

A `define_provider!` macro in `mvm-hostd/src/supervisor/ai_meter.rs` declares
host patterns and JSON paths for usage fields. The extractor matches the
request URL host, parses the JSON response body, and reads usage fields.
Missing or malformed usage records `unknown` rather than guessing.

For streamed responses, it looks for a trailing usage block. If none is
present, counts are `unknown`.

### Budget tracker

`mvm-hostd/src/supervisor/ai_budget.rs` holds a process-global
`AiBudgetTracker` mapping `instance_id` to cumulative counters and an
`exhausted` flag.

- After each AI response, add extracted usage to the VM's cumulative totals.
- If any configured limit is exceeded, set `exhausted` and emit an
  `ai.budget_exceeded` audit record.
- On the next AI request for an exhausted VM, return `WireResponse::Refused`
  with a clear message before forwarding.
- Best-effort enforcement: a single response that pushes the VM over budget is
  still allowed through and recorded.

### Metrics

`mvm-core/src/observability/instance_metrics.rs` gains AI request and token
counters, exposed as Prometheus counters labeled by `instance_id`, `tenant`,
`template`.

### Audit

A new `ai.usage` record carries trace correlation, destination metadata,
provider/model, and token counts. No request/response bodies, headers, or
credentials are recorded.

## Phases

### Phase 1 — Core types

- [x] Add `AiPolicy`, `AiBudget` to `mvm-contract/src/policy/network_policy.rs`
      (and re-export through `mvm-core`).
- [x] Add `ai: Option<AiPolicy>` to `NetworkPolicy::Preset` and
      `NetworkPolicy::AllowList`.
- [x] Add `AiUsageRecord` type in `mvm-core/src/policy/audit/ai_usage.rs`.
- [x] Add AI counter fields to `mvm-core/src/observability/instance_metrics.rs`
      and update Prometheus exposition.

### Phase 2 — Host extraction and metering

- [x] Create `mvm-hostd/src/supervisor/ai_meter.rs` with `define_provider!`,
      OpenAI, and Anthropic providers, plus the `AiBudgetTracker`.
- [x] Hook extraction into `SubstitutionService::process` and `process_stream`
      after upstream response returns.
- [x] Update `InstanceMetricsRegistry` from the host endpoint using the VM's
      `instance_id`.
- [x] Emit `ai.usage` audit records via the attached recorder.

### Phase 3 — Budget enforcement

- [x] Keep per-VM cumulative counters and an `exceeded` flag in
      `AiBudgetTracker` (`ai_meter.rs`).
- [x] Pass `instance_id` and `AiPolicy` through `EndpointConfig` →
      `FromPlanInputs` → `SubstitutionService`.
- [x] Check budget after each extraction and refuse subsequent AI requests when
      exhausted.
- [x] Emit `ai.budget_exceeded` audit record once per crossing.

### Phase 4 — User-facing config

- [x] Add `ai` field to `ManifestNetwork` (`mvm-core/src/domain/manifest.rs`)
      and map it into `NetworkPolicy` for the transient-machine path.
- [x] Add `ai` field to SDK `Network` IR
      (`mvm-contract/src/ir/workload.rs`) and propagate through launch JSON.
- [x] Update the workload-IR schema if it is generated from these types.

### Phase 5 — Docs

- [x] Update `README.md` with the `[network.ai]` policy section, supported
      providers, metrics names, and budget behavior.
- [x] Update website docs (`public/`) with the same content.

### Phase 6 — Tests and gates

- [x] Unit tests for each provider's JSON usage shape.
- [x] Unit tests for budget tracker (increment, exhaustion, reset).
- [x] Unit test that garbage response bodies record `unknown` and do not fail
      the request.
- [x] Integration tests exercising the full host endpoint with a mock upstream
      for non-streaming, streaming, budget enforcement, and disabled policy.
- [x] `cargo clippy --workspace -- -D warnings` clean (fixed the
      `clippy::double_must_use` warning by adding a `#[must_use]` reason and
      updating `async-trait`, and the `chunks_exact_to_as_chunks` warning in
      `icmp_echo.rs`).
- [x] `cargo test --workspace` green on host-gated code.
- [x] `just check-gated` passed for the shared types touched by this plan.

## Risks

- **Response body inspection scope.** Only matched provider URLs are inspected;
  arbitrary destinations see no new behavior.
- **Performance.** Extraction is a single `serde_json::Value` parse per AI
  response. Benchmark if launch-path latency moves.
- **Privacy.** Audit records contain counts and metadata only; bodies are never
  logged.

## Acceptance criteria

- A VM with `network.ai.metering = true` has non-decreasing AI token counters
  in Prometheus after each OpenAI/Anthropic call.
- A VM with `network.ai.budget.max_total_tokens = N` can make AI calls until
  the cumulative total exceeds `N`, after which AI egress is refused.
- Adding a new provider requires only a `define_provider!` entry and a unit
  test.
- README and website docs describe the policy and metrics.
