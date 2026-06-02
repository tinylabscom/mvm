# Plan 135 — Prompt-injection / agent-safety guardrails (taint pipeline completion)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Save-only note:** this document is the captured plan. It is sequenced as a
> refinement threaded into plans 120–132; it does not stand alone and is not to
> be executed ahead of its prereqs. Verify the `135` prefix against `main` +
> open PRs before merge (`cargo xtask check-spec-numbers` is CI-gated).

**Goal:** Complete the prompt-injection / agent-safety pipeline that
`injection_guard.rs` already names as deferred (taint propagation, tool-gate,
classifier seam) — as **risk-classification + provenance + taint + deterministic
capability authorization**, in the consolidated ADR-066 module layout. Shared
logic in `mvm-core`; enforcement consumed by `mvmd`. **No new crates, no new
third-party deps by default** (respects 121 + 126).

**Architecture:** This is not a new subsystem — it is the completion of the
existing `Inspector` / `injection_guard` egress backbone and an extension of the
broker's binding-gated dispatch (ADR-059, claims 12/13). Detection is advisory;
the **authoritative** control is a deterministic policy gate: tainted
(untrusted-provenance) content cannot, by itself, authorize a privileged host
action — authorization requires an explicit signed binding. After 121,
detection + policy + taint live in `mvm-core::guard` (folding the current
`mvm-supervisor/src/injection_guard.rs` `DEFAULT_RULES` as the single rule
source); the `Inspector` adapter follows the L7 egress proxy into `mvm-network`
(123). `SecretExfiltration` is a finding from 129 Phase E's leak-detector — one
scanner, two consumers. GuardPolicy is bound into the signed `ExecutionPlan` /
policy bundle (`mvm-core::policy`), never runtime-mutable; `ruleset_version` is
recorded in the audit labels for replay determinism on the signed chain.

**Tech Stack:** Rust (`mvm-core::guard`, `mvm-core::policy`, `mvm-network`,
`mvm-hostd`), existing workspace deps only (`regex`, `aho-corasick`, `serde`,
`thiserror`, `tracing`); the eval is a `cargo xtask guard-eval` subcommand
(precedent: `xtask perf` / `check-*`). NFKC/confusable (`unicode-normalization`
/ `unicode-security`) and the ONNX model backend (`ort` / `tokenizers`) are
deferred, not added by default.

**Prereqs / sequencing:** 121 (post-fold homes: `mvm-core`, `mvm-hostd`,
`mvm-network`), 123 (the egress proxy the `Inspector` hangs on), 129 Phase E
(the shared leak-detector). 128 owns the CI claim gate + fuzz parity; 127 owns
the latency budget. mvmd enforcement is a separate-repo plan consuming the
post-121 `mvm-core` module map (the Plan 104 / mvmd ADR-0020 handoff pattern).

**Boundary (what this plan does NOT do):** it does not make the guest "safe"
(single-tenant + confined per ADR-002); it does not claim detection accuracy
(see §"Why not a detection claim"); it does not guard the developer's own
coding-agent skill files (operator environment, not mvmd runtime); it does not
add new crates (121) or new default deps (126); it does not build mvmd's
enforcement wiring (separate repo).

---

## Why not a detection claim (claim framing)

Claiming "we detect prompt injection" is lossy and self-defeating, and
`check-doc-claims` / `check-no-overclaim` gate the marketing phrasing. The
verifiable, CI-gatable property is the **policy gate**: untrusted-provenance
content cannot authorize a privileged host action without an explicit signed
binding. If promoted to a numbered security claim, follow 128 C4's
jailer-promotion pattern and word the claim as the policy property — an
extension of claims 12/13 — not as detector recall.

## Threading into 120–132

| Piece | Host plan | What lands |
|---|---|---|
| `mvm-core::guard` (types, rule engine, taint, policy, `PromptGuard::inspect`, `authorize_tool_call`) | **121** | detection + deterministic policy, fed by the migrated `DEFAULT_RULES`; no new crate |
| `Inspector` adapter re-homed onto `mvm-core::guard` | **121 → 123** | egress proxy (`mvm-network`) calls the shared rules; supervisor dup removed |
| Taint provenance on `RequestCtx` / `ServiceCallCtx`, surviving to the capability check | **123 + broker (ADR-059)** | the load-bearing piece injection_guard deferred |
| GuardPolicy in the signed plan + `ruleset_version` in audit | **122/129 + claim-8 admission** | policy signed, not mutable; audit replay-deterministic |
| `SecretExfiltration` = 129 leak-detector finding | **129 Phase E** | no second scanner |
| `cargo xtask guard-eval` + fixtures + CI claim gate + fuzz target | **128** (Phase B/C) | metrics gate + re-homed fuzz harness, input-cap + RegexSet size limit |
| Latency budget (p95) on the inline path | **127** (`xtask budget`, informational per ADR-066 §7) | aho-corasick prefilter; benign traffic skips the regex set |
| mvmd enforcement (mvmd-mcp / -sandbox / -gateway / -iam) | **mvmd plan (new)** | consumes post-121 `mvm-core::guard`; cross-repo handoff |

---

## Phase 1 — `mvm-core::guard` (within 121's core fold)

### Task 1: core types

**Files:** `crates/mvm-core/src/guard/{mod,input,verdict}.rs`.

- [ ] **Step 1:** Failing serde roundtrip + `deny_unknown_fields` tests for
      `PromptSource`, `TrustLevel`, `PromptInput`, `Provenance`, `GuardAction`,
      `GuardReasonKind`, `GuardReason`, `GuardVerdict`, `GuardAuditEvent`.
- [ ] **Step 2:** Implement the types; `thiserror` `GuardError` (no panics —
      lib returns `Result`, caller maps `Err` → deny). Commit.

### Task 2: rule engine (single rule source)

**Files:** `crates/mvm-core/src/guard/rules/{engine,families}.rs`; migrate
`DEFAULT_RULES` out of `mvm-supervisor/src/injection_guard.rs`.

- [ ] **Step 1:** Move the curated rules (ControlToken / Jailbreak /
      Steganography) into the module; add families: system-prompt-extraction,
      tool-abuse, shell-abuse, network/data-exfil, mcp-injection,
      skill-file-injection. Each rule carries `family`, `weight`,
      `GuardReasonKind`. aho-corasick literal prefilter → `regex::RegexSet`.
- [ ] **Step 2:** Cap input length before scanning; set `RegexSet` size limit;
      cap reasons-per-verdict; never echo matched spans into reasons/audit
      (preserve the existing audit-safety invariant). Commit.

### Task 3: taint, context, policy, guard

**Files:** `crates/mvm-core/src/guard/{taint,context,policy,guard,model}.rs`.

- [ ] **Step 1:** `taint.rs` — taint set + propagation helpers; test the
      web→summary→shell chain keeps taint to the authorization layer.
- [ ] **Step 2:** `context.rs` — down-weight by source/trust/task (benign
      security-doc / fixture / definition-question / quoted-issue →
      `BenignQuotedAttackExample`). Fixtures include real lines from the repo's
      own ADRs so the guard never flags ADR-002.
- [ ] **Step 3:** `policy.rs` — `Capability`, `ToolRequest`, `ToolDecision`,
      `GuardPolicy`, `authorize_tool_call` (deny-by-default matrix: tainted
      untrusted content cannot auto-trigger Write/Shell/Network/SecretRead/
      TenantMutation; secrets deny-by-default; MCP-from-untrusted →
      RequireApproval/Deny). `RequireApproval` defaults to Deny-with-audit when
      no approval channel is wired.
- [ ] **Step 4:** `model.rs` — `ModelBackend` trait + `NullModelBackend`
      (neutral score); blend logic tested.
- [ ] **Step 5:** `guard.rs` — `PromptGuard::inspect`; doctests on the public
      API. Commit.

## Phase 2 — re-home the `Inspector` (within 121 → 123)

- [ ] Migrate `injection_guard`'s `Inspector` impl onto `mvm-core::guard` as the
      single rule source (hard-move, no parallel duplicate — first-version
      ethos). Existing `injection_guard` tests pass. Document chain placement in
      the `DestinationPolicy → SsrfGuard → SecretsScanner → InjectionGuard →
      PiiRedactor` order (cheap high-precision denies early). Commit.

## Phase 3 — signed-policy binding + audit (within 122/129)

- [ ] `GuardPolicy` fields in the signed `ExecutionPlan` / policy bundle
      (`mvm-core::policy`); admission (claim 8) carries them. `ruleset_version`
      in `GuardAuditEvent` → audit labels (bounded cardinality; no spans/free
      text). Trust labels are stamped host-side at ingress and **never** accepted
      from the guest (lint-enforce if practical). Commit.

## Phase 4 — eval + claim gate + fuzz (within 128, budget in 127)

- [ ] `cargo xtask guard-eval` reading `specs/guard-fixtures/<category>.jsonl`
      (12 categories: benign_security_discussion, direct/indirect/second_order
      injection, jailbreak, tool_abuse, secret/shell/network exfil,
      mcp_injection, skill_file_injection, unicode_obfuscation). No secrets, no
      network. Metrics: precision/recall/FP/FN, p50/p95, reason + policy-decision
      coverage.
- [ ] CI claim gate asserts low FP on benign fixtures + recall threshold on
      malicious; rule changes that tank precision fail the build. Re-homed
      `cargo-fuzz` target over the rule engine / normalizer (128 Phase B). p95
      latency budget into 127's `xtask budget` (informational). Commit.

## Phase 5 — ADR

- [ ] `specs/adrs/0NN-prompt-injection-guardrails.md` (next free at write time;
      `check-spec-numbers` gated). Sections: Context, Decision, Why-not-detector-
      only, Why-shared-logic-in-mvm-core, Why-enforcement-in-mvmd,
      Taint/provenance model, Policy model (signed, not mutable), Future model
      backend, Evaluation strategy, Security tradeoffs (over-claim risk, FP
      soak, fail-closed), Open questions. Cross-ref ADR-002, ADR-059, ADR-066,
      ADR-067, Plan 37 §15.

---

## Open questions (resolve in the ADR)

- **Fail-closed on guard error.** Guard failure (rule compile, backend
  unavailable, timeout) must fail-closed for privileged capabilities; fail-open
  only for non-privileged reads.
- **`RequireApproval` in a headless daemon.** No human at dispatch — map to
  queue or **Deny-with-audit**; never silent allow.
- **Bypass governance.** Prefer no global env bypass; per-binding allow in the
  signed plan; any bypass emits a distinct audit event and is refused under
  `--prod`.
- **Trust-label origin.** "Untrusted by default" only holds if the label is
  assigned host-side and is non-forgeable by the guest.
- **Cross-repo serde versioning.** `GuardVerdict` / `GuardReason` /
  `GuardAuditEvent` cross mvm→mvmd: `deny_unknown_fields` + version discipline,
  fail-closed on schema bump.
- **Ruleset is in-tree, never fetched** (no hot-reload rule source).
- **MCP tool outputs** flowing back to the operator's LLM are a second-order
  vector we can annotate (advisory taint marker) but not own — decide
  annotate-don't-block.
- **Snapshot/restore (123).** Confirm taint is per-request and never baked into
  a warm-start snapshot.

## Verification

- `just lint` + `just test` green; `cargo test -p mvm-core guard` (unit +
  doctests for every reason kind, deny-by-default matrix, taint propagation,
  context down-weighting); existing `injection_guard` tests pass post-migration.
- `cargo xtask guard-eval --json` prints metrics; gate asserts FP/recall
  thresholds; fuzz target smoke-runs; `cargo xtask check-spec-numbers` green.

## Deferred follow-ups

- [ ] NFKC + confusable-skeleton coverage (126 dep-budget decision on
      `unicode-normalization` / `unicode-security`).
- [ ] ONNX `ModelBackend` (`ort` + `tokenizers` + Python train/export).
- [ ] mvmd enforcement plan (separate repo) consuming `mvm-core::guard`; its own
      claim promotion in the ADR-002 table.
