# Plan 313: Egress token accounting, streaming responses, and opt-in compaction

## Status

**Phase 0 COMPLETE** (2026-08-10). Phases 1+ not started.

Written from the competitive assessment in
`specs/research/agent-execution-layer-entrant-assessment.md`.

Tracks issue #2305 (accounting) and extends it with streaming and compaction.

### Phase 0 findings

The premise is confirmed, and the consequence is worse than this plan first
assumed. Resolved at code level; no live run was needed, because the buffering is
unconditional rather than dependent on runtime conditions.

1. **The substitution path buffers the whole response body.**
   `ReqwestForwarder::forward` (`supervisor/substitution_proxy.rs`) ends in
   `resp.bytes().await` and constructs `ForwardResponse { status, headers, body:
   Vec<u8> }`. No incremental relay exists on this path. `ForwardResponse`'s owned
   `Vec<u8>` body is the type-level reason no caller *can* stream.

2. **A streamed response does not merely fail to stream — past 30s it fails.**
   The forward client is built with reqwest's `.timeout(...)`, a whole-request
   deadline that includes body read, defaulting to 30s
   (`default_forward_timeout_secs`). An SSE stream held open longer than the
   timeout is killed. Streaming model calls that run longer than 30s are broken
   today, not just non-streaming.

3. **There is no response body size cap on this path.** `resp.bytes()`
   accumulates without a ceiling, in the one host process that holds workload
   credentials in the clear. A large or hostile response is an unbounded host
   allocation. This is a defect in its own right, independent of metering.

4. **The raw path streams, but gives up everything this seam exists for.**
   `EgressMode::Raw` splices with `tokio::io::copy_bidirectional`, so it streams
   correctly — but it is a gated TCP splice with no credential substitution and no
   HTTP-level redaction. `EgressMode::Wire` (what a plan carrying secret bindings
   selects) is the buffering path.

**The architectural finding: today a workload can have streaming *or* secret
substitution, never both.** That is the real headline, and it reframes Phase 1
from an enabler into a defect fix that also serves the standing requirement that
workload output be observable while it runs.

### Consequence for sequencing — Phase 1 is standalone

`mvm_http::Response` is already streaming-capable and bounded: it holds a live
`stream` with incremental `chunk()` plus a `max_bytes` ceiling — strictly better
than the reqwest path on both counts.

An earlier revision of this section said Phase 1 should be folded into #2314
(Plan 309 Phase 2, retiring reqwest) while that PR was open, because it rewrote
this exact function. **#2314 has since merged, and it kept the buffering**: on
`main` the forwarder still ends in `resp.bytes()` and `ForwardResponse` still
carries `body: Vec<u8>`, with `max_bytes` unset. Retiring reqwest was kept
mechanical, which was a reasonable call on an already-large diff.

So the cheap window is closed and **Phase 1 is a standalone change**. Nothing
about it is blocked any more, and the type-level blocker is unchanged: while
`ForwardResponse.body` is an owned `Vec<u8>`, no caller can stream.

The unbounded-allocation half is tracked separately as its own defect (see the
issue referenced from Phase 1), so it can land ahead of the streaming work if
that is the faster path to a bounded host.

## Why

Three problems that share exactly one seam.

**1. mvm has no cost accounting of any kind.** A grep across `crates/` and `src/`
for spend caps, token budgets, cost caps, or usage metering returns nothing. This
is the single capability gap where the assessed commercial entrant leads on its
headline message, and it is the line item a buyer feels monthly.

**2. Streaming model calls likely do not stream.** `ProxyRequest` in
`crates/mvm-hostd/src/supervisor/substitution_proxy.rs` carries
`body: Vec<u8>` — request bodies are fully buffered. `mvm_http::Response`
(`crates/mvm-http/src/response.rs:205`) bounds its buffer "even for a chunked body,"
which reads as accumulate-then-return rather than incremental relay. If that holds
on the response leg, a workload issuing an SSE model call receives nothing until
the response completes, which defeats the purpose of streaming and is a
correctness problem independent of metering. **Phase 0 must confirm this before
anything else is built.**

**3. Compaction is wanted, but the commodity version is not worth building.** Any
proxy can shrink a prompt. The prior research recommended against chasing it, and
that recommendation stands *for the commodity form*. What is defensible is stated
in the design position below.

These are strictly ordered: **stream → measure → compact.** You cannot measure a
streamed call you buffer, and you must not compact what you cannot measure.

## Design position

The seam is `mvm-substitution-endpoint` (an `mvm-hostd` bin, spawned per VM by
`crates/mvm-vmm/src/host/substitution_spawn.rs`). It is the correct and only
place, for three reasons that already hold today:

- It is the **sole claim-10 decision point**. `xtask check-uniform-vsock-egress`
  pins Firecracker, libkrun, and HVF to that one spawn site, so anything counted
  there is counted for every workload backend by construction.
- It **terminates TLS** for bound hosts (`build_egress_tls_delivery`,
  `EGRESS_CERT_DRIVE_NAME`), so it sees cleartext for exactly the destinations a
  secret binding covers — including model-API responses carrying `usage`.
- It **already inspects and mutates bodies**. `service_redact` /
  `redactor_redact_bytes_for` in
  `crates/mvm-hostd/src/supervisor/substitution_endpoint.rs` performs
  detect-and-replace on cleartext egress, protected by
  `xtask check-stream-redaction-seam`. Body inspection is not a new capability
  class here; it is an existing, gated one.

Byte accounting also already exists in unattributed form: `EgressBudgetState`
(`crates/mvm-vmm/src/vsock_egress_bridge/substitution_bridge.rs`) is a token
bucket with `try_consume` / `reserve_read` / `refill_tokens` used for rate
limiting.

**Why compaction here is not the commodity form.** A hosted proxy that compacts
your prompts requires you to ship those prompts to its cloud. mvm's runs on the
user's own machine, inside the process that already holds their credentials in
the clear, and — critically — every elision can be recorded in the chain-signed
audit log. That makes it the only version of this feature where you can *prove
what was removed* rather than trust a vendor's dashboard. If we build compaction
without the audit anchor, we have built the commodity version and should not
bother.

## Non-goals

- **No spend enforcement in this plan.** A ceiling that denies at the gate is a
  policy surface needing its own design, an ADR-001 row, and a witness. Accounting
  first; enforcement is a follow-on.
- **No new dependency in the default closure.** `CLOSURE_BUDGET` is a ratchet
  currently at **262** and, per Plan 309, sits at its ceiling. See the dependency
  policy below.
- **No LLM-based or semantic compression.** Structural transforms only.
- **No silent mutation of a workload's request.** Ever. See Phase 5.
- **Not a general prompt optimizer.** We compact tool *output* being fed back into
  a prompt, not user-authored prompts.

## Phase 0 — Verify the ground truth (blocking)

**COMPLETE.** Findings in the Status section above. Resolved at code level: the
buffering is unconditional, so a live run could not have contradicted it.

- [x] Locate where the response body is accumulated and whether any byte can reach
      the guest before the response completes. **It cannot** —
      `ReqwestForwarder::forward` ends in `resp.bytes().await`.
- [x] Determine the behaviour for an SSE (`text/event-stream`) response. **Worse
      than buffering**: the whole-request `.timeout(...)` (30s default) kills a
      stream held open past the deadline.
- [x] Confirm whether chunk framing survives the forward leg. **It does not** —
      the body is decoded into an owned `Vec<u8>`; framing is lost by construction.
- [x] Record the per-connection memory ceiling for a large response. **There is
      none** on this path — an unbounded allocation in the credential-holding
      process.
- [x] Write the findings into this plan's Status section before opening Phase 1.
- [x] *(added)* Establish whether the raw path differs. **It does** —
      `EgressMode::Raw` splices via `copy_bidirectional` and streams, but carries
      no substitution and no HTTP-level redaction.

## Phase 1 — Incremental response relay

Confirmed by Phase 0 as a **defect fix**, not a feature: it restores streaming,
bounds an unbounded host allocation, and removes the 30s cliff on long responses.
Value independent of metering.

**Standalone and unblocked.** #2314 has merged and kept the buffering, so there
is no longer a cheaper carrier for this change. The bounded-allocation item below
is also tracked as its own defect and may land first.

- [ ] Change `ForwardResponse` to carry a streaming body rather than an owned
      `Vec<u8>`. This is the type-level blocker; nothing else can stream until it
      changes.
- [ ] Relay incrementally via `mvm_http::Response::chunk()`, preserving chunk
      framing.
- [ ] Set `max_bytes` on the forward response so the allocation is bounded, and
      pick a refusal behaviour for exceeding it.
- [ ] Replace the whole-request `.timeout(...)` with an **idle/read** timeout. A
      total-request deadline can never coexist with a long-lived stream; leaving it
      in place silently re-breaks streaming for slow responses.
- [ ] Keep the existing redaction seam correct across chunk boundaries. **This is
      the hard part**: a secret or PII match straddling two chunks must still be
      caught. This is the same window-straddling limitation already documented for
      the claim 17 secret scan — do not silently regress it. Carry a bounded
      overlap window between chunks and document the residual limit.
- [ ] Bound per-connection buffering explicitly; assert the high-water mark in a
      test.
- [ ] Tests: TTFB on an SSE response is bounded and does not scale with total
      response length; a secret split across a chunk boundary is still redacted;
      chunk framing round-trips.

## Phase 2 — Token accounting

> Non-streaming token accounting, per-VM budget enforcement, and the
> user-facing `[network.ai]` policy are being implemented in
> `specs/plans/2026-08-21-ai-egress-metering-and-budget.md`. This phase keeps
> the streaming-specific accounting work (SSE framing and trailing-usage
> extraction once Plan 313 Phase 1 lands).

- [ ] Detect `Content-Type: text/event-stream` and parse SSE frames incrementally
      (`data:` lines, `\n\n` terminated), never buffering the whole stream.
- [ ] Read provider-reported usage. Two protocol shapes, both real:
      - **Anthropic Messages SSE** emits `message_start` carrying
        `usage.input_tokens` and `message_delta` carrying `usage.output_tokens`.
        Always present; nothing to negotiate.
      - **OpenAI-compatible SSE** only emits a final `usage` chunk when the caller
        set `stream_options: {"include_usage": true}`. The *workload* controls
        that, not us. Do **not** mutate the request to force it in v1 — record
        `unknown` (see the open question).
- [ ] Non-streamed responses: parse `usage` from the JSON body where present.
- [ ] Attribute counts to the resolved destination using the same binding the
      `EgressGate` verdict used, and to the byte counters already in
      `EgressBudgetState`.
- [ ] **Fail-open-to-unknown, always.** A missing, malformed, truncated, or
      unrecognised body records `tokens: unknown`. Metering must never block, error,
      or alter an egress decision. Assert this with a test that feeds garbage.
- [ ] Tests: usage parsed from both SSE shapes; garbage body yields `unknown` and
      the request still succeeds; counts attribute to the right binding.

## Phase 3 — Anchor it in the audit chain

This is what makes the feature ours rather than a dashboard.

- [ ] Emit a `plan.egress_usage` chain-signed entry carrying destination binding,
      byte counts, and token counts where known.
- [ ] **Payload-free**, matching
      `stream_audit_entries_carry_the_binding_and_no_payload_bytes` — binding and
      counts only, never request or response bytes. Add a test asserting this for
      the new entry type.
- [ ] Confirm `mvm_hostd::supervisor::verify_audit_chain` still detects drift with
      the new entry type present.

## Phase 4 — Surface it

- [ ] `mvmctl trust audit usage` (or equivalent read-side verb) reading the
      existing chain: per-VM and per-destination totals, tokens and bytes,
      with `unknown` counts reported honestly rather than folded into zero.
- [ ] `--json` output for programmatic use.
- [ ] Docs: a reference page plus an explicit statement of what `unknown` means and
      when it occurs. Do not publish a number whose provenance we cannot explain.

## Phase 5 — Opt-in compaction (gated on Phases 1–4)

**Do not start this before Phase 3 lands.** Compaction without the audit anchor is
the commodity version.

- [ ] Off by default. Enabled per-plan, explicitly, never inferred.
- [ ] Structural transforms only, no dependencies required (see policy below):
      - JSON array of homogeneous records → header + delimited rows
      - Log text → keep errors, warnings, and bounded surrounding context
      - Diffs → changed lines with bounded context
      - Search results → bounded ranked retention
- [ ] Every transform is **lossless-by-declaration or refuses**: if a transform
      cannot guarantee it preserved the declared signal, it must decline to
      transform rather than guess.
- [ ] Every applied compaction emits an audit entry carrying the transform name,
      input digest, output digest, and byte/token delta — **not the content**. This
      is the property no hosted proxy can offer.
- [ ] Measure before shipping: a `just` recipe reporting realized reduction on a
      corpus, so the claim is a measurement and not a marketing number.
- [ ] Tests: each transform round-trips its declared signal; a transform that
      cannot preserve signal declines; compaction is off unless the plan enables it;
      the audit entry carries digests and never content.

## Phase 6 — Fleet aggregation (`mvmd`)

- [ ] Aggregate per-VM usage entries to per-tenant and per-pool totals in the
      fleet daemon, reading the same chain entries rather than a second source of
      truth.
- [ ] Expose via the existing REST surface and console.
- [ ] Because BYOC is the fleet product's differentiator, the aggregated numbers
      must be derivable on the customer's own hardware with no call home. Assert
      this.

## Dependency policy

`CLOSURE_BUDGET` is at **262** and Plan 309 reports it at its ceiling. Any new
crate fails `xtask check-closure-budget`. Therefore:

- **v1 adds zero dependencies.** Provider-reported `usage` is authoritative, free,
  and needs only the JSON parsing already present. SSE framing is line splitting.
  The structural transforms in Phase 5 are a few hundred lines of plain Rust —
  no library exists that would do them better for our shapes.
- **No tokenizer in the default closure.** `tiktoken-rs` pulls `fancy-regex` plus
  bundled encoder tables; the HuggingFace `tokenizers` crate is far heavier. Either
  would force a budget bump for a *fallback estimate*, which is a bad trade.
- **If local token estimation is ever needed**, it goes behind an off-by-default
  cargo feature so the default closure is untouched, and its output is labeled
  `estimated`, never mixed with provider-reported counts.
- The v1 fallback when no provider usage exists is an explicit `unknown`, not a
  silently-wrong heuristic. A wrong number is worse than no number.

## Risks

- **Chunk-boundary redaction regression (Phase 1).** The highest-severity item
  here. Moving from buffered to incremental relay can silently weaken the existing
  secret/PII redaction. Mitigation: bounded overlap window, an explicit test for a
  straddling match, and a documented residual limit. Do not land Phase 1 without it.
- **Latency on the launch path.** The endpoint spawn is on the prepared launch
  path (#2280, #2299). Parsing must not add measurable per-connection latency;
  benchmark before and after.
- **Cleartext exposure creep.** The endpoint is the one process holding
  credentials in the clear. Nothing in this plan may widen what it stores or logs.
  Counts and digests only.
- **Compaction changes workload semantics.** The model sees different input than
  the workload sent. This is why it is opt-in, audited, and declines rather than
  guesses.
- **Scope drift into enforcement.** Spend ceilings will be asked for as soon as
  numbers exist. That is a separate plan with a separate claim.

## Open questions

- **OpenAI-compatible streaming without `include_usage`.** Options: (a) record
  `unknown`; (b) mutate the request to add `stream_options.include_usage`; (c)
  estimate locally behind the optional feature. (b) is the only one that yields
  complete data, but it mutates a workload's request — which this plan otherwise
  forbids. Recommendation: ship (a) in v1 and treat (b) as an explicit, audited,
  per-plan opt-in decided on its own merits. **Decide before Phase 2 code.**
- Do any bound destinations use a non-HTTP protocol where this seam sees no usable
  frame at all? Phase 0 should enumerate.
- Should `unknown` counts be surfaced as a data-quality metric in their own right
  (e.g. "82% of calls measured")? Probably yes — it makes the honesty visible.
