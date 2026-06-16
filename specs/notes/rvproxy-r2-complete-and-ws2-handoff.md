# rvproxy R2 complete — review record + WS-2 handoff (2026-06-15)

Follow-on to `rvproxy-r2-session-closeout-and-handoff.md`. That note handed off
*building* R2; this one records that **R2 is now complete on rvproxy `main`**, the
review findings against each slice, and the conditions WS-2 (the mvm-side port)
starts under. Source of truth for the cutover plan remains
`specs/plans/193-rvproxy-network-substrate.md` §WS-2.

## R2 is done

All four slices of the native flow-decision + audit API (rvproxy
`specs/plans/014` §R2) merged to rvproxy `main`:

| Slice | What landed | rvproxy PR |
|-------|-------------|-----------|
| 1 — deny-by-default flow decision | `default_egress_deny` enforced at the single `policy_destination_reason` chokepoint | #97 |
| 2 — flow lifecycle + audit | `FlowEvent` (`Opened`/`Closed{reason}` w/ 5-tuple, verdict, byte counts) + in-process `FlowEventSink` trait (default `NoopFlowEventSink`); fail-closed at flow birth (`flow_decision_sink_failures`) | #100 |
| 3 — flow-context + flow-kill | `ByteFrameFlow` 5-tuple on `ByteFrameMetadata`; `TransformOutcome::FlowKill{reason}`; `kill_flow`/`kill_tracked_flow` sticky teardown emitting `FlowClosed`; `requires_flow_metadata()` opt-in; `rvproxy_flow_kills_total` metric | #101, #103 |
| 4 — rule-carrying redaction | `PluginRedactionRegionRule {prefix, terminators, mask, min_len}` masking on `secret-redaction-filter`; declared/undeclared split preserved | #108 |

The mvm-side parity lane (Plan 193 WS-1.5: `scripts/rvproxy-gateway-parity.sh` +
`.github/workflows/rvproxy-parity.yml`) was already live before R2; it now has a
complete native API to validate against.

## Review findings (the part to carry forward)

These PRs merged fast (self-merged within ~30–90 min each), so the reviews are
mostly post-merge. Findings filed as rvproxy issues / PR comments:

- **rvproxy #108 finding 1 — 🔴 raw secret in the decision channel (carry into WS-2).**
  The `secret-redaction-filter`'s `TransformInput` decision event captures the
  **raw, pre-redaction** payload. It's opt-in (gated by `include_payload_bytes`)
  and pre-existing, but slice 4 makes this the *undeclared-secret-redaction* path —
  so with payload capture on, the cleartext secret it is redacting leaks out the
  `PluginDecisionSink` (JSONL/UDS). **mvm MUST wire this filter with
  `include_payload_bytes: false`.** Ideal upstream fix: suppress `TransformInput`
  capture (or capture the masked form) for this filter regardless of the knob.
  Merged with this open.

- **rvproxy #111 — segment-split evasion (scope honesty).** Region redaction is
  stateless per-frame with no cross-frame reassembly; a secret split across two TCP
  segments is only partially masked, and an adversarial guest can split on purpose.
  Inherent to a gateway-side byte-stream redactor. Fine as a **best-effort**
  undeclared layer — but it is not authoritative. Declared-credential substitution
  stays in mvm's host-side TLS terminator (which reassembles). Keep claim-16
  (leak-gate) scope aligned with "best-effort, evadable."

- **rvproxy #105 — fail-open transform-skip (hardening).** `TransformPipeline`'s
  `AttachmentSummary` cache silently skips all transforms for any
  `(direction, attachment)` pair outside its 3 hardcoded slots. Benign today (only
  3 attachment constants exist, each used with its canonical direction), but a
  future attachment or non-canonical pairing would silently bypass transforms at
  the GUEST_SERVICE_EGRESS chokepoint. When mvm registers transforms, only use the
  cached slots; track #105 for the upstream fix.

- **#100 (slice 2) notes:** `Opened` is audited *after* the upstream connect, so a
  policy-allowed flow whose audit sink is down briefly establishes a real
  connection before teardown (no guest *data* is relayed; the policy gate is
  pre-connect, so not a claim-10 issue). `FlowEvent`s are **TCP-only** — UDP/DNS
  egress audit stays in the per-datagram `GuestEgressAuditSink`, so mvm's
  native-path audit must consume **both** sinks to match the bridge's coverage.

- **#101 (slice 3) note:** `rvproxy_flow_kills_total` counts kill *decisions*
  (frames dropped), not flows *torn down* — a kill on a SYN / already-closed /
  UDP frame increments the counter but tears down nothing. Correlate teardowns via
  `FlowClosed` events, not the counter.

## WS-2 entry conditions

WS-2 = port `gateway_bridge`'s `PlanFlowPolicy` deny-by-default + flow-audit onto
the native seams (`FlowEventSink` + the region-rule `secret-redaction-filter`
Mutator), prove identical verdicts vs the gvproxy splice through the WS-1.5 parity
gate, then delete the in-line splice + Plan-141 `on_packet` hooks and flip the
macOS default. Before starting:

1. **Pinned binary:** bump the parity lane's `RVPROXY_DEFAULT_REF` to an
   R2-complete rvproxy rev; WS-2 needs a released/pinned binary in mvm CI.
2. **`include_payload_bytes: false`** on the redaction filter (finding above).
3. **Consume both audit sinks** (`FlowEventSink` for TCP flow lifecycle +
   `GuestEgressAuditSink` for UDP/DNS) into mvm's chain-signed audit.
4. **Re-check the lane is unclaimed** — WS-2 had no mvm branch/PR/uncommitted edits
   as of 2026-06-15, but the rvproxy-building session also keeps a mvm-side
   `docs/r2-build-status-sync` worktree, so it may pick this up; confirm before
   starting to avoid a collision.

WS-3 (backend cutover: replace gvproxy/passt spawn with `rvproxy run --config`) and
WS-4 (`mvm net` verbs) follow WS-2.

## WS-2 phase-0 decision (2026-06-16)

The live WS-2 checklist (sub-slices 2a–2d) lives in Plan 193 §WS-2 (sub-slice 2a
landed via mvm #957). This section is the decision record + gap analysis behind it.

**Decision: Option A — split by concern.** rvproxy owns what lowers cleanly to static
config (deny-by-default, mandatory-deny CIDRs, L4 proto+port+CIDR, DNS allow-list) +
the flow-lifecycle audit export. mvm's **undeclared content-redaction stays in the
host-side TLS terminator** (where declared substitution already lives) — it sees
post-TLS plaintext, reassembles the stream (which also resolves the #111 segment-split
evasion), and keeps full-fidelity redaction with zero porting. The gateway
region-rule Mutator stays a thin placeholder-leak backstop. The splice still dies: its
policy/audit role → rvproxy, its content-redaction role → the terminator.

*Rejected:* (B) push mvm's redaction engine into rvproxy — unavailable to a
subprocess-consumed released binary without per-packet IPC (the complexity ADR-082
avoided); (C) accept reduced fidelity — unacceptable for a containment claim. The
gap is bigger than first thought: mvm's curated secrets are **regexes**
(`AKIA[0-9A-Z]{16}`, `sk-[A-Za-z0-9]{48}`) and PII is **regex + Luhn/IBAN checksum** —
neither expressible as rvproxy's `{prefix,terminator,mask,min_len}` region rules.

**Config-surface gaps (filed as rvproxy #118):**

| mvm primitive | rvproxy config | status |
|---|---|---|
| deny-by-default + CIDR allow/deny | `default_egress_deny` + `cidr_*` | ✅ |
| mandatory-deny (metadata/link-local/CGNAT/loopback) | inject as `cidr_denylist` | ✅ workaround (v6 moot — egress is IPv4) |
| L4 proto+port+CIDR | `policy.l4_allowlist` | ✅ **landed rvproxy #115** |
| FlowEvent export (audit re-feed) | `FlowEventSink` over dataplane-audit JSONL/UDS, fail-closed | ✅ **landed rvproxy #113** |
| region_rules in config | `[[transform]]` region rules | ✅ landed rvproxy #114 (low priority under Option A) |
| DNS suffix allow-list (upstream) | only `allow_dns_*` booleans | 🔴 **still open** (rvproxy #118; needed for DNS-sinkholing tenants, not a 2a/2b blocker) |
| placeholder-leak as FlowKill | redaction masks, can't kill on match | ⚠️ open (low — backstop) |

Both hard blockers (L4 #115 + FlowEvent export #113) merged to rvproxy `main`
overnight, plus my R2-review issues #105 (fail-open transform cache) and #111
(segment-split) — both CLOSED COMPLETED. **No rvproxy release/tag yet**, so the parity
lane pins a `main` rev via `RVPROXY_DEFAULT_REF`; a formal release is a cutover-time
concern. Remaining cross-repo dependency for full splice deletion (2d): the DNS
suffix allow-list, and lowering into `l4_allowlist`/host-side redaction so
`RvproxyPolicyGaps` reaches empty before the splice is removed.
