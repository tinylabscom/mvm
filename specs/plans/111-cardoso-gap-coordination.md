# Plan 111 — Cardoso gap coordination

**Source post:** Luis Cardoso, [A field guide to sandboxes for AI](https://www.luiscardoso.dev/blog/sandboxes-for-ai), 2026-01-05.
**Companion docs:** [`specs/research/sandboxes-for-ai-cardoso-gap-analysis.md`](../research/sandboxes-for-ai-cardoso-gap-analysis.md) (raw audit) · [`specs/adrs/002-microvm-security-posture.md` §"Appendix: Cardoso minimum-viable-policy checklist"](../adrs/002-microvm-security-posture.md) (per-claim mapping).

## Goal

Make mvm's public posture audit-cleanly against Cardoso's
boundary × policy × lifecycle rubric **by amending existing plans
and ADRs** rather than standing up a parallel tracker. The raw
research lives at `specs/research/`; the per-claim checklist lives
in ADR-002. This plan is the coordination tracker for the
follow-up edits.

## Why this is a coordination plan, not a new feature plan

A first-pass analysis assumed many gaps were unowned. A verification
pass found that most of them already have owning plans or ADRs.
Each Cardoso concern maps onto an existing target:

| Cardoso concern | Owning plan / ADR | Verified status |
|---|---|---|
| Default-deny egress | **ADR-002 claim 10** + Plan 34 + Plan 79 | CI-claimed via `policy_default_is_deny_all` + `test_resolve_network_policy_default_is_deny_all`. Cardoso's specific holes (DNS, vsock carve-out, broker channels) need audit against the existing gate. |
| VM-level snapshot / restore | **Plan 65** (`VmBackend::snapshot/restore` trait) | Trait scaffolded; cross-claim interactions not enumerated. |
| Paused-pool / warm-pool | None (Plan 43 is in-guest warm-process pools — different layer) | True gap. |
| Resource limits in `ExecutionPlan` (timeout / PID) | **Plan 37** + ADR-041 | `resources` field scaffolded; `timeout_seconds` / `pid_limit` not populated. |
| GPU stance | **ADR-002 §"Per-backend tier matrix"** | Posture allows Cloud Hypervisor as Tier-1 peer for VFIO / GPU. No backend ships VFIO today. Treated as future; no current GPU dependency. |
| Cold-start measurement | **Plan 74** (already names "measured cold-starts") | Named; no benchmark lane yet. |
| README workload-shape + mvmctl/mvmd split | None (README) | True gap. Docs work. |
| Plan 104 framing as policy-proxy | **Plan 104 + ADR-059 + ADR-049** | Claim 12 + claim 13 already implement binding-gated dispatch + no-raw-secret broker — the Cardoso "policy proxy" framing is largely already true. One-paragraph framing tweak. |
| TCB inventory | Distributed across ADR-002 + ADR-055 + ADR-061 | Consolidation into ADR-002 is the work. |
| Threat-model vocabulary | **ADR-002 §"Threat model"** | Verified: not in flight in any active worktree against this section (`mvm-security-threat-model` is 10+ commits stale; `mvm-threat-model-02` adds a STRIDE doc for the broker, does not touch ADR-002's threat-model section). Safe to proceed. |
| **CLAUDE.md stale claim list** | **CLAUDE.md §"Security model"** | Lists 10 claims; ADR-002 has 13. CLAUDE.md claims 1–8 align; CLAUDE.md claim 9 (app-dep) = ADR-002 claim 11; CLAUDE.md claim 10 (OCI) not yet a numbered ADR-002 claim. Reconciliation needed. |

That table is the actual work plan. Workstreams below convert each
row into a concrete edit target.

## Non-goals

- Standing up a parallel security-claims taxonomy. ADR-002 is the
  source of truth; CLAUDE.md is the summary. This plan reconciles
  them.
- Reopening the multi-tenant scope decision. ADR-002 puts
  multi-tenant guests out of scope; mvmd owns multi-tenancy. This
  plan adds a README signal so external readers see the split up
  front.
- Hardware-backed attestation (SEV-SNP/TDX). ADR-002 already
  excludes this. Aligned with Cardoso's framing; no work here.
- Wasm / V8 isolate boundary. Cardoso routes "tool calling" to
  those boundaries; not our shape.
- Shipping GPU support now. ADR-002 allows the posture (Cloud
  Hypervisor as Tier-1 peer); we don't depend on GPU today.
  Workstream D is filed as future / deferred.

## Security implications and cross-claim interactions

Surfaced during the analysis; preserved here because they remain
binding for the sub-plans below. Each item names the workstream
that must own it.

- **Snapshot/restore × five other claims** — entropy reuse;
  claim 8 admission-vs-continuation semantics; claim 3 dm-verity
  re-check at restore; claim 7 reproducibility carve-out; audit
  chain branching policy. *Owner: Workstream B (Plan 65
  amendment).*
- **GPU passthrough × claim 11** — model weights as deps. If/when
  Workstream D is reopened, claim 11 either extends to cover model
  weights or a new claim is added. *Owner: Workstream D (deferred).*
- **Egress claim 10 has three subtle holes** — DNS as
  side-channel; Plan 104 broker channels as covert egress; vsock
  control plane as egress requiring explicit carve-out. *Owner:
  Workstream A.*
- **Resource-limit additions are hard backwards-incompatibility** —
  mandatory `timeout_seconds` / `pid_limit` invalidates every
  existing signed plan. Per memory
  `feedback_no_backcompat_first_version` that is policy; flag in
  the PR description. *Owner: Workstream C.*
- **Threat-model vocabulary needs a fourth category for deps** —
  Cardoso's hostile / semi-trusted / trusted misses "audited
  semi-trusted." *Owner: Workstream G.*
- **Disclosure trade-off** — publishing the gap analysis + the
  Cardoso checklist + the TCB inventory is a deliberate disclosure;
  ADR-002 and the claim table are already public. State this in
  the plan rationale; do not soften.
- **mvmd alignment before publishing the multi-tenant signal** —
  Workstream F must sync with mvmd maintainers (or read current
  mvmd ADRs) before the README rewrite ships.

## Workstreams

Every workstream names its **target file** so this remains a
coordination tracker rather than a parallel tracker.

### A — Default-deny egress: close Cardoso's three holes, sync CLAUDE.md

> **Superseded by [Plan 142](142-network-no-bypass-egress-audit.md)** (refactor
> sequence) — the egress-hole remainder (DNS / broker / vsock carve-out) plus the
> libkrun implicit-vsock/TSI no-bypass audit are now owned there. The CLAUDE.md
> 13-claim sync below already landed; the rest of this coordination tracker is
> unaffected.

Target: `specs/plans/34-egress-l7-proxy.md` (amend) +
`specs/plans/79-*` (extend if needed) + `CLAUDE.md` (sync claim
list).

- [ ] Read ADR-002 claim 10 evidence (`policy_default_is_deny_all`,
      `test_resolve_network_policy_default_is_deny_all`) to confirm
      what's actually gated.
- [ ] Audit DNS handling: does the default-deny policy cover UDP/53,
      or does it slip through?
- [ ] Audit Plan 104 broker channels: are `host.*` vsock services
      treated as egress for policy purposes? If not, document why
      (binding-gated dispatch is the answer per claim 12) or extend
      the CI gate to assert.
- [ ] Confirm vsock control-plane port allowlist is explicit (W1.3
      per CLAUDE.md is the existing gate).
- [ ] Extend Plan 34's CI lane (if missing) so a default plan
      refuses DNS to non-allowlisted resolvers, not just TCP.
- [x] Sync CLAUDE.md §"Security model" with ADR-002's 13-claim
      table. *Landed in this plan's PR.*

### B — VM-level snapshot/restore: amend Plan 65 with cross-claim interactions

Target: `specs/plans/65-*.md` (existing snapshot/restore trait
plan).

- [ ] **Decision** to make before amending: ship snapshot on
      Firecracker workload microVMs, drop it, or defer it. Default
      recommendation: ship, with the security sub-bullets below.
- [ ] Amend Plan 65 with §"Cross-claim interactions" enumerating:
      entropy reseed at resume (virtio-rng / vsock entropy delivery
      before vCPU unfreeze); claim 8 admission policy
      (continuation-within-G4 vs re-admission; default reject if
      G4 expired); claim 3 dm-verity re-check or snapshot-hash
      verification at restore; claim 7 reproducibility carve-out
      (workload-runtime non-determinism is expected under restore);
      audit chain branching policy (default reject;
      `verify_audit_chain` learns to reject diverged chains).
- [ ] Decide warm-pool stance in the same plan or carve it out as a
      Plan 65 follow-up.

### C — Resource-limit completeness: extend Plan 37 + ADR-041

Target: `specs/plans/37-*.md` + `specs/adrs/041-signed-audited-execution-plans.md`.

- [ ] Audit `crates/mvm-plan/src/plan.rs` to confirm the `Resources`
      field shape today.
- [ ] Extend Plan 37 §3.3 with mandatory `timeout_seconds` and
      `pid_limit` fields; the planner errors if absent.
- [ ] Amend ADR-041 schema table with the new fields. The
      backwards-incompatibility is documented in the PR description;
      no migration shim per memory
      `feedback_no_backcompat_first_version`.
- [ ] Wire enforcement: cgroup PID cap on Firecracker; document
      Vz / libkrun parity (or non-parity) per backend.
- [ ] Update the ADR-002 Cardoso checklist row for "resource
      limits" from **partial** to **pass** once these land.

### D — GPU stance: deferred future item

**Status: future / deferred.** No current GPU dependency.
ADR-002 §"Per-backend tier matrix" already lists Cloud Hypervisor
as Tier-1 peer "selected over Firecracker when a workload needs
VFIO / GPU passthrough or virtio-fs." The posture is allowed; we
don't ship the backend today and won't unless a user need surfaces.

Recorded so it doesn't get lost; not actively scheduled.

If this is ever reopened:

- Verify ADR-013 §"Cloud Hypervisor" and Plan 54 status (Plan 54's
  "door closed" framing may be stale relative to ADR-002 line 307).
- Pick the implementation path: Cloud Hypervisor + VFIO; hybrid
  "GPU service outside mvm"; or silent gap.
- **Prerequisite (not a follow-up):** extend claim 11 (app-dep
  audit) to cover model weights, or add a claim 14 for "model
  assets sealed and attestation-checked." Either is fine; pick
  in the reopening plan.
- Update ADR-055 cross-backend invariants with the GPU-passthrough
  isolation requirements (IOMMU, device firmware trust posture).

### E — Cold-start measurement: extend Plan 74

Target: `specs/plans/74-*.md`.

- [ ] Add a perf lane that measures `mvmctl up <image>` → guest
      PID 1 active per backend (libkrun macOS, Firecracker Linux,
      Vz macOS 26+ AS).
- [ ] Publish numbers in README + docs.
- [ ] Re-measure after Workstream B if snapshot ships.

### F — README workload-shape + mvm/mvmd split

Target: `README.md` (no existing plan home; smallest workstream).

- [ ] Rewrite README first paragraph: name target shapes
      (devbox + code-interpreter); name pending shape (RL — depends
      on Workstream B); name non-goals (tool calling = Wasm;
      GPU = deferred per Workstream D); state host trust assumption
      (host trusted, workload bytes hostile or model-generated);
      name mvmctl single-tenant vs mvmd multi-tenant split.
- [ ] Sync with mvmd maintainers (or read current mvmd ADRs/specs)
      before publishing the multi-tenant signal.

### G — Threat-model vocabulary: proceed (no in-flight conflict)

Target: `specs/adrs/002-microvm-security-posture.md` §"Threat
model."

Verified: `mvm-threat-model-02` adds a STRIDE doc for the host
services broker; does not touch ADR-002 §threat model.
`mvm-security-threat-model` is 10+ commits stale and effectively
abandoned. Safe to proceed.

- [ ] Add a short section to ADR-002 §"Threat model" adopting
      Cardoso's hostile / semi-trusted / trusted vocabulary plus
      an explicit fourth category for "audited semi-trusted"
      (pinned + SBOM + attestation + CVE-scanned dependencies per
      claim 11). State: workload bytes hostile, deps audited
      semi-trusted, host trusted, multi-tenant guests out of scope.

### H — Plan 104 framing: one-paragraph Cardoso citation

Target: `specs/plans/104-*.md` narrative + `specs/adrs/059-*.md`
§Discussion.

- [ ] Claim 12 + claim 13 already cover the binding-gated dispatch
      + no-raw-secret properties. Add one paragraph to Plan 104
      narrative and ADR-059 §Discussion explicitly naming the
      connection to Cardoso's policy-proxy / brokered-syscall
      pattern. No code change.
- [ ] If we want explicit per-request scope-check in
      `host.secrets.v1` beyond what binding-gating already
      provides, add a follow-up bullet to Plan 104 W5; otherwise
      close.

### I — TCB inventory: consolidate into ADR-002

Target: `specs/adrs/002-microvm-security-posture.md` (new
§"Trusted computing base inventory" — cross-links to ADR-055 +
ADR-061).

- [ ] Add a §"Trusted computing base inventory" table to ADR-002
      enumerating libkrun (C), libkrunfw kernel, passt / gvproxy
      (C / Go), Firecracker (Rust), guest kernel, host kernel,
      `mvm-libkrun-supervisor`, `mvm-supervisor`,
      `mvm-guest-agent`, vsock host proxy, `mvm-builder-init`,
      dm-verity sidecar, host signer, audit emitter. Each row:
      language, review status, fuzz coverage, upstream tracking.
- [ ] Cross-link from ADR-055 §"New untrusted-input surfaces" and
      ADR-061 §"Implementation choices."

### J — Persist analysis + checklist + this plan

Target: `specs/research/sandboxes-for-ai-cardoso-gap-analysis.md`
+ `specs/adrs/002-microvm-security-posture.md` §"Appendix:
Cardoso minimum-viable-policy checklist" + this file
(`specs/plans/111-cardoso-gap-coordination.md`).

- [x] Write `specs/research/sandboxes-for-ai-cardoso-gap-analysis.md`.
- [x] Append §"Appendix: Cardoso minimum-viable-policy checklist"
      to ADR-002.
- [x] Write this plan at `specs/plans/111-cardoso-gap-coordination.md`.

## Build sequence

1. **J + part of A** (this PR) — persist the research note, the ADR-002
   appendix, this plan, and the CLAUDE.md security-model sync.
2. **A remainder** — audit Cardoso's egress holes (DNS, broker, vsock
   carve-out) against the existing claim-10 CI gate; extend Plan 34
   if anything is missing.
3. **C** — extend Plan 37 + ADR-041 for timeout / PID. Small.
4. **G** — Cardoso threat-model vocabulary in ADR-002.
5. **H + I + F** — docs-only sweeps. Can parallelize.
6. **E** — cold-start numbers via Plan 74.
7. **B** — snapshot decision + Plan 65 amendment.
8. **D** — deferred future. Reopen only if a GPU workload need
   surfaces.

## Verification

- After J: `ls specs/research/` shows the new file; ADR-002 has the
  appendix; this plan exists at `specs/plans/111-…md`; CLAUDE.md
  §security claims reflects ADR-002's 13-claim table.
- After A remainder: CI exercises DNS in the default-deny check;
  broker channels and vsock control plane are documented as
  carve-outs.
- After C: every `ExecutionPlan` carries timeout + PID limits or
  documents per-backend exception.
- After all docs-only workstreams: a reader handed Cardoso's post,
  ADR-002, the research note, and this plan can answer his
  three-question model about mvm.

## Success criteria

- [x] CLAUDE.md §"Security model" reflects ADR-002's 13 claims
      with correct numbering. *Landed in this PR.*
- [x] ADR-002 has §"Appendix: Cardoso minimum-viable-policy
      checklist." *Landed in this PR.*
- [x] `specs/research/sandboxes-for-ai-cardoso-gap-analysis.md`
      exists and is cited from ADR-002. *Landed in this PR.*
- [ ] ADR-002 has §"Trusted computing base inventory" appendix
      (Workstream I).
- [ ] README first paragraph names target shape + host trust
      posture + mvmctl/mvmd split (Workstream F).
- [ ] Plan 65 §"Cross-claim interactions" enumerates the five
      snapshot security implications (Workstream B).
- [ ] Snapshot decision made and reflected (Workstream B).
- [ ] At least one published cold-start number per backend
      (Workstream E).
- GPU / Cloud Hypervisor decision is *deferred* (Workstream D);
  not a blocking success criterion.
