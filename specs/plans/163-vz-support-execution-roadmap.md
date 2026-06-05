# Plan 163 — Apple VZ support execution roadmap & sequencing

> **Status (2026-06-05):** Tracking/sequencing plan — it doesn't add new
> capability, it orders the already-written VZ plans into build sessions
> so the sequence isn't lost across sessions. Update the checkboxes as
> each lands.
>
> **Numbering:** 163 was free at write time (`main` tops at 162, no open
> PR claims a plan number). Re-confirm before merge — `check-spec-numbers`
> is a Lint gate.

## Context

A 2026-06-04/05 research + brainstorm thread set the Apple
`Virtualization.framework` (VZ) direction and produced/updated a cluster
of plans. Decisions (full record in memory `project_vz_strong_support_direction`
+ the docs below):

- **Drop Swift, go Rust-native `objc2`** for the VZ supervisor, kept as a
  separate per-VM codesigned binary (entitled-TCB ⇒ *process* separation,
  not Swift). External projects were studied as **inspiration, never a
  dependency**; Apple's Swift `Containerization` framework was declined.
- **152 ↔ 141 reconciled** (ADR-064 §8): 141 keeps its backend-agnostic
  packet-observer core (libkrun + Firecracker); **Vz `payload_tap` rides
  Plan 152** (Rust owns device + bridge in-process, no fd-handoff).
- **152 WS-D ↔ 147 reconciled**: nested-virt `/dev/kvm` is the *native*
  provider on M3+/macOS-26; **Lima (147) stays the portable/CI provider**;
  both register behind one Firecracker-E2E selector. Complementary.
- **Host-service reach** (Plan 104): brokered `host.fetch.v1` /
  `host.endpoint.v1`, never raw NAT.

Landed to `main` this thread: PR #590 (152, 159, 104 edits, gap analysis),
PR #594 (152 WS-D ↔ 147 reconciliation).

This plan records the **execution order**: which plan is built in which
session, what gates it, and whether a session is *build* or *plan-first*.

## Execution sequence (one unit ≈ one session)

Ordered by leverage + readiness. Highest value that's unblocked first.

- [ ] **S1 — Plan 141 core (BUILD). Unblocked now.**
      Backend-agnostic packet-observer core (`on_packet`/`Verdict`/
      etherparse) for **libkrun + Firecracker** — the egress-observer /
      redaction capability. Depends only on Plan 113 (merged); **not** on
      the 152 rewrite. Close 141's Q8 (`Modify` failure modes) + Q9
      (per-direction observers) via a short brainstorm, then writing-plans
      → TDD. No Vz changes (that's S3). Highest near-term value.
- [ ] **S2 — Plan 152 WS-A (BUILD). Gates satisfied — unblocked.**
      Guest `/init` exit-code → `poweroff -f` parity (fixes the
      function-workload reboot; the exit channel is vsock). Small, concrete
      — implement directly with TDD. Gate: Plan 120 (`core_demo_e2e`)
      green ✓ and Plan 134 (artifact model) slice-1 merged to main ✓
      (`a57f2548`) — sequenced after it, now landed.
- [ ] **S3 — Plan 152 WS-B (PLAN FIRST, then build).**
      The Rust-`objc2` VZ supervisor rewrite — a separate per-VM
      codesigned `[[bin]]` in `mvm-vm-host`, sibling to
      `mvm-libkrun-supervisor`. Reuses ~70% shared Rust
      (framing/config/audit/codesign); the new chunks are vsock
      multiplexing + objc2 lifecycle + in-process Vz `payload_tap`
      (absorbs 141's Vz arm). **Security-sensitive rewrite of a shipped
      component → give it its own writing-plans session** (tracer-bullet:
      scaffold bin → boot VM → vsock round-trip → each control verb →
      snapshot → **parity matrix** → delete Swift), *then* TDD. WS-E
      (config hardening) folds in here.
- [ ] **S4 — Plan 152 WS-D (SPIKE).** Nested-virt `/dev/kvm` capability
      probe + Firecracker-in-VZ spike (M3+/macOS-26). If it holds,
      register it behind Plan 147's `/dev/kvm`-provider selector (Lima the
      fallback). Lightweight; can interleave with S3.
- [ ] **S5 — Plan 159 DX (BUILD, later).** vz-inspired DX — warm runtime
      pool (keyless launcher, mvmd-routed), tiered checkpoints + fork,
      `mvmctl sign`, acquisition DX. **Depends on Plan 152.** Cross-refs
      Plans 157/148/140/147 (owns only the additive slice). Pull from
      there when 152 is landing.

## Gate / dependency map

| Unit | Depends on | Gate state (2026-06-05) |
|---|---|---|
| S1 — 141 core | Plan 113 (merged) | **ready** (close Q8/Q9 first) |
| S2 — 152 WS-A | Plan 120 green; Plan 134 | **ready** — 120 green ✓; Plan 134 slice-1 merged to main ✓ (`a57f2548`) |
| S3 — 152 WS-B | S2; ADR-064 §8 reconciliation | plan-first; after S2 |
| S4 — 152 WS-D | S3 (Rust supervisor sets the flag); M3+/macOS-26 | spike anytime; needs S3 to land |
| S5 — 159 DX | Plan 152; Plans 157/148/140 for primitives | after 152 |

## Build-vs-plan rule (why S1/S2 build but S3 plans first)

- **Small, well-scoped workstream → implement directly** (S1 core, S2 WS-A).
- **Large, security-sensitive rewrite of a shipped component → render a
  full implementation plan first** (S3 WS-B), then build. Implementing a
  supervisor rewrite straight off a checklist risks a half-migrated,
  security-sensitive component.

## Guardrails (apply to every unit)

- Never regress claims 1–14; no SSH into guests; observer code is
  host-allowlisted, never tenant-shipped (ADR-064 §7).
- External VZ projects are inspiration only — **no third-party VZ crate as
  a dependency**; Apple Swift `Containerization` framework declined.
- Refer to external repos obliquely in all repo text (naming policy).

## References

- `specs/plans/152-rust-native-vz-and-init-lifecycle-parity.md` — supervisor
  migration + `/init` parity + nested-virt + config hardening (S2/S3/S4).
- `specs/plans/159-vz-inspired-macos-dx.md` — DX build-out (S5).
- `specs/plans/141-vz-payload-tap-and-rust-owned-shuffle.md` — backend-agnostic
  observer core (S1); Vz arm moved to 152.
- `specs/plans/147-lima-test-backend-and-fc-e2e-parity.md` — Lima provider,
  complementary to WS-D.
- `specs/plans/104-host-services-broker.md` — brokered host-service reach.
- `specs/adrs/064-network-provider-trait.md` §8 — the 152↔141 decision record.
- `specs/research/on-device-vz-sandbox-gap-analysis.md` — the prior-art research.
- Memory `project_vz_strong_support_direction` — direction + reconciliation log.
