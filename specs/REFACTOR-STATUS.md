# Refactor status — rollup checklist

**Last updated: 2026-06-08**

> MAINTENANCE: keep this file current. Whenever you land, merge, or descope a
> workstream in any plan below, tick/strike the matching box here in the SAME
> change and bump the "Last updated" date. This is a hand-maintained rollup of
> the per-plan checkboxes in `specs/plans/` and `specs/SPRINT.md` — it is a
> quick index, not the source of truth. If it disagrees with a plan doc, the
> plan doc wins; fix this file.

## Plans

```
PLAN 121 — Crate consolidation (32→15)          ✅ DONE
PLAN 169 — Backend-agnostic agent RPC           ✅ DONE
PLAN 166 — QEMU Linux dev/test backend          ✅ DONE (Phase 2)
PLAN 165 — Sealed-prod interactivity (claim 15) ✅ DONE

PLAN 129 — Secrets / SigV4 substitution         🟡 ~95%
  [x] keyholder, resolver, binding store, `secret set`
  [x] host substitution endpoint (UDS + AF_VSOCK)
  [x] SigV4 canonical-request builder
  [x] in-guest substitution client + forward-proxy
  [x] guest↔host vsock transport, both directions   — PR #708/#709
  [x] workload env injection via RunEntrypoint proto — PR #711
  [x] e2e substitution over AF_VSOCK loopback        — PR #710
  [x] claim-13 audit (secret.substituted)
  [ ] forward-path signing integration
  [ ] guest-init wiring (host call-site + bin glue)
  [ ] Python/TS SDK toolchain integration
  [ ] real-microVM boot validation (KVM box)

PLAN 152 — Rust-native VZ supervisor            🟡 design locked
  [x] WS-A exit channel (vsock + PID-1 helper) — PR #698 (merged)
  [x] WS-B threading decision (serial queue) — PR #697
  [ ] WS-B the actual Swift→Rust rewrite (~1,450 LOC)
  [ ] WS-C snapshot/restore + fork
  [ ] WS-D nested KVM (/dev/kvm in guest)
  [ ] WS-E VZ-config hardening

PLAN 159 — vz-inspired macOS VZ DX               🔴 gated on 152
  [x] WS-5 E streamed exec (ExecEvent) — PR #712 (plan-172)
  [ ] WS-1 warm path / WS-2 checkpoints+fork (need 152 WS-B)
  [ ] WS-* remaining DX/UX layer

PLAN 124 — Lean guest agent                     🟡 ~65%
  [x] A1/A3 drop tokio+rtnetlink (-27 crates)
  [x] B universal agent in all images
  [x] C1 verity-sealed runtime overlay
  [x] D1.0/D1.1 schema SSOT
  [ ] D1.2/D1.3 SDK codegen
  [ ] E signed on-device config

PLAN 170 — Host lifecycle convergence           ✅ mvm-side done (density → mvmd)
  [x] WS-A reconcile-on-entry — PR #688 (merged)
  [~] WS-B idle-reaper mechanism — PR #696 (merged, no consumer)
  [~] WS-C pressure reaper — PR #701 (closed unmerged)
  [~] WS-D wake-on-request — owned by mvmd
  (WS-B/C/D density belongs to mvmd, not mvm — see plan-170 banner)

PLAN 126 — Dependency reduction                 🔴 ~10%
  [x] A1 re-baseline
  [x] B5 drop tokio from mvm-core (PR-1)
  [ ] B1/B2/B4 prune sigstore/opendal/aws-lc
  [ ] C1/D1 unify + lock gate

PLAN 153 — CLI directory split                  🔴 NOT STARTED
```

## Security claims

15/15 shipped, none regressed (`specs/claims/catalog.md`, gated by
`xtask check-claim-catalog`).
