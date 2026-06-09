# Refactor status — rollup checklist

**Last updated: 2026-06-09**

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

PLAN 129 — Secrets / SigV4 substitution         🟢 declared substitution + undeclared egress redaction landed (box-validated); SDK-free transparent-terminator core landed (#735), FC wiring + e2e next
  [x] keyholder, resolver, binding store, `secret set`
  [x] host substitution endpoint (UDS + AF_VSOCK)
  [x] SigV4 canonical-request builder
  [x] in-guest substitution client + forward-proxy
  [x] guest↔host vsock transport, both directions   — PR #708/#709
  [x] workload env injection via RunEntrypoint proto — PR #711
  [x] e2e substitution over AF_VSOCK loopback        — PR #710
  [x] claim-13 audit (secret.substituted)
  [x] retire dead in-guest ADR-049 scaffolding       — PR #713
  [x] per-VM substitution-endpoint moat (mvm-hostd)  — PR #715
  [x] QEMU spawns endpoint at boot, fail-closed      — PR #717
  [x] invoke injects HTTP_PROXY+placeholders; guest forward proxy — PR #718
  [x] on-box endpoint validation: real AF_VSOCK + real encrypted store
      (placeholder mint, substitution success, claim-12 refuse) — 2026-06-08
  — SDK-free egress (transparent terminator) · direction 2026-06-08 · branch feat/plan-129-egress-terminator · draft PR #735 · plan: specs/notes/plan-129-stage1b-2-transparent-terminator-plan.md ("Resume state")
  [x] SDK secret() type/hosts + ADR-049 retire             — PR #722/#723
  [x] passt-redirect feasibility PoC (nft OUTPUT + SO_ORIGINAL_DST) — GREEN on box
  [x] terminator core (orig_dst, request parse, handler, reader) — 4 commits, reviewed
  [ ] terminator listener + EndpointConfig wiring          — Task 4 (Linux)
  [ ] passt --runas + scoped nft redirect at launch        — Task 5 (Linux)
  [ ] box e2e: generic curl http, SDK-free, audited        — Task 0/6
  [ ] Stage 2: name-constrained CA + https termination     — ADR-006
  [x] Python `mvm.secret(type=,hosts=)` egress surface + retire `_runtime.py` — PR #722
  [x] TS `secret()` egress + retire `runtime.ts` + docs .mdx  — PR #723
  [x] secret-egress example workload (examples/python/secret-egress)
  [x] Phase E: undeclared secret/PII egress redact-to-XXX detector
      (RedactingSubstitution mask-and-continue; PiiRedactor/SecretsScanner
      redact()) wired always-on into the gateway bridge — PR #733
  [ ] local secret-workload launch via admission flow (compile refuses managed
      refs → deploy/plan path; the user-facing local boot gap) — plan 129
  [ ] full guest-VM boot e2e (depends on the above) — runbook in plan 129
  [ ] forward-path signing integration (SigV4)        — DEFERRED (user)

PLAN 152 — Rust-native VZ supervisor            🟢 native objc2; no Swift
  [x] WS-A exit channel (vsock + PID-1 helper) — PR #698 (merged)
  [x] WS-B threading decision (serial queue) — PR #697 (merged)
  [x] WS-B Swift→Rust rewrite (boot/vsock/control/snapshot/flow-audit) — PR #700 (merged)
  [x] WS-B parity gate (#703) → Rust-only after Swift deletion (plan-174)
  [x] WS-B finalize: resolver→Rust bin + DELETE Swift crate — plan-174
  [x] WS-E VZ-config hardening (validateSaveRestore, MAC pin) — folded into #700
  [ ] WS-C fork primitive (snapshot/restore done in #700) — separate workstream
  [ ] WS-D nested KVM (/dev/kvm in guest) — separate workstream
  NOTE: Swift control socket self-deadlocked on async VZ ops; Rust fixes it
  (ADR-056 addendum). Deferred: VzIngest/mvm-vz-drainer dead-code sweep.

PLAN 159 — vz-inspired macOS VZ DX               🟡 152-independent slice shipped
  [x] WS-3 mvmctl sign + doctor signing — PR #667 (plan-168)
  [x] WS-5 C shared --json (cache/network/snapshot/audit) — PR #667
  [x] WS-5 B session --continue/--resume/--ephemeral — PR #667
  [x] WS-4 resumable + honest-cost dev-image download — PR #667
  [x] WS-5 E streamed exec (ExecEvent) — PR #712 (plan-172)
  [x] WS-5 E follow-up: enforce exec timeout_secs — plan-173
  [ ] WS-1 warm pool / WS-2 checkpoint+fork  (gated on 152 WS-B)
  [ ] WS-5 D verb renames; curl|sh installer; --json remainder
  [ ] signed delta-image distribution (unowned — needs a home)

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

PLAN 123 — Network / storage / warm-start        🟢 Phase A done; B done; C1+C4 done; C2/C3 gated
  [x] Phase A claims-gated lift (A1/L1, A2, A3, A4, L3-A)
  [x] A2/A4 per-tenant enforce: libkrun PlanFlowPolicy deny-by-default
      (mirrors FC install_default_deny) + per-tenant DnsSinkholeScan
  [x] L3 slice B — workload site honors MVM_NETWORKING (#664)
  [x] L2 microvm_nix egress — DECIDED: QEMU is mvm-only dev/test (Tier 2),
      no enforcement; option (a) VmStartConfig plumbing deferred to a future
      promotion. Documented in ADR-002 + CLAUDE.md.
  [x] Phase B StorageProvider local/encrypted(macOS)/CAS/snapshot + MountProvider+S3
  [x] Phase B Linux LUKS2 arm (#729, live-verified on Linux VM) + S3 coverage
      S3-free (#732: from_s3_config validation + LocalFileSystem sync)
  [x] Phase C PostRestore host sender (#734) — the warm-start prerequisite
  [x] C1 SnapshotCapability enum + per-backend disposition
  [x] C4 warm-start operation seam: typed WarmStartError (ADR-053 hint) +
      SnapshotCapability::{label,satisfies} + fail-closed VmBackend::warm_start
      default; libkrun disk-only (SnapshotUpper clone of golden rootfs);
      doctor warm-start matrix + Linux NBD/HugeTLB substrate probe
  [ ] C2 Firecracker live-memory fast-resume — carved out → Plan 175
  [ ] C3 Vz save/restore (macOS 26+) — owned by Plan 152 WS-C
  [ ] C4 warm-start CLI/RPC wiring — carved out → Plan 175 (rides C2)

PLAN 175 — Firecracker live-memory warm-start    🔴 NOT STARTED (live-KVM-gated; Plan 123 C2 carve-out)
  [ ] T1 VMGenID delivery on PostRestore (token payload + GenIdReseeder dispatch)
  [ ] T2 UFFD/NBD/hugepages fast-resume substrate (diff snapshot + lazy paging)
  [ ] T3 SIGUSR1 "primed" ready-barrier for a deterministic warm base
  [ ] T4 FirecrackerBackend::warm_start override + mvmctl verb + agent_ping e2e
  (Vz=152 WS-C; libkrun disk-only done #741; reflink clone = 123 C4 follow-up)

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
