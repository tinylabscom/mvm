# Prior-art review — an external agent-sandbox microVM runtime (2026-06)

**What:** a production-validated, open-sourced (June 2026) agent-sandbox
runtime for executing LLM-generated code. KVM microVMs, Rust /
Cloud-Hypervisor / RustVMM lineage, containerd shim-v2 integration,
E2B-compatible REST API. Single repo spanning what we split across
**mvm** (per-node VM lifecycle) **and mvmd** (fleet control plane:
scheduler, reverse proxy, multi-node orchestration). Linux/KVM/x86_64
only; QEMU dev-only; no macOS path. Apache-2.0. Referred to obliquely
here and everywhere per the no-competitor-names rule — do not name it
in any spec, branch, commit, or comment.

## Why it matters to us — convergence, not novelty

It independently arrived at the same core architecture we designed,
which is external validation that our bets are industry-correct:

- **microVM-per-workload, dedicated guest kernel, no shared kernel** —
  our ADR-001/002 thesis exactly.
- **Host-side egress gateway doing credential injection + domain
  filtering + access auditing, with a generated CA for TLS
  interception** — this is our Plan 129 end-to-end: claim 13 (the raw
  secret lives in the gateway and is substituted on outbound; it never
  enters the guest), claim 10 (default-deny egress), and Plan 129
  Stage 2 (per-VM name-constrained CA for TLS termination). Their
  `gen-ca.sh` + OpenResty is the same MITM-at-the-gateway shape we
  chose — and we are ahead: ours is destination-bound, time-bound,
  signed, `zeroize`d, and chain-audited; theirs reads like static
  header injection from gateway config.
- **CoW snapshot + fork for parallel exploration / warm pools** — our
  warm-pool + fork-snapshot line (Plans 118, 196; Vz saved-standby
  pool already landed; the fork prior-art audit in 148/157/175).

## What we took — exactly one thing

The only idea worth building **in this repo**: a **density +
concurrent-launch distribution benchmark**, landed as **Plan 118
Part C (PR-10c)**. Their headline numbers (per-instance host overhead
"<5 MB", "2000+ sandboxes / 96-vCPU host", concurrent-launch P95/P99 at
50–100 concurrency) flex two axes our existing probe (Plan 118 Part A /
Plan 119) does not measure: steady-state **footprint** and launch
**distribution under concurrency**. Those are precisely the axes the
warm pools exist to move, so we could not prove the pool's payoff or
state our own footprint/latency posture in committed numbers. PR-10c
reuses the Part A probe substrate, adds two report shapes, stays
read-only, and routes every boot through claim-8 admission — zero new
attack surface. See `specs/plans/118-supervisor-standby-pool-and-live-bench.md`
§"Part C".

## What we rejected — and why

- **OpenResty/Lua egress gateway.** Rejected even though it is
  production-grade. The egress gateway is our highest-value TCB
  component — it holds the **raw secrets** (claim 13) and the
  **name-constrained CA private key**. Moving substitution + policy
  into nginx+LuaJIT enlarges that TCB with a large C/JIT surface that
  (a) cannot `zeroize` secret bytes, (b) cannot share our typed
  `PlanFlowPolicy` lowering (Plan 193), (c) is not covered by `cargo
  deny`/`audit` (claim 7) or our fuzz harnesses, and (d) reverses
  ADR-082 (the in-house Rust gateway whose whole point is to own this
  seam in Rust). It fails the "no new blast radius" bar outright. The
  only place an off-the-shelf proxy is defensible is **secrets-free
  ingress routing** — which is mvmd's control plane, not this repo.
- **eBPF egress enforcer (their eBPF virtual-switch analogue).** New privileged
  in-kernel code, Linux-only, redundant with our nftables
  `install_default_deny`. If ever pursued, it folds behind the
  existing seam in Plan 141 (`on_packet`/`Verdict`) / Plan 193, not a
  standalone effort — and it can never be a cross-platform headline
  (it does not reach macOS/libkrun/vz).
- **Forking Cloud Hypervisor / RustVMM.** Conflicts with our standing
  no-vendor-fork stance and the keep-the-`VmBackend`-trait rule. We
  use stock Firecracker behind the trait.
- **E2B SDK wire-compatibility.** Genuinely useful as a de-facto
  agent-sandbox API surface, but it belongs in **mvmd's control
  plane**, not here. Tracked as an mvmd consideration, not an mvm plan.

## Claims posture (for the record)

They market "safe execution of any LLM-generated code" / "eliminating
container escape risks" with **no formal threat model, no verified
boot, no signed/audited execution plans, no content-addressed bundles,
no attestation, no CI-enforced claim ledger**. Our differentiation is
the provable, machine-checked security (ADR-002's numbered claims +
`xtask check-claim-catalog`), not raw speed. The one honest gap they
expose is that we have **no published latency/density numbers** —
which PR-10c exists to close.

## Pointers

- Bench / warm-pool home: `specs/plans/118-supervisor-standby-pool-and-live-bench.md`
- Egress credential substitution: `specs/plans/129-*`, ADR-082 (in-house Rust gateway), ADR-049/059
- Default-deny egress + claims: ADR-002 (claims 10, 13), `specs/claims/catalog.md`
- Fork/snapshot prior-art audit: Plans 148/157/175
