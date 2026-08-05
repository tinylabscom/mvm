# Audit — do the security claims hold on the backends we ship?

**Status:** Research note; first pass. No implementation commitment.
**Date:** 2026-08-02
**Owner:** mvm
**Method:** Ledger-first. Start from the `<!-- claims-catalog -->` table in ADR-001, resolve each lead against `main` at `a9fb158ca`, and record what was checked rather than what is believed. Every finding below names the file or command it came from.

## Why this exists

A run of plan-276 workstreams found **four** specifications that did not match the code: one workstream was already shipped and stronger than written, one rested on a structurally impossible premise, one had its premise backwards, one understated the problem. The conclusion is not that those plans were careless — it is that **`specs/` is not a reliable map of `crates/`**, so a readiness answer assembled by reading specs inherits the same error rate.

This pass therefore checks leads *against the tree*, and reports staleness in both directions — including where the code turned out to be in better shape than the notes claimed.

## Scope and honesty boundary

This is a **static** audit. It establishes what the code and gates say, not that a workload boots and runs under policy on any given host. Nothing here is live evidence, and no claim below should be read as "verified in production". Items needing a live witness are marked as such and are the largest remaining gap in the readiness picture.

Five leads were carried in. Two were **stale in the safe direction** — the code is better than the note. Two are real. One is a deliberate, contained decision rather than a defect.

## Findings

### F1 — `check-sdk-split` is a dead CI reference (confirmed)

`.github/workflows/ci-full.yml:140` runs `cargo run -p xtask -- check-sdk-split`. That subcommand does not exist:

```
Error: Unknown xtask: "check-sdk-split". Available: gen-man, check-adr-coverage, ...
```

It survives because `ci-full.yml` is `workflow_dispatch:` only — it never runs on a pull request or in the merge queue, so nobody has hit it. Any operator-triggered full-matrix run fails at that step.

Two consequences worth separating. The immediate one is a broken step. The structural one is that **`ci-full.yml` is not a safety net**: a gate placed only there is not enforced at all. `check-sdk-split` is currently the only such gate, so the exposure is bounded — but the lane's *shape* invites the mistake.

*Severity: low on its own; medium as a pattern. Certainty: high.*

### F2 — ADR-001's claim-10 prose describes a superseded architecture (confirmed)

ADR-001 §"Claim-10 coverage" states egress default-deny is enforced "at the host-side network chokepoint … Firecracker via nftables default-deny on the TAP, and libkrun via the gateway-bridge `PlanFlowPolicy`".

The code converged away from that. Both gates agree:

```
check-vsock-only-egress:    clean (29 files; the vmm/HVF workload path is NIC-free)
check-uniform-vsock-egress: clean (Firecracker + libkrun + HVF bind WorkloadRunner
                            runners; 8 driver file(s) spawn no egress endpoint)
```

A workload has no NIC, so there is no TAP to put nftables on. Enforcement is one per-VM vsock substitution endpoint spawned at a single site.

The mechanism is sound; the **document that auditors and reviewers read as the source of truth is wrong about how the load-bearing claim is enforced**. That matters more than a typical doc-drift: ADR-001 is what a reader consults to decide whether to trust the posture, and it currently describes controls that are not there.

*Severity: medium. Certainty: high.*

### F3 — "libkrun transient egress is AllowAll" is stale; the code is better than the note

The carried lead was that egress was enforced only on Firecracker, with libkrun transient runs effectively unrestricted. On `main` that is no longer true: `EgressGate` has `default_deny()`, resolves fail-closed (`Err(_) => Self::default_deny()`), and `check-uniform-vsock-egress` pins Firecracker, libkrun and HVF to the same single spawn site.

Recorded because a stale *pessimistic* note is its own hazard — it invites re-fixing something already fixed, which is exactly the duplicated-work failure this project has already paid for once.

*Severity: none (resolved). Certainty: high, static.*

### F4 — Claim 14 is numbered and Shipped; the note saying otherwise is stale

Carried lead: claim 14 (OCI image provenance) was promotion-pending and not in the numbered table. The ledger lists **14 · Shipped**. Claim 16 is the only `Preview` row.

*Severity: none (resolved). Certainty: high.*

### F5 — `trusted_build_egress()` is unrestricted, deliberately, and guarded only by prose

`mvm_contract::policy::network_policy::trusted_build_egress()` returns `Self::unrestricted()`. That is intentional and well-handled: it is one named, greppable constructor; cloud-metadata and link-local stay blocked by the always-on mandatory deny; a test pins that it is *not* the deny-all default; and the doc says **"Never use it for a workload (`mvmctl run`/`up`/`invoke`): those default to `deny_all`."**

The gap is the enforcement of that last sentence. Its callers are the builder/dev path (`builder_runner/runner.rs:135`, `libkrun_builder.rs:363`), which is correct — but **I found no gate that mechanically prevents a future workload path from calling it.** The protection is a doc comment plus review, for the one constructor that turns off the project's headline security claim.

This is the same shape as two defects already fixed this month: `verify_fetched_kernel` was correct and simply never called, and `resolve_kernel` handed out a bare path so nothing signalled a skipped check. A named-and-documented boundary with no mechanical enforcement is a boundary that holds until someone is in a hurry.

*Severity: medium. Certainty: medium — a gate may exist that I did not find; `check-trust-gradient` is adjacent but ledger-scoped, not caller-scoped.*

### F6 — Warm-pool standby is fail-closed by default (confirmed)

`supports_standby_pool()` reads a backend capability, and `standby_pool_defaults_are_fail_closed` pins the default to `false`. Consistent with the warm pool shipping disarmed.

*Severity: none. Certainty: high. Not audited: the four pre-flip blockers, which need live evidence.*

## What this pass did not establish

The honest limit. None of the above shows that a workload **boots and runs under policy** on any backend. Specifically unaudited:

- Live egress enforcement on each shipping backend (prior notes record live witnesses failing on both hosts; not re-checked here).
- The warm-pool pre-flip blockers, including the structural "restored child unauthorizable" item.
- Whether the prod image builds and boots on a clean host.
- Claims 1–9, 11–13, 15 beyond confirming their ledger rows and witnesses exist.

A static audit can show a control is *wired*. It cannot show it *holds*. Closing the readiness question needs a live witness per claim per shipping backend, which is a different exercise from this one.

## Ranked

1. **F5** — an unrestricted-egress constructor enforced by prose alone. Highest severity of the real findings, and the cheapest to close: a gate asserting only builder/dev call sites reach it.
2. **F2** — the security source of truth misdescribes how the headline claim is enforced. Cheap to fix, and it is what a reviewer reads.
3. **F1** — a dead CI step, plus the broader point that `ci-full.yml` gates nothing automatically.
4. **F3/F4/F6** — no action; recorded so the stale notes stop generating phantom work.

## Method note for the next pass

Two of five carried leads were stale, both in the safe direction. Prior findings age badly here, and re-verification is cheaper than the duplicated work that follows from trusting them. Check the tree first, every time.
