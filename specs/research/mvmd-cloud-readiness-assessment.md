# mvmd cloud-readiness — security assessment & path to monetizable production

**Status:** Research (handoff)
**Date:** 2026-07-01
**Audience:** engineering partner picking up the cloud-tier security work
**Related:** `specs/notes/mvm-client-facade-design.md` (the client facade this sprint started from), ADR-002 (local security posture), `specs/adrs/104-cloud-control-plane-trust-boundary.md` (cloud trust boundary — the superset threat model this assessment motivates)

## TL;DR

The bones are strong. `mvmd` is a real distributed control plane (~390K LOC, 14 crates,
1,700+ tests, coordinator + per-node QUIC agents, per-tenant L4 proxy/TLS/rate-limiting,
scheduler, metering→Stripe). It is **not** a scaffold.

The problem is not missing components — it is the recurring gap between **built** and
**wired**. The multi-tenant *enforcement gates* are designed and, in the latest sprint,
fully implemented — but not connected to the request path. The most recent example (IAM,
PR #161) is a production-grade authorization + row-level-security system that is ~100%
built and ~0% integrated.

The single missing discipline that would fix this class of problem: mvm's
**claim → named witness → CI gate** ledger, ported to the cloud tier. Today nothing fails
CI when a security control ships un-enforced.

## Business context and why the threat model inverts

- **OSS-local (`mvm`)** — the user owns and trusts the host. Threat: a workload escaping onto
  *their own* machine. ADR-002 encodes this: *single trusted local host, one guest = one
  workload, malicious host out of scope.* The 15 CI-enforced claims all defend this boundary.
- **Paid-cloud (`mvmd`)** — *we* own the host; the user is untrusted; **many** untrusted
  tenants share *our* hosts. Threat: tenant→host and tenant→tenant escape.

The cloud product must therefore solve exactly the two things ADR-002 declares **out of
scope**: multi-tenant guests, and an untrusted-host relationship from the tenant's view.
"Keep every guarantee, even stricter" is the right goal, and concretely it means the cloud
tier needs a **superset** of the local posture: the 15 claims **plus** cross-tenant
isolation **plus** untrusted-tenant admission. The 15 claims are necessary, not sufficient.

## The client facade (where this sprint began)

`specs/notes/mvm-client-facade-design.md` proposes a `MvmClient` trait with two impls —
`LocalBackend` (in-process mvmctl) and `GatewayBackend` (REST → mvmd-gateway, local sidecar
or remote fleet). It is a good architecture move and worth building. But it is the thin
enabling layer, not the security story: it adds no trust of its own and depends entirely on
the server enforcing. See "Implication for the facade" below — its remote phase must be
gated on the enforcement work landing.

## Current state of mvmd

### Genuinely solid (implemented and enforced)

- HMAC-SHA256 API-key auth with per-key caching, expiry warnings (`auth/middleware.rs`).
- Per-tenant L4 proxy isolation — tenant identity derived from the **listen socket**, not
  client headers (`mvmd-proxy`, SECURITY_MODEL.md).
- Per-tenant TLS termination with hot cert reload + ACME (Sprint 139).
- Per-tenant rate limiting + wake-amplification circuit breaker.
- VM-level hardening: Firecracker + jailer + seccomp + cgroups (`mvmd-runtime`).
- Working scheduler with capacity/constraint/cost scoring and node-failover.
- Metering pipeline → Stripe usage records (functioning meter, not yet a billing system).

### The IAM sprint (PR #161 / Sprint 137) — built ~100%, wired ~0%

New crates `mvmd-iam` + `mvmd-iam-storage` landed a production-grade authz foundation:

- **Policy engine** (`mvmd-iam/src/policy/`): RBAC + ACL evaluation, Deny-wins precedence,
  effective-role computation from memberships (`rbac.rs`, `acl.rs`, `effective.rs`).
- **Domain model**: organizations, teams, workspaces, principals, API keys, ACL grants,
  audit_log; Postgres + libSQL backends; dbmate migrations.
- **Real Postgres row-level security** — the strongest artifact in either repo:
  `migrations/postgres/0002_iam_rls.sql` defines `USING`/`WITH CHECK` policies scoped by a
  transaction-local GUC `app.current_org`; `0003_iam_functions.sql` sets it via a
  `SECURITY DEFINER set_request_scope()`; **fail-closed** — an unscoped connection sees
  nothing.

**The wiring did not land:**

- `mvmd-gateway` does **not** depend on `mvmd-iam` (no Cargo.toml entry).
- The gateway never calls the policy engine (`evaluate_with_acls()`), never calls
  `enter_org_scope()`, never activates RLS. It still runs on the legacy `StateStore`
  (in-memory/etcd), not Postgres.
- The hot path authorizes with the **old coarse model**: `ApiKeyRecord.can_access_tenant()`
  against a static per-key `tenant_scopes` list; the `route_auth` permission guard checks
  **role only**, not org/tenant (`auth/permissions.rs`).

**Precise verdict** (correcting an earlier overstatement): it is *not* "any key touches any
tenant" — the legacy per-key `tenant_scopes` allowlist does gate access. But the new
fine-grained model — org/workspace/team membership, ACLs, and the DB-level RLS backstop —
gives **zero runtime protection today**, because nothing on the request path invokes it. If
a handler forgets its manual `can_access_tenant()` check, there is no DB-level net beneath
it. M1 has moved from "designed, not built" to **"built, not wired."**

### Remaining gaps — current status

| # | Gap | Status | Evidence |
|---|-----|--------|----------|
| 1 | Replay protection on signed requests | **Mostly open** | `mvm-core/src/protocol/signing.rs` `SignedPayload` is still `{payload, signature, signer_id}` — no timestamp/nonce. A `ReplayWindow` exists only for delegated host-services (`mvmd-agent/src/transport.rs`); the main `ReconcileSigned` path (`agent.rs`) has none. **This blocker lives in the `mvm` repo — see Task B.** |
| 2 | Per-instance / tenant secret encryption | **Narrower than feared** | Secrets travel **by name** (`SecretScope{integration, keys: Vec<String>}` in `mvm-core/src/domain/pool.rs`), not as values in `DesiredState`. Raw values don't transit the reconcile payload (aligns with mvm claim 13). No payload-level envelope encryption, but exposure is limited. |
| 3 | Signature-verification gating | **Prod-enforced, dev-skipped** | `is_production_mode()` rejects unsigned `Reconcile` in prod (`mvmd-agent/src/agent.rs`); dev/test accept unsigned. Works, but the dev/prod split is a footgun. |
| 4 | Per-tenant node quotas / co-location isolation | **Open** | Unrestricted co-location; no per-node per-tenant CPU/mem/net caps. `SpreadAcrossNodes` is advisory scoring, not a hard rule (`mvmd-coordinator/src/scheduler/placement.rs`). |
| 5 | End-to-end signing gateway→coordinator→agent | **Open** | Coordinator gossips unsigned `DesiredState` (`mvmd-coordinator/src/gossip/mod.rs`); agent verifies only pre-signed `ReconcileSigned` variants. |

## The meta-pattern, and the actual fix

The important finding is not any single gap. It is the recurring gap between **built** and
**wired**, and *why* it persists: **there is no gate that fails when a control ships
un-enforced.** IAM is the exemplar — a production-grade RLS + policy engine merged, CI
stayed green, and the request path gained no protection.

This is precisely what mvm's **claim → witness → CI-gate** discipline prevents. A cloud claim
*"a principal scoped to org A receives 403/empty on org B's resources,"* witnessed by a
two-org integration test wired into CI, would have shown PR #161 as a **red claim** rather
than a green "we shipped IAM." Porting that ledger to the cloud tier is the highest-leverage
move and is **Task A**.

## Reprioritized path forward

1. **Integration over new foundations.** The next unit of work is wiring, not building:
   gateway depends on `mvmd-iam` + `mvmd-iam-storage`; auth middleware resolves
   principal→org/workspace/role from the IAM store; **call `enter_org_scope()` (activating
   RLS) before every data access**; route handlers call the policy engine. Activating RLS is
   the single highest security-ROI action — a backstop that holds even when a handler is
   wrong.
2. **Stand up the cloud claim catalog now** (Task A), cross-tenant isolation as claim #1 with
   a two-org test as its witness, gated in CI. This stops the built-but-not-wired pattern
   from recurring.
3. **Close `SignedPayload{timestamp, nonce}` in mvm** (Task B). Still open, in *our* repo,
   still blocking real replay protection on the main reconcile path. Small, high-leverage.
4. **Make the co-location decision** — dedicated node pools per tenant (simpler, stronger
   isolation, lower density/margin) vs hardened co-location (denser, harder security). This
   drives both the threat model and unit economics; decide it before building more scheduler
   logic on the current co-locate-freely default.

## Implication for the facade

The `GatewayBackend` "dumb courier / zero authority" principle is *more* correct given these
findings — but it is only safe if the server actually enforces, which today the fine-grained
model does not. So the facade's **Phase 2 (remote `--remote` / mTLS)** must be gated not only
on ADR-104 but on **IAM integration being live and its cross-tenant claim green**. Shipping a
polished remote client over an unenforced authorization boundary is the worst outcome — it
makes the insecure path easier to reach. (Update `mvm-client-facade-design.md` §Scope to add
this dependency when Task A lands.)

---

# Appendix — Task A: cloud claim catalog + first cross-tenant witness

**Repo:** `mvmd` (with an `xtask`-style gate mirroring mvm's `check-claim-catalog`)
**Why:** convert "we built IAM" into "cross-tenant isolation is enforced and *stays* enforced."
The absence of this gate is the root cause of the built-but-not-wired pattern.

**Deliverables**

1. `specs/claims/catalog.md` in `mvmd` — a claim→witness ledger modeled on
   `mvm`'s `specs/claims/catalog.md`. Seed it with:
   - **Claim C1 — cross-tenant isolation.** *A principal scoped to org A cannot read or
     mutate any resource belonging to org B.* Witness: `two_org_isolation` integration test
     (below). CI lane: gateway test job.
   - **Claim C2 — RLS fail-closed backstop.** *A DB connection with no `app.current_org`
     scope set returns zero rows from any IAM-scoped table.* Witness: a storage-layer test
     that queries without calling `enter_org_scope()` and asserts empty.
   - **Claim C3 — admission under fleet authority.** *Every deploy/instance mutation is
     authorized by the policy engine before state change and recorded in the audit log.*
     Witness: handler test asserting `evaluate_with_acls()` is on the path and an audit
     entry is emitted. (Depends on the integration work; may start as `Pending`.)
2. `two_org_isolation` integration test (`mvmd-gateway/tests/`):
   - Bootstrap org A and org B, each with a scoped API key and one sandbox/instance.
   - Assert A's key on B's resource → **403** (or 404 by policy), for read, mutate, delete.
   - Assert A's key listing returns only A's resources (no B leakage).
   - Run against the **wired** path (gateway → mvmd-iam → RLS-scoped store), not the legacy
     `can_access_tenant()` shortcut. Until integration lands, mark C1 `Pending` with the test
     `#[ignore]`d and a one-line note — never silently green.
3. `xtask check-claim-catalog` (or CI step) that fails if a named witness stops existing —
   same contract as mvm's gate.

**Acceptance criteria**

- `catalog.md` exists with C1–C3, each naming a real witness file/test.
- `two_org_isolation` passes against the integrated path (or is explicitly `Pending`+`#[ignore]`
  with a tracked reason, not omitted).
- The catalog gate runs in CI and fails on a missing witness.
- A follow-up issue links C3 to the IAM-integration work so it flips green when wiring lands.

**Non-goals:** porting all 15 mvm claims at once; billing/compliance claims. Start with the
three that gate multi-tenant safety.

---

# Appendix — Task B: `SignedPayload{timestamp, nonce}` + validity/replay verification

**Repo:** `mvm` (`mvm-core`), unblocking `mvmd`'s replay protection on the reconcile path.
**Why:** the main `ReconcileSigned` path has no replay protection because the signed type
carries no freshness. A captured signed desired-state replays indefinitely.

**Current state**

`mvm-core/src/protocol/signing.rs`:
```rust
pub struct SignedPayload { payload: ..., signature: ..., signer_id: ... }
```
No `timestamp`, no `nonce`. mvmd's `ReplayWindow` (`mvmd-agent/src/transport.rs`) only guards
delegated host-services calls (caller-supplied `request_id`), not `ReconcileSigned`.

**Design**

- Add `issued_at: <unix-millis>` and `nonce: [u8; 16]` to `SignedPayload`. The signed bytes
  **must include both** (they are inside the signed envelope, not siblings of the signature),
  so tampering with freshness breaks verification.
- New fields deserialize with `#[serde(default)]` for wire tolerance, but verification
  **requires** them present and non-default (nothing is in production; no schema-version
  bump — see the project's no-ceremony convention).
- Verification API: a validity window (`issued_at` within ±skew) + a nonce replay store,
  mirroring the G4 validity-window + nonce replay-store already used for `ExecutionPlan`
  admission (claim 8). Reuse that machinery rather than inventing a second replay store.
- Consumer wiring is out of scope for this task except to expose the verify entrypoint the
  agent will call; the mvmd side (guarding `ReconcileSigned` with the store) is a follow-up
  issue in mvmd that depends on this.

**Files**

- `mvm-core/src/protocol/signing.rs` — struct fields, sign path includes them in the signed
  bytes, verify path checks window + nonce.
- Wherever the ExecutionPlan nonce store lives (`mvm-core/src/plan/…`) — reuse or generalize
  the replay store; do not fork a second copy.

**Test plan (mvm's positive/negative/edge discipline)**

- Roundtrip: sign→verify with fresh `issued_at`/`nonce` passes.
- Replay: same payload verified twice → second is rejected by the nonce store.
- Stale: `issued_at` outside the window → rejected.
- Tamper: flip a `nonce`/`issued_at` byte after signing → signature verification fails.
- Serde: `#[serde(default)]` deserialization of a payload missing the fields → verify
  rejects (absent freshness is not valid), proving fail-closed.

**Acceptance criteria**

- `SignedPayload` carries `issued_at` + `nonce` inside the signed envelope.
- Verify enforces validity window + nonce replay via the shared store (no second store).
- All five tests above pass; `cargo fmt --all`, `nextest`, `--doc`, `clippy -D warnings`
  clean.
- A tracked mvmd follow-up issue references this to guard `ReconcileSigned` end-to-end.

**Non-goals:** wiring mvmd's agent to the store (separate mvmd issue); end-to-end
gateway→coordinator→agent signing (gap #5, separate).
