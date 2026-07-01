# ADR-104: Cloud control-plane trust boundary (multi-tenant superset of ADR-002)

- Status: Proposed
- Date: 2026-07-01
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — the 15 claims, single-host scope), ADR-041 (signed audited execution plans — claim 8), ADR-059 (host services broker — claim 12 binding-gated dispatch), ADR-049 (destination/time-bound secret substitution — claim 13). Design input: `specs/notes/mvm-client-facade-design.md`, `specs/research/mvmd-cloud-readiness-assessment.md`.
- Sequenced by: cloud claim catalog + `two_org_isolation` witness (Task A, in `mvmd`); `mvm-client` facade Phase 2 (remote) is gated on this ADR being Accepted.

## Context

`mvm` (this repo) is the open-source, run-microVMs-locally product. `mvmd` (sibling
repo) is the paid, multi-tenant cloud where users *deploy* microVMs onto hosts we
operate. `mvm-studio` and — per the facade design — `mvmctl` reach **both**: a local
in-process path and a remote REST path to an `mvmd-gateway`, through one `MvmClient`
trait.

ADR-002 is the source of truth for the local security posture. Its threat model is
scoped, explicitly, to:

- a **single trusted local host** (the user owns the machine),
- **one guest = one workload** (no multi-tenant guests),
- **malicious host out of scope**.

The 15 CI-enforced claims all defend *that* boundary: a workload escaping onto the
*user's own* machine.

The cloud product **inverts every one of those assumptions**. We own the host; the
user is untrusted; **many** untrusted tenants share our hosts. The threat becomes
tenant→host and tenant→tenant escape — precisely the two items ADR-002 declares out of
scope (multi-tenant guests; an untrusted-host relationship from the tenant's view).

Introducing `mvmctl --remote <url>` also adds a **new actor** ADR-002 never modeled: a
remote control plane reachable over a network, with a network in between. A trait that
makes the local and remote calls look identical can hide that their security
*guarantees* are enforced by different authorities. That is a mental-model hazard, not
just a code one.

This ADR establishes the cloud tier's trust boundary as an explicit **superset** of
ADR-002, so "the cloud keeps every local guarantee, and adds the multi-tenant ones" is
a *checkable* statement rather than an aspiration.

## Decision

### 1. The cloud tier is ADR-002 plus a named set of multi-tenant claims

The 15 local claims remain necessary and continue to hold on the workload backends.
The cloud tier adds, at minimum:

- **CT-1 Cross-tenant isolation.** A principal scoped to tenant/org A cannot read or
  mutate any resource of tenant/org B — enforced on the request hot path *and* backed
  by a database-level fail-closed backstop (row-level security), so a forgotten
  handler check is not a breach.
- **CT-2 Admission under fleet authority.** Every deploy / lifecycle mutation is
  authorized by the control plane's policy engine before state change and recorded in
  the chain-signed audit log. (Mirrors claim 8, enforced by mvmd's authority.)
- **CT-3 Control-plane replay resistance.** Signed control-plane requests carry
  freshness (validity window + per-signer nonce) and are rejected on replay. (The
  `mvm-core` primitive for this is Task B; the reconcile-path wiring is mvmd's.)
- **CT-4 Per-tenant resource bounds.** A tenant's workloads cannot starve another's on
  a shared host — resource caps and/or placement isolation, per the co-location
  decision below.

The catalog is seeded here and owned as a living `specs/claims/catalog.md` in `mvmd`
(Task A). It is expected to grow (secret confidentiality across the boundary, egress
attribution, etc.); this ADR fixes the *discipline*, not the final list.

### 2. The trait unifies the call, never the trust

There are two authorities, and they are never silently merged:

- **Local path** — the authority is the local host, exactly as ADR-002 describes
  (host-signed `ExecutionPlan`, broker, local audit chain). `LocalBackend` runs the
  same `mvmctl` library over the same on-disk state.
- **Remote path** — the authority is `mvmd`. `GatewayBackend` is a **dumb courier with
  zero enforcement authority**: it presents credentials and ships intent; every
  security decision (RBAC, quota, admission, audit, rate-limit) is made server-side and
  the server treats the client as untrusted input regardless.

Security is therefore never a property of the transport the caller picked; it is
enforced at whichever authority owns that path. The facade must make the acting
authority observable, never present remote guarantees as if they were the local ones.

### 3. Key-domain separation

Local signing keys (`~/.mvm/keys/host-signer`) are the *local host's* authority and
must never be trusted by the fleet. The facade must not ship a locally-signed plan and
have `mvmd` honor that local signature — that is key-trust confusion. Remote DTOs carry
**intent**; `mvmd` re-admits and re-signs under its own fleet key. The shared wire
contract must not leak local signing material or host paths across the boundary. This
is a constraint on the DTO shapes, not only a runtime check.

### 4. Client-side rules are fail-closed

- **Prefer mTLS; require TLS.** HTTPS + cert validation by default; support the
  gateway's `require_client_cert` mode; **refuse plaintext to any non-loopback host**
  (the loopback sidecar is the only cleartext exception).
- **Ride the server's auth model exactly** — scoped bearer keys, honor expiry warnings,
  hard-fail on API-version skew. No bespoke client auth.
- **Credentials** — OS keychain (studio) or env var / mode-0600 file (CLI); never a
  token flag (leaks to `ps`/history); never logged; `zeroize` on drop; **endpoint-bound**
  so a token is never sent to a different `--remote` URL.
- **Untrusted-input hardening** — the shared DTOs are deserialized by the server from
  anyone with network reach: `#[serde(deny_unknown_fields)]`, size/depth limits,
  validation. Typed DTOs fail closed; today's `Result<Value>` surface does not.

### 5. Built is not wired: enforcement must fail CI when absent

A control that exists but is not on the request hot path with a passing witness is
treated as **absent**. Each cloud claim maps to a named test/CI gate (the mvm
claim→witness→gate discipline, ported to `mvmd`). This is a direct response to the
present state, where a production-grade IAM + RLS subsystem shipped ~100% built and ~0%
wired without turning CI red.

### 6. Sequencing

The `mvm-client` remote phase (`--remote` / mTLS / `GatewayBackend`) ships only once
this ADR is Accepted **and** cross-tenant enforcement (CT-1) is wired with a green
witness. Shipping a polished remote client over an unenforced authorization boundary
would make the insecure path easier to reach — the worst outcome.

## Threat model — new actors (relative to ADR-002)

In scope for the cloud tier, additional to ADR-002:

- **The network between client and `mvmd`.** Mitigated by TLS/mTLS, endpoint-bound
  credentials, replay resistance (CT-3), fail-closed client rules.
- **Other tenants on a shared host / control plane.** Mitigated by CT-1 (isolation +
  RLS backstop), CT-4 (resource bounds), and the co-location decision.
- **A tenant's untrusted workload versus the fleet host.** The ADR-002 guest-boundary
  claims (1–15) carry over unchanged and are the first line; multi-tenancy raises the
  blast-radius stakes but not the per-guest mechanism.

Still out of scope (named, deliberately):

- **A malicious `mvmd` operator / the host we operate.** We trust our own control-plane
  operators with the hypervisor and fleet keys, mirroring ADR-002's malicious-host
  exclusion. (Reducing this trust — confidential computing, hardware attestation — is a
  separate future ADR.)
- **Hardware-backed key attestation.** As ADR-002.

## Consequences

- "Same guarantees or stricter, in the cloud" becomes provable: the superset is
  enumerated and each element has a CI witness.
- The facade design gains a hard gate (§6): remote is not shippable until CT-1 is
  enforced, not merely designed.
- Honest current status at authorship: CT-1 is built (mvmd IAM + Postgres RLS) but not
  wired; CT-3's `mvm-core` primitive has landed (Task B) with the mvmd reconcile-path
  wiring outstanding; CT-2 is partial (prod-gated signature verify, no end-to-end
  gateway→agent signing); CT-4 is open (unrestricted co-location). This ADR does not
  claim these are done — it makes their absence a tracked, CI-visible gap.

## Alternatives considered

- **Keep ADR-002 as-is; handle cloud security ad hoc.** Rejected: there is then no
  checkable superset, and the built-≠-wired failure mode has nothing to make it red.
- **A separate cloud threat-model doc only, no ADR.** Partially adopted: a companion
  `specs/threat-models/` doc in `mvmd` may hold the long-form analysis, but the *trust
  boundary decision* belongs in the ADR ledger next to ADR-002 so the two are read
  together.
- **Make the trait fully uniform over local/remote, hiding the transport.** Rejected:
  uniformity of *interface* is good DX; uniformity of *apparent trust* is a hazard. The
  acting authority must stay observable (§2).

## Co-location decision (to resolve; drives CT-4 and unit economics)

Two honest options, called out so it is decided before more scheduler logic is built on
the current co-locate-freely default:

- **Dedicated node pools per tenant** — simplest, strongest isolation, lower density
  and thinner margins.
- **Hardened co-location** — denser and better economics, but defends the
  Firecracker/VMM boundary, network segmentation, and noisy-neighbor between untrusted
  tenants on shared silicon.

This is a product+security decision, not purely security; this ADR records it as the
open question gating CT-4 rather than pre-deciding it.
