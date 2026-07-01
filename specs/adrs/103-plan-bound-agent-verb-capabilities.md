# ADR-103: Plan-bound agent verb capabilities

- Status: Proposed
- Date: 2026-06-30
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — claim 4 `do_exec`, claim 15 sealed interactivity), ADR-041 (signed audited execution plans — claim 8), ADR-049 (secret substitution — time/destination-bound signed credentials), ADR-059 / ADR-062 (host services broker — claim 12 binding-gated dispatch), ADR-090 (resident daemon trust gradient)
- Sequenced by: (plan TBD — writing-plans follow-up)

## Context

The guest agent's control channel (vsock port 5252, `GUEST_AGENT_PORT`) carries every
host→guest control verb — ~75 `GuestRequest` variants multiplexed over one
`AuthenticatedFrame`-signed connection (`crates/mvm-guest/src/vsock.rs`). The agent is
the server; the host is the client.

Today the verb surface is gated exactly once, coarsely, by *class × profile*:

- Each variant classifies as `ProdSafe`, `DevOnly`, or `BuilderOnly`
  (`GuestRequest::class`, `crates/mvm-guest/src/vsock.rs:819`; a compile-fail test at
  `:5418` forces every new variant to be classified).
- Before dispatch the agent runs `req.allowed_in(active_profile)`
  (`crates/mvm-guest/src/bin/mvm-guest-agent.rs:2055`, logic at `vsock.rs:884`) and
  returns `GuestResponse::UnsupportedInProfile` for anything the boot profile
  (`SealedProd` / `Dev` / `Builder`) doesn't permit. A sealed-prod agent already
  refuses `Exec` / `FsWrite` / `ConsoleOpen`.

This class gate is a hard *outer* bound, but it is not per-workload. Every `ProdSafe`
verb is available to every sealed-prod workload — `RunEntrypoint`, `Ping`,
`MountVolume`, `UpdateIdleTimeout`, the status/probe family — regardless of whether a
given workload's admitted plan needs them. There is no way for a plan to say "this
workload receives `RunEntrypoint` and `Ping` and *nothing else*."

Two forces make that gap worth closing:

1. **Least privilege per workload.** The signed `ExecutionPlan` is the authority for
   what a workload may do (claim 8). It already binds host-side *services* (claim 12,
   `ExecutionPlan.services` → broker dispatch gate). The agent verb surface is the
   symmetric guest-side capability and is currently unbound.

2. **The host is decomposing.** Under the ADR-090 trust gradient the plan is signed by
   the host-signer moat at admission, but the component holding the 5252 client may be
   a less-trusted control process. A guest-side, plan-bound verb check is only
   meaningful when the *signing authority is separated from the calling authority* — so
   the grant must be bound to the plan's signature, not merely asserted by whoever is
   calling.

## Decision

Add an optional per-workload **verb grant** to the signed `ExecutionPlan`. The guest
agent, at handshake, receives a host-signer-signed capability token derived from that
grant, pins it for the session, and intersects every subsequent request against it —
*after* the existing class/profile gate. The grant is strictly **subtractive**: it can
only narrow what the profile already allows; it can never widen a `SealedProd` agent to
accept a `DevOnly` verb.

Enforcement is **guest-side** (the agent is the load-bearing last line, and it already
owns the `allowed_in` seam). This ADR does not require, but explicitly leaves room for,
a complementary host-side check at the daemon (closing the `services_bindings: vec![]`
gap at `crates/mvm-backend/src/host_agent_spawn.rs:208`) as a cheap outer layer.

### Why a handshake-delivered token, not a boot-time file

The grant must reach the agent *per claim*, not per boot. Warm pools (Plan 118
auto-claim, Plan 175 warm-start, Plan 211 sub-second `machine run`) pre-boot an agent
before its workload's plan exists, then claim it later. A boot-time artifact
(`/etc/mvm/agent-caps.json` read once at PID 1) is fixed at the wrong moment — it cannot
attenuate a VM that is claimed for a plan minted after boot. Each claim redoes
`ProtocolHello`, so the handshake is the one delivery point that re-pins per workload.

This mirrors the shape ADR-049 / claim 13 already ship for secrets: a **time-bound,
context-bound, signed credential** rather than a static blob.

### The grant

A new optional field on `ExecutionPlan` (additive, `#[serde(default)]` — no schema-bump
ceremony; `SCHEMA_VERSION` stays as-is):

```rust
/// Per-workload agent verb allow-list. `None`/absent → class-gate-only
/// (current behavior, preserves dev flows). `Some(set)` → the agent
/// accepts a control verb only if it passes the class gate AND its
/// `verb_name()` is in `set` (or is baseline). Strictly subtractive.
pub agent_verbs: Option<Vec<VerbId>>,
```

`VerbId` is the stable `GuestRequest::verb_name()` string (`vsock.rs:760`), validated at
parse time — the identifier already used in `UnsupportedInProfile` responses, so it is
wire-stable by construction.

At admission the supervisor mints a session token and signs it with the host-signer key:

```rust
#[serde(deny_unknown_fields)]
pub struct VerbGrant {
    pub session_id: String,   // binds to THIS 5252 session
    pub plan_nonce: Nonce,    // binds to the admitted plan (claim 8 replay ledger)
    pub not_after: DateTime<Utc>, // ≤ plan.valid_until
    pub verbs: Vec<VerbId>,
    // Ed25519 signature by the host-signer authority, over the JCS bytes
    // of the fields above. NOT the per-session frame key.
}
```

### Baseline verbs (always allowed, need not be listed)

The handshake/liveness verbs are implicitly granted, mirroring claim 12's implicit
`host.audit.v1`: `ProtocolHello` (it *is* the handshake, and runs before any grant is
pinned), `Ping`, and `ReadinessStatus`. A grant listing only workload verbs never has to
enumerate these, and an empty `verbs: []` still yields a live, answerable agent.

### Enforcement order

```
read_authenticated_frame            (integrity + replay — unchanged)
  → allowed_in(active_profile)      (class/profile gate — unchanged, HARD outer bound)
    → grant.permits(verb)           (NEW: baseline OR in pinned set; skipped if no grant)
      → dispatch
```

The grant check is skipped entirely when the plan carries no `agent_verbs`, so opting
out is the default and dev/interactive flows are unaffected.

### Trust: the key separation is the whole point

The guest already obtains a host `VerifyingKey` + `session_id` at `ProtocolHello`
(`vsock.rs:2290`). The `VerbGrant` signature MUST chain to the **plan-admission
(host-signer) authority**, which under ADR-090 is distinct from the 5252 caller. If the
grant were signed by (or forgeable by) the caller, a compromised caller would simply mint
the verb it wants and the check would buy nothing. The Plan must therefore provision the
guest with the host-signer verifying key (or a delegation chain to it) and verify the
grant against it — separately from the per-session frame-signing key. This invariant is
load-bearing; a Plan that collapses the two keys silently defeats the ADR.

### Denials are audited (claim-12 parity)

A grant refusal returns a new wire-stable `GuestResponse::VerbNotAuthorized { verb }`
(sibling to `UnsupportedInProfile`; must be registered in the `response_contract()` /
`ResponseVariant` machinery at `vsock.rs:1108`). On receiving it the host caller emits an
`agent.verb_denied` entry to the chain-signed audit log, so refusals are observable and
tamper-evident via `verify_audit_chain` — the same posture claim 12 gives service-call
denials.

## Alternatives considered

- **Boot-time signed grant file.** Rejected: cannot attenuate per-claim under warm-pool
  reuse (see "Why a handshake-delivered token").
- **Host-side only (close the `services_bindings: vec![]` gap, no guest change).** A real
  and complementary gap, but it is self-policing in the single-trusted-host case (the
  caller checks itself) and does not defend the guest as the last line. Kept explicitly
  in scope as an *optional outer layer*, not the primary mechanism.
- **Widen the class taxonomy instead (finer `RequestClass`).** Rejected: classes are a
  static property of a verb, not a per-workload one. No number of classes expresses "this
  particular workload needs this particular subset."
- **Encrypt the channel.** Out of scope and unrelated: vsock has one host endpoint and
  one guest endpoint inside the TCB; ADR-002 puts a malicious host out of scope. The need
  here is attenuation and authenticity, not confidentiality.

## Threat model

- **In scope:** a less-trusted host-side 5252 caller (ADR-090 gradient) invoking a
  `ProdSafe` verb the workload's admitted plan did not authorize; replay of a broader
  grant captured from an earlier plan (defended by `plan_nonce` + `not_after` riding the
  claim-8 validity/replay machinery); a grant forged by the caller (defended by the
  host-signer key separation).
- **Out of scope (unchanged from ADR-002):** a malicious host holding the hypervisor and
  the host-signer private key; confidentiality of vsock bytes; a guest that is already
  compromised attempting verbs — that is the class gate's and claim 4/15's job, which
  this ADR strengthens but does not replace.

## Consequences

- Strengthens the claim 4 / claim 15 family (interactive/exec surface minimization) with
  a per-workload dimension. Whether this becomes a numbered or `Preview` claim in the
  ADR-002 ledger is a maintainer decision and is deliberately **not** asserted here
  (cf. claim 16's pending promotion).
- New signed field on `ExecutionPlan`; synthesis populates `agent_verbs` from workload
  requirements, admission mints + signs the `VerbGrant`.
- New wire-stable `GuestResponse::VerbNotAuthorized` + `agent.verb_denied` audit verb.
- Zero behavior change for plans that omit `agent_verbs` — dev, interactive, and existing
  prod flows are unaffected until a plan opts in.

## Testing

- `agent_verb_grant_denies_unlisted_verb` — sealed-prod agent with a grant refuses a
  `ProdSafe` verb outside the set; returns `VerbNotAuthorized`.
- `agent_verb_grant_is_subtractive` — a grant listing a `DevOnly` verb does NOT make a
  `SealedProd` agent accept it (class gate still wins).
- `agent_verb_grant_baseline_always_allowed` — `ProtocolHello` / `Ping` / `ReadinessStatus`
  answer under an empty grant.
- `agent_verb_grant_forged_by_non_signer_rejected` — a grant not signed by the host-signer
  authority is refused at handshake.
- `agent_verb_grant_replay_across_session_rejected` — a grant bound to session A / nonce A
  is refused on session B.
- `agent_verb_grant_expired_rejected` — `not_after` in the past → refused.
- `no_grant_is_class_gate_only` — plan without `agent_verbs` behaves exactly as today.
- Audit: `audit_chain_contains_verb_denied_entries` — a refusal appears in the chain and
  survives `verify_audit_chain`; a tamper breaks it.
