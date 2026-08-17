# Survey follow-ups: identity federation, authenticated ingress, web-fetch host case

Backing: preview
Validation: none — this plan proposes work; only the WS-A slice below is implemented

## Context

A capability survey of an adjacent hosted-VM platform produced four ideas. Two
have shipped: the dead-binding-model deletion plus the one-predicate gate
(#2573), and named service bindings (#2597, ADR-044). A fourth — idle-VM budget
accounting — was investigated and **retracted**: charging the configured maximum
is deliberate and documented in `crates/mvm-hostd/src/admission_budget.rs`, and
the proposed change would have been unsound.

Three follow-ups remain. This plan covers all three, sequenced, and records two
corrections that change what they cost.

## WS-A — web-fetch allowlist host case *(implemented; landing separately)*

`WebFetchTool::allowed_hosts` is a `BTreeSet<String>` compared with
`.contains(host)`, and the list is typed by an operator into
`MVM_WEB_FETCH_ALLOWLIST`. Nothing folded case on either side, so an operator
writing `API.Allowed.Example` had every fetch to that host denied — a
fail-closed but silent misconfiguration whose error blames the allowlist rather
than the case.

Fixed by normalising at ingest in `with_allowlist` and folding again at the
comparison, in `crates/mvm-hostd/src/supervisor/tools/web_fetch.rs`. Witness:
`allowlist_matching_is_case_insensitive` (written first, confirmed red).

**Explicitly not done: wildcards.** The type's own doc comment defers them
"once we have a use case for them". Building them now would be inventing the
use case to justify the work. The `check-single-host-predicate` exemption for
this file stands: it is a per-tenant fetch allow-list, not a secret's
destination binding, and unifying the two would silently change its semantics.

## WS-B — workload identity federation

**Goal.** A workload reaches a cloud API using a short-lived, identity-bound
credential the provider issues, instead of a long-lived secret sitting in
`secret_store` and being substituted on egress. Fewer standing credentials, and
the provider's own audit log gains an independent record of which workload
acted — something mvm cannot produce today.

Named service bindings were its prerequisite: you cannot federate "to a
provider" while a provider is a free-text host string. That is now done.

### Two corrections that change the cost

**1. The plan hash is not the workload identity.** Earlier framing in this
effort claimed the content-addressed `plan_id` could serve as the federated
subject. `crates/mvm-core/src/plan/content_id.rs` says the opposite, in its
own words: `plan_id` is *"a **per-execution** identity, not a workload
identity"* — it commits to the per-synthesis nonce and the validity window, so
it changes on every synthesis. The stable identity is `(tenant, workload)`.

This matters concretely: a trust policy in a customer's cloud account is
configured once against a `sub`. Binding it to `plan_id` would break the
relationship on **every single run**. The federated subject must be
`(tenant, workload)`, with `plan_id` carried as an additional claim for audit.

**2. The signing algorithm is an open blocker, not a detail.** Every signing
path in this workspace is Ed25519 (`ed25519_dalek` in
`mvm-core/src/plan/signing.rs`); there is no ECDSA or RSA anywhere, and no
JWS/JOSE dependency. Cloud federation endpoints validate an OIDC token against
a published JWKS and, to the best of current knowledge, accept RS256/ES256 but
**not** EdDSA. If that holds, federation requires a second key type and a JWS
implementation — against the workspace's standing "limit dependencies" rule.

**Verify this before writing any code.** It decides whether WS-B is a moderate
feature or a crypto-surface expansion, and no later phase is worth starting
until it is answered.

### Phasing

- **B0 — algorithm spike (blocking). DONE — see
  `specs/research/workload-identity-federation-algorithm-spike.md`.**
  Answer: EdDSA is **not** accepted. AWS `AssumeRoleWithWebIdentity` requires
  RS256/384/512 or ES256/384/512, so a second key type is required regardless
  of other providers. The cost is smaller than feared — a `p256` dependency
  plus a hand-rolled signing-only JWS over the `base64`/`sha2`/`serde_jcs`
  already in the tree, avoiding a `jsonwebtoken`/`jose` dependency. The real
  expense is not crypto: it is operating a stable issuer with a reachable
  JWKS, which only mvmd can be.
- **B1 — identity claims DTO.** The claim set (`iss`, `sub` = `(tenant,
  workload)`, `aud`, `exp`, plus `plan_id` for audit) in `mvm-contract`, with
  serde round-trip and validity-window tests. No issuer, no network.
- **B2 — the issuer lives in mvmd.** A stable issuer with a reachable JWKS is
  the whole premise, and a local CLI cannot be one: every developer's host
  signer is a different issuer, and nobody will add a per-laptop trust
  relationship to a cloud account. mvmd already has `mvmd-iam`, but its surface
  is `api_key` + `principal` and its only OIDC reference is *inbound*
  (`oidc_client`) — users authenticating **to** mvmd. Outbound issuance is
  greenfield there.
- **B3 — consume at the substitution endpoint.** Exchange the token for
  provider credentials on the forward leg, reusing the ADR-044 provider entry
  to know which endpoint to exchange at. Only now does a workload see any
  benefit.

**Scope warning.** B2 is a new subsystem in a different repository, and B3
touches the claim-12/13 enforcement path. This is not a one-PR feature; treat
B0/B1 as the commitment and re-decide at B2.

## WS-C — authenticated HTTPS ingress

`crates/mvm-core/src/ingress_broker.rs` is closed-by-default and well-built:
inbound exists only where the signed plan declares a route, and an undeclared
port is denied. It stops at raw TCP forwarded over vsock. The surveyed platform
layers automatic TLS, a stable per-VM hostname, and identity-based sharing on
top — the gap between "the port is open" and "someone can actually use this".

**Recommendation: do not start this on my judgement.** It is a product tier,
not a security fix. The seam is small (5 public items; two files reference
`IngressRoute`/`IngressPolicy`), so the work is mostly new: certificate
issuance and renewal, a naming authority, and a sharing/identity model. All
three imply hosted infrastructure that mvm, as a local CLI, does not have —
which makes this a direction decision rather than an engineering task.

If it is wanted, the first question is not technical: **who operates the name
and the certificate authority?** Answer that and the design follows; skip it
and the implementation will encode an answer nobody chose.

## Recommended order

1. **WS-A** — done; land it.
2. **WS-B0** — the algorithm spike. Cheap, blocking, and it decides whether the
   most valuable idea here is affordable.
3. **WS-B1** — the claims DTO, if B0 clears.
4. **WS-C** — only after a product decision on who operates name + CA.

## Verification

WS-A:

```sh
cargo test -p mvm-hostd --lib web_fetch::
just check-gated
cargo nextest run --workspace
cargo run -p xtask -- check-single-host-predicate
```

WS-B0 produces a decision note, not code; its "verification" is that the
answer is written down with a citation, and that B1 does not start first.
