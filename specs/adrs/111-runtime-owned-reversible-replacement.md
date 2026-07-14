# ADR-111: Runtime-owned reversible replacement on owned cleartext paths

**Status:** Proposed — 2026-07-13

## Summary

Land the first runtime-owned detect -> replace -> reinject slice for sensitive
values on owned cleartext request/response paths. The promise is narrow:
request-scoped opaque token replacement on outbound traffic plus exact-token
restore on the owned response path. No semantic recovery, no third-party async
callbacks, and no guest-visible plaintext persistence.

## Context

The existing substitution/redaction stack in `mvm` already has two useful
security properties:

1. declared secrets can stay off the guest entirely through host-side
   substitution
2. undeclared secret-shaped or PII-shaped content can be redacted before egress

That was still missing one product-critical capability: when the runtime owns
both sides of a cleartext request/response flow, it had no way to replace
sensitive spans on the outbound leg and restore them exactly on the inbound
leg. Without that, policy could safely scrub prompts or payloads before an
external AI/tool call, but any authorized caller-visible response still had to
choose between one-way redaction and raw passthrough.

The requirement for v1 is intentionally limited:

- runtime-owned paths only
- exact opaque-token restore only
- request-scoped correlation only
- no plaintext in proofs or ordinary audit/log views

## Decision

`mvm` adds a runtime-owned reversible replacement slice at the host
substitution proxy boundary.

### 1. Shared policy + proof types live in `mvm-core`

`ExecutionPlan` now carries a `ReversibleReplacementPolicy` that is signed,
admitted, and handed to `mvm-hostd` like the other policy-bearing plan fields.
The shared contract includes:

- sensitive classes: `secret`, `pii`
- replace / reinject surfaces
- fail-closed fallback mode
- request-scoped flow ids
- opaque rewrite tokens
- plaintext-free proof records carrying keyed digests and byte spans only

This keeps the policy part of the signed plan boundary rather than making it an
ephemeral host-local toggle.

### 2. Replacement happens before one-way redaction

On the outbound host-owned request path:

- the claim-10 destination gate still runs first
- reversible replacement runs before one-way redaction and before host-side
  declared-secret substitution
- the replacement engine detects secret-shaped and structured-PII spans
- matched values become request-scoped opaque tokens
- identical values within one flow reuse the same token

That ordering preserves the host-only placeholder model for declared secrets
while still allowing undeclared secret/PII content to be tokenized for exact
restore instead of only masked away.

### 3. Reinjection is exact-token-only on the owned response path

On the inbound response path, the runtime restores only exact token echoes from
the same flow state. If the external service paraphrases, transforms, splits,
or drops the token, nothing is restored. This is a deliberate contract, not a
best-effort heuristic.

### 4. Proofs and audit stay plaintext-free

Each replace/reinject event records:

- flow id
- event index
- sensitive class
- surface
- optional field name
- offset and lengths
- token id
- keyed HMAC digest of original bytes
- keyed HMAC digest of rewritten bytes
- policy / authorization decision labels

The audit chain carries those proof metadata records, not the plaintext value.

## Consequences

### Positive

- `mvm` now has a concrete v1 implementation of “tokenize outbound, exact-token
  restore inbound” for owned cleartext paths.
- The policy is part of the signed execution plan and therefore travels through
  the same admission / provenance path as the rest of the runtime controls.
- The implementation composes with the existing substitution and redaction
  layers instead of replacing them.

### Negative

- This is not a general semantic restoration mechanism. Model-transformed output
  will not restore.
- The v1 authority labels are local runtime labels such as `runtime_owned`; the
  cloud-side permission authority lives in sibling `mvmd`.
- The current proof substrate is an audit/proof metadata trail, not a full
  durable proof-access service.

## Non-goals

- paraphrase-aware recovery
- async callback or webhook reinjection
- cross-flow or cross-tenant token reuse
- guest-side plaintext reinjection defaults
- claiming macOS parity beyond the currently owned substitution-proxy path

## Follow-on work

1. Bind the runtime-owned authorization label to the sibling `mvmd`
   tenant/permission authority on cloud-managed paths.
2. Extend the proof model to a dedicated retrieval surface where that is needed.
3. Decide whether additional structured PII classes should become enabled by
   default beyond the current detector set.
