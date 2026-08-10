# Unified policy and human-approval contract v1

Status: implemented for issue #2168.

This contract makes one distinction explicit: static policy admission decides
what an operation is allowed to be, while human approval decides whether an
already-admissible operation may proceed now. Approval never widens signed
admission, guest enforcement, or a sealed-production refusal.

## Decision order

Every operation is evaluated in this order:

1. A verified signed admission must bind the operation's capability and
   resource digest. Missing or ambiguous admission is an immediate deny.
2. An active emergency deny or an explicit deny rule is an immediate deny.
3. The most-specific matching rule wins; higher priority wins first, then
   deny beats ask, ask beats allow, and configuration order breaks remaining
   ties deterministically.
4. An ask result creates a bounded approval request. Only an authorized
   operator may answer it, and the first valid response wins.
5. A signed admission plus an allow result proceeds without approval.

The default is deny. No policy state, malformed rule, stale admission, or
expired approval may fall through to allow.

## Typed scopes and metadata

The operation vocabulary is closed and covers filesystem read/write, network
connect, process spawn/signal, environment read, and agent-capability invoke.
Rules match a typed operation and an optional SHA-256 resource digest. Raw
paths, commands, environment values, credentials, and operator PII are not
approval or audit payloads.

An approval request contains only a stable public approval ID, agent session
ID, typed capability, resource/request/policy digests, expiry, and bounded
authorized operator IDs. The request is therefore reviewable without
retaining the underlying command or sensitive resource name.

## Durable lifecycle

Approval requested, responded, expired, and canceled events are durable
`AgentSessionEventEnvelope` entries from the existing #2167 journal. They
share the session's durable cursor and hash/reference ordering; there is no
second approval stream. Ephemeral UI or transport notifications may be
dropped and never decide authorization.

An approval is pending until one authorized response is durably recorded.
Approved, denied, expired, and canceled requests are terminal. Replayed,
duplicate, stale, unauthorized, and late responses are refused deterministically.

## Compatibility map

- Signed `ExecutionPlan` admission and `AdmittedPlan` remain the authority for
  static capability admission and replay/freshness checks.
- Existing network policy, secret bindings, sealed-production profile, and
  guest/runtime gates remain enforcement backstops; this contract cannot
  override them.
- Existing command blocklist `Block`, `RequireApproval`, and `Log` decisions
  map to the typed deny/ask/allow effects. The new evaluator does not auto-
  approve production operations; development auto-approval remains explicitly
  separate and is not a signed-admission substitute.
- Existing `AuditEntry`/`AuditAction` remains the audit sink. Approval events
  carry only typed outcomes and digests, so audit records can name the policy
  decision without exposing secrets or PII.
- `mvm-client` and `mvm-sdk` re-export the shared policy/approval contract;
  gateway and CLI routing adopt it at their existing admission boundaries.

## Security invariants

- A guest cannot convert deny into ask or allow.
- Approval cannot grant an unadmitted capability or resource.
- Only authorized operator IDs can answer a request.
- The first valid response wins and is durable before execution is released.
- Expired, canceled, stale, malformed, or replayed responses fail closed.
- Policy and approval history contains no raw command, path, credential, or
  unbounded diagnostic text.
