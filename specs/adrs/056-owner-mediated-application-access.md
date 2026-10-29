# ADR-056: Owner-mediated application access

Backing: preview
Validation: none

## Status

**Accepted by the owner on 2026-10-20.** The owner took
[#4460](https://github.com/tinylabscom/mvm/issues/4460) on, which settles that
option D (a typed, host-mediated message channel) is the chosen direction. The
protocol, authorization, precedence and lifecycle are specified in
[owner-mediated application access](../contracts/owner-mediated-application-access.md).
Acceptance of the direction is not an implementation: the channel does not exist
yet, no sealed-image witness exists, and the open questions below are answered
in that contract or remain listed there. It adds no claim and promotes none;
claims 4, 8, 12, 15 and 17 keep the wording in ADR-001, and every limit recorded
below stands.

Related context: [#4222](https://github.com/tinylabscom/mvm/issues/4222) and
[#4227](https://github.com/tinylabscom/mvm/issues/4227).

## Context

An owner of a running application sometimes needs to talk to it: ask an agent
for its state, hand it a new task, answer a prompt, cancel a run. Today the
available paths are a poor fit:

- The PTY-over-vsock console is the only interactive transport and is dev-only.
  The host refuses it on a sealed image (`console_refused_on_sealed_image`,
  `enforce_accessible_gate`; claim 15).
- A declared application terminal exists as a signed grant
  (`ApplicationTerminalBinding` in `mvm-contract`'s `plan/verb_grant.rs`), and a
  bundle declaring `InteractiveTerminal` is refused under the `SealedProd`
  profile (`interactive_terminal_under_sealed_prod_is_refused`). It is an input
  to this decision, not evidence that sealed application access is supported.
- Workload stdin has a grant-gated, single-writer, secret-scanned route
  (`mvm-hostd` `stream/input_gate.rs`; `Preview` claim 17). It is stdin only:
  no program selection, no argv or env change.

The issue asks whether, and how, an authenticated owner may interact with a
running application through host-mediated message passing instead of shell or
administrative console access, without widening the sealed runtime console
surface.

### Demo boundary

The agent-environment demo may use the existing development-only terminal path,
labelled development mode. That shows no sealed production support,
production admission or release readiness. Development access is never an
automatic fallback for a sealed package. Signature verification, package
integrity, host policy, credential isolation and the sealed-console refusal stay
as they are. This ADR is for after the demo.

### Four things that must not be conflated

| Surface | What the owner reaches | Today |
| --- | --- | --- |
| Application message | A declared, typed operation the application chose to expose | Does not exist |
| Application terminal | A PTY to one declared program | Signed grant exists; refused when sealed |
| General shell / `exec` | Any program as the workload user | DevOnly verbs; refused under claim 4 |
| VM console | The guest console | Dev image only; refused when sealed (claim 15) |

## Decision drivers

1. A sealed image must not gain a shell, a PTY or a DevOnly verb (claims 4, 15).
2. Authority must come from the signed plan (claim 8), not from a connection
   that happens to be open.
3. Raw credentials stay on the host (claim 13); no guest NIC, no second
   network path (ADR-003, ADR-042). The channel is vsock.
4. Message passing is not automatically harmless: a message that selects a
   program, a path or a flag is a shell with extra steps.
5. Every grant, use, refusal and revocation is audit-visible and chain-signed.
6. Reuse the existing gates; do not grow a second decision point.

## Alternatives considered

### A. Shell or console access for owners

Rejected. It is exactly what claims 4 and 15 forbid on a sealed image, and
making it available "for owners" turns a sealed image into a conditionally
accessible one. It remains the dev-mode path.

### B. Declared application terminal on sealed images

An owner attaches a PTY to the one program the plan declares. Narrower than a
shell, but still an unstructured byte stream into an interpreter, which claim 17
notes cannot be policed by content (encoding, derivation and window-straddling
defeat the scan). It requires lifting the `SealedProd` refusal, which expands the
sealed console surface the issue says not to expand. Rejected for sealed
images; kept as the dev-mode behaviour.

### C. Application stdin plane

Reuse the claim-17 route: grant-gated, single writer, secret-scanned across
frames, refusals audited. Cheapest, and already built. But it is a raw byte
channel to whatever reads stdin, so its safety depends on the application, and
it carries no request identity, so replies and cancellation cannot be bound to a
request. Acceptable as the transport substrate for option D's framing, not as the
interface.

### D. Typed, host-mediated message channel (chosen)

The application declares a closed set of operations in its signed bundle. The
host accepts an owner request, checks it against the signed plan and local
policy, and forwards a bounded envelope to the guest agent over the existing
vsock flow multiplexing. The guest agent delivers it to the application's
declared handler; it never selects a program and never opens a PTY. Replies flow
back the same way.

### E. Per-request bearer tokens

The host mints a short-lived token per request and the guest validates it.
Rejected as the primary mechanism: the guest becomes a verifier of owner
credentials, which puts authentication state inside the workload trust boundary,
and a token leaked through a message is a replayable credential. The useful part
(a per-request nonce) is kept inside option D, verified on the host.

## Decision (D, over C's framing)

Accepted as the direction; the contract carries the exact fields and bounds.

### Authority

- **Owner** is a host-local principal, authenticated by the host with the host's
  existing signer material. Remote owners are out of scope here (see non-goals);
  fleet-level ownership belongs to mvmd.
- **Grant.** The signed `ExecutionPlan` carries an access declaration: the
  operation names the application exposes, the owner principal(s) allowed each,
  size and rate ceilings, and whether an operation may stream. A plan with no
  declaration admits no owner messages. Declaration is by the package author;
  admission is by the host; neither alone suffices.
- **Precedence.** Deny wins. Order of evaluation, first refusal ends it: sealed
  profile (never admits a terminal, shell or DevOnly verb) → signed plan
  declaration → local host policy (can only narrow) → revocation list → per-call
  limits. Local policy can remove an operation the plan permits; it can never add
  one the plan lacks.

### Envelope (host to guest)

Fields, all covered by the host's authentication of the frame:

- `instance_id` and `bundle_digest` (the admitted package and entrypoint
  identity from the signed plan). A frame naming a different instance or digest
  is refused on the host and again by the guest agent.
- `request_id` (unique per owner session) and a monotonically increasing
  `sequence`, so replay and reordering are refused.
- `operation` (a name from the declared set) and `payload` (bounded JSON or
  bytes, per operation schema).
- `deadline`, after which the host cancels and reports a timeout.
- `owner` (principal id), carried for audit only; the guest makes no
  authorization decision from it.

Replies carry `request_id`, `status` (`ok`, `refused`, `timeout`, `cancelled`,
`error`), bounded `payload`, and an exit status where the operation has one.
Unknown fields are rejected (`deny_unknown_fields`, as on every host-guest type).

### Limits and lifecycle

- Per-operation maximum request and reply size, maximum in-flight requests per
  instance (default 1), per-owner rate, and a hard deadline.
- Cancellation is a host-originated frame for a `request_id`. Signals, resize
  and detach/reattach apply only to a declared application terminal and so only
  in dev mode; message sessions have no PTY semantics.
- Owner disconnect cancels in-flight requests unless the operation is declared
  detachable, in which case the reply is retained in the stream store until
  collected or expired.
- Instance stop or restore invalidates all sessions and sequence state. A
  warm-claimed child does not inherit a parent's sessions.

### Secrets

Payloads in both directions pass the existing stream redaction and the
claim-17 style fingerprint scan before leaving the host; a match refuses the
frame and is audited. The scan is a length-and-hash match and is not a
guarantee, which this ADR does not hide. Credentials are never placed in an
envelope; the host substitutes at the egress endpoint as today (claims 10, 13).

### Audit and revocation

Chain-signed records in the tenant's audit chain (claim 8 path):
`access.granted`, `access.request`, `access.refused` (with a reason code, never
payload bytes), `access.completed`, `access.revoked`. Records carry digests and
sizes, not content, mirroring the stream plane's payload-freedom.

Revocation is a signed entry that the host checks before every forward. Lag is
bounded by the next forward on that instance, plus, for streaming operations, a
host-side re-check per frame. A revocation takes effect for in-flight requests
by cancelling them. Denial diagnostics name the failed layer from the precedence
list and nothing about the guest.

### Production-safe guest surface

Only what is needed: a dispatcher in the universal guest agent for the declared
operations, gated by the same runtime profile and signed `VerbGrant` boundary as
today. No new listener, no PTY, no `exec`, no file verbs. The set of agent verbs
a sealed profile accepts grows by exactly one (deliver-declared-operation), and
`prod_safe_grant_refuses_all_dev_only_requests` continues to hold.

## Threat model

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Confused deputy: a message makes the application act with its own authority | Operations are declared and typed; the application chooses its handlers; no free-form program or path argument | An application that turns a message into a shell is its author's bug; the plan declaration is the audit trail |
| Replay | `request_id` plus `sequence`, host and guest check; deadline | Replay across instance restart is prevented by session invalidation |
| Cross-instance use | `instance_id` and `bundle_digest` in the signed envelope, checked twice | None known |
| Escalation to a shell | Sealed profile precedence; no PTY, `exec` or file verbs added; dispatcher only reaches declared handlers | An operation declared as "run this string" defeats the design; admission should refuse operation schemas that are an unbounded string to an interpreter |
| Secret exfiltration through replies | Redaction and fingerprint scan on host; payload size caps; audit carries no bytes | Encoded or split secrets defeat the scan (as claim 17) |
| Revocation lag | Check before every forward; cancel in-flight | A request already delivered to the application may complete |
| Audit evasion | Chain-signed records; refusal is itself recorded | Tail truncation limits are those of claim 8 |
| Resource exhaustion | In-flight, size, rate and deadline bounds; counted against the instance's admitted resources | Application-internal cost of a legitimate operation |
| Dev path used as a fallback | Dev access is selected explicitly and labelled; a sealed package never falls back | Operator error in choosing a dev profile |

## Non-goals

- Any shell, PTY, `exec`, file transfer or console on a sealed image.
- Lifting the `SealedProd` refusal of `InteractiveTerminal`.
- Remote or multi-user owner authentication; fleet policy (mvmd).
- Guest-initiated outbound requests to the owner; the guest has no new network
  path.
- A new numbered claim, or promotion of claim 17.
- Changing the demo, which uses the labelled dev path.

## Test and witness plan

Unit and integration (on every PR):

- Unauthorized caller refused; wrong application, wrong instance and wrong
  `bundle_digest` refused on host and guest.
- Replayed `request_id` and out-of-order `sequence` refused.
- Operation not in the declaration, or removed by local policy, refused with the
  layer named.
- Oversize request or reply, rate excess and deadline expiry bounded and audited.
- A secret in a reply is refused; no envelope or audit record contains a
  credential.
- Revocation mid-request cancels it.
- Precedence: local policy cannot add an operation; sealed profile overrides a
  plan that declares a terminal.
- Fuzz the envelope parser alongside the existing vsock framing targets.

Witness (required before any claim language, per the issue): on a real sealed
image, with a plan that declares one operation, the owner (a) completes that
operation and receives its reply, (b) is refused for an undeclared operation, a
foreign instance and a replayed request, (c) cannot obtain a shell, PTY or
DevOnly verb, with `console_refused_on_sealed_image` and the
`guest-agent-runtime-boundary` job still green, and (d) leaves a verifiable
chain-signed trail via `mvmctl trust audit verify`. Development-only tests do not
satisfy this.

## Open questions for the owner

1. Is typed host-mediated messaging wanted at all, or is "no owner access to a
   sealed workload" the permanent answer?
2. Who is the owner: the host user only, the plan signer, or a delegated
   principal? How is a second owner added and removed?
3. Where does the operation declaration live: the package bundle, the plan, or
   both with the plan narrowing?
4. Is stdin framing (option C as transport) acceptable, or should the channel be
   a new typed flow?
5. Should detachable operations and retained replies exist in the first version?
6. What default limits (size, in-flight, rate, deadline) ship?
7. Does this belong in `mvm`, or only as a local primitive with fleet behaviour
   left to mvmd?
8. Should claim-bearing language wait for the sealed-image witness, as proposed
   here, or for something stronger?

## Consequences

Because it is accepted: a new plan-level declaration, one new agent verb, one gate module
beside the input gate, five audit event kinds, and the tests above. Until it is implemented,
sealed images stay owner-inaccessible and dev mode stays the only interactive
path.
