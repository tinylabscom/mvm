# Owner-mediated application access

Backing: preview
Validation: none — this contract defines required behavior; the channel it describes is not implemented.

This contract belongs to [#4460](https://github.com/tinylabscom/mvm/issues/4460),
which owns status. The direction is decided in
[ADR-056](../adrs/056-owner-mediated-application-access.md); this document fixes
the interface. It adds no numbered claim and promotes none. Claims 4, 8, 12, 13,
15 and 17 keep the wording in ADR-001, and nothing here widens the sealed
runtime console surface.

## Scope and separation

Two modes, never merged:

| Mode | Access | Selected by |
| --- | --- | --- |
| Dev / demo | Existing PTY console and application terminal, labelled development mode | Explicit dev profile |
| Sealed production | Typed application operations only. No shell, PTY, `exec`, file verb or DevOnly verb | The signed plan's access declaration |

A sealed package never falls back to the dev path. A refused operation is not
retried through another surface. `SealedProd` keeps refusing
`InteractiveTerminal` (`interactive_terminal_under_sealed_prod_is_refused`).

## Authorization

- **Owner** is a host-local principal: the OS user that owns `~/.mvm` (mode 0700),
  authenticated by the host process holding the host signer key
  (`~/.mvm/keys/host-signer.ed25519`). Possession of an open connection or of a
  guest-visible value is never authority. A second owner is a plan-declared
  principal id and is added or removed only by a new signed plan; there is no
  runtime delegation in v1. Remote and fleet owners belong to mvmd.
- **Declaration.** The package author declares operations in the bundle; the
  plan that admits the package carries the declaration (operation names, schema
  digest, per-operation ceilings, permitted principals). The plan may narrow the
  bundle's declaration and never add to it. No declaration admits no owner
  message.
- **Binding.** Every request is bound to the admitted application, the exact
  `instance_id`, the plan digest, and the signed entrypoint identity (the
  entrypoint's own digest from the plan, not only the bundle digest). Any
  mismatch is refused on the host, and again by the guest agent.

## Policy precedence

Deny wins; the first refusal ends evaluation and names its layer:

1. Sealed profile (never admits a terminal, shell or DevOnly verb)
2. Signed plan declaration
3. Local host policy (can only narrow)
4. Revocation list
5. Per-call limits (size, rate, in-flight, deadline)

## Message protocol

Transport is the existing vsock flow multiplexing between the host and the guest
agent. No new listener, guest NIC or socket. Frames are JSON,
`deny_unknown_fields`, one frame per flow message, authenticated by the host
under the existing authenticated-frame scheme.

Request (host to guest):

| Field | Type | Bound |
| --- | --- | --- |
| `instance_id` | string | exact match with the admitted instance |
| `plan_digest` | sha256 hex | exact match |
| `entrypoint_digest` | sha256 hex | exact match with the signed entrypoint |
| `session_epoch` | u64 | minted by the host per boot or restore; never reused |
| `request_id` | string | 1..=64 bytes, `[A-Za-z0-9_-]`, unique within the epoch |
| `sequence` | u64 | strictly `previous + 1` within the epoch |
| `operation` | string | 1..=64 bytes, a declared name |
| `payload` | JSON | per-operation ceiling, hard cap 64 KiB |
| `deadline_ms` | u32 | 1..=300000, relative to delivery |
| `owner` | string | audit only; the guest makes no decision from it |

The whole frame is at most 128 KiB, far under `MAX_SERVICE_PROXY_FRAME_BYTES`.

Reply (guest to host): `request_id`, `status` (`ok`, `refused`, `timeout`,
`cancelled`, `error`), `payload` (per-operation ceiling, hard cap 64 KiB),
optional `exit_status` (i32). Cancel (host to guest): `request_id` only.

Defaults when a declaration is silent: one in-flight request per instance,
10 requests per minute per owner, 30 s deadline, 16 KiB request, 16 KiB reply.
A declaration may raise these only up to the hard caps above.

Replay: a request is refused unless `session_epoch` is current and `sequence` is
exactly the next value; a repeated `request_id` is refused. Instance stop,
restore or fork mints a new epoch, so restoring a snapshot cannot revive
authority to replay an old valid envelope. A warm-claimed child gets its own
epoch and inherits no session.

An operation schema that is an unbounded string handed to an interpreter is
refused at admission. Schema screening cannot prove a handler safe; an
application that turns a message into a command is its author's defect, and the
declaration is the audit trail.

## Lifecycle

- **Open.** First request for an instance opens a session at a new epoch after
  the policy layers pass.
- **Cancel.** Host-originated, per `request_id`. Side effects already delivered
  are not undone.
- **Timeout.** The host cancels at the deadline and reports `timeout`.
- **Disconnect.** Owner disconnect cancels in-flight requests. Detachable
  operations and retained replies are not in v1.
- **Detach/reattach, resize, signals.** Exist only for an application terminal
  and therefore only in dev mode. Message sessions have no PTY semantics.
- **Exit status.** Returned in the reply when the operation defines one;
  otherwise absent.
- **Stop/restore.** Invalidates every session and sequence state.

## Credentials

Credentials never appear in a request, reply, environment, kernel command line
or audit record. Payloads in both directions pass the claim-17 style fingerprint
scan before leaving the host; a match refuses the frame. The scan is a
length-and-hash match, not a guarantee. Egress credentials stay host-side
(claims 10, 13).

## Audit and revocation

Chain-signed entries on the claim 8 path: `access.granted`, `access.request`,
`access.refused` (reason code and failed layer, never payload bytes),
`access.completed`, `access.revoked`. Entries carry digests and sizes only.

Revocation is a signed entry checked before every forward and, for any
streaming operation a future version adds, per frame. It cancels in-flight
requests. A request already delivered to the application may still complete.

## Denial diagnostics

A refusal names the failed layer from the precedence list and a stable reason
code, and nothing about guest internals. The same text is the audit reason.

## Acceptance map (issue #4460)

| Bullet | Status |
| --- | --- |
| 1. Alternatives and threat model recorded | Specified in ADR-056 |
| 2. Authorization, protocol, precedence, lifecycle specified | Specified here |
| 3. Dev/demo separate from sealed production | Specified here; sealed refusals tested by `console_refused_on_sealed_image`, `gate_force_does_not_bypass_sealed_refusal`, `interactive_terminal_under_sealed_prod_is_refused`, `prod_safe_grant_refuses_all_dev_only_requests` |
| 4. Tests: unauthorized caller, wrong app/instance, replay, denied capability, credential non-disclosure, bounded use | Unauthorized caller on the existing input route: `input_is_refused_without_a_plan_grant`, `a_second_writer_is_refused_while_the_lease_is_held`. Replay/order on that route: `a_frame_that_does_not_advance_the_sequence_is_refused_rather_than_reordered`. Refusals audited: `every_refusal_is_audited`. Credential non-disclosure: `handed_placeholders_never_contain_the_secret_value`, `secret_material_split_across_frames_is_still_refused`, `stream_audit_entries_carry_the_binding_and_no_payload_bytes`. Unknown fields: `service_call_rejects_unknown_envelope_fields`. Unbound service refused: `unbound_service_returns_not_bound`. Write-only console: `following_the_console_never_writes_to_it`. **NOT YET IMPLEMENTED — slices 2-5** for wrong instance/entrypoint, epoch replay, declared-operation denial, and message bounds, because the message channel has no code |
| 5. Witness on a real sealed image | **NOT YET IMPLEMENTED — slice 6** |

## Implementation slices

Each is independently mergeable and leaves production behavior unchanged until
slice 5 is enabled.

1. **Contract types.** `mvm-contract` request/reply/cancel DTOs with the bounds
   above, `deny_unknown_fields`, serde round-trip and bound-rejection tests, and
   a fuzz target beside the vsock framing targets. Acceptance: oversize,
   unknown-field and malformed frames rejected.
2. **Declaration and admission.** Bundle declaration, plan field narrowing it,
   admission refusal of interpreter-string schemas. Acceptance: no declaration
   admits nothing; local policy cannot add an operation.
3. **Host gate.** A gate module beside `input_gate.rs`: precedence ladder,
   instance/plan/entrypoint binding, epoch and sequence replay refusal, limits,
   fingerprint scan, `access.*` audit entries. Acceptance: the negative tests in
   ADR-056's test plan pass against a mock guest.
4. **Revocation and lifecycle.** Revocation entry, cancel, timeout, disconnect,
   epoch minting on stop/restore/fork. Acceptance: revocation mid-request
   cancels; a restored snapshot refuses an old envelope.
5. **Guest dispatcher.** One new verb in the universal agent, delivering only
   declared operations, gated by the runtime profile and signed `VerbGrant`.
   Acceptance: `prod_safe_grant_refuses_all_dev_only_requests` still holds and
   the verb is refused without a grant.
6. **Sealed-image witness.** On a real sealed image with one declared operation:
   completes it, is refused for an undeclared operation, a foreign instance and a
   replay, cannot obtain a shell/PTY/DevOnly verb, and `mvmctl trust audit
   verify` passes. Only then may claim language be considered.

## Open items

Fleet or remote owners (mvmd), detachable operations, and any new numbered
claim are deferred and need their own decision.
