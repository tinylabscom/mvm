# Host interface and distributed execution

## Status

Proposed implementation plan. The GitHub issue linked from this document is the
authoritative work tracker; this file is the immutable design attachment for
the work.

## Summary

Add a transport-independent host interface between every microVM and the
services that launch, constrain, observe, and recover it. The interface must
support both:

- the existing local product workflow; and
- distributed edge nodes managed through `mvmd` and `mvm-studio`.

The microVM must not need to know whether its host interface is local,
hosted, or remote. Security controls must be established before launch and
must fail closed when required policy or enforcement cannot be verified.

The existing UX remains primary:

```text
pull pack
run pack
mvmctl run <name>
mvmctl machine run
```

Central admission, distributed control, attestation, and remote telemetry are
optional deployment capabilities selected by configuration or policy. They
must not introduce a mandatory enrollment command for local users.

## Goals

1. Define a stable host-interface contract with local and remote
   implementations.
2. Preserve local execution and pack workflows unchanged.
3. Support distributed nodes communicating through bounded, authenticated
   mailbox operations.
4. Prevent a microVM from starting when policy, image, volumes, secrets,
   resources, or enforcement controls are tampered with or unavailable.
5. Make TPM/TEE attestation optional by default, with stronger assurance
   available through policy.
6. Provide policy-governed volumes, secrets, egress, mailbox access, resource
   limits, telemetry, lifecycle, and recovery.
7. Support disconnected operation through signed local policy and explicit
   offline leases, followed by safe reconnect and reconciliation.
8. Preserve the product's existing telemetry, auditing, attestation, reporting,
   logging, and alerting capabilities across local and distributed modes.
9. Meet the launch performance budgets: less than 300 ms cold and less than
   50 ms warm preflight/launch overhead, subject to measurement and profiling.

## Non-goals

- Guaranteeing secure erasure from arbitrary physical storage.
- Proving that an AI workload is behaviorally trustworthy.
- Solving a compromised host OS without hardware-supported isolation.
- Making TPM, TEE, or hardware attestation a hosted-service prerequisite.
- Turning local volumes into implicitly shared distributed filesystems.
- Making `mvmd` mandatory for local execution.
- Selecting Hydro or Cap'n Proto before protocol and consistency requirements
  are documented.
- Claiming mailbox delivery is end-to-end complete until the runtime wiring and
  delivery semantics are validated.

## Deployment modes

### Local default

- Local host interface.
- Local policy and identity.
- No central admission.
- No required TPM/TEE.
- Existing `mvmctl` and pack commands.
- Existing local telemetry path.

### Managed distributed

- Host interface connects to an authorized `mvmd` control/data-plane service.
- Node admission is enabled by profile or policy.
- Policy, revocation, mailbox routing, lifecycle, and telemetry are coordinated.
- Admission is automatic at first launch and appears as a pending request in
  `mvm-studio`; users do not need a new enrollment command.

### High-assurance

- Managed distributed mode.
- Policy explicitly requires hardware-backed attestation.
- Launch fails if the required assurance level is unavailable or invalid.

Default policy behavior is equivalent to:

```yaml
attestation:
  required: false
```

Evidence may still be collected when available. The effective assurance level
must be visible and must never be represented as hardware verified when it is
not.

## Host-interface responsibilities

The interface must cover:

- node identity and admission;
- workload identity and execution epochs;
- signed policy acquisition and validation;
- launch preflight and enforcement setup;
- secret brokering and short-lived leases;
- named volume grants;
- mailbox and egress mediation;
- quotas, fair scheduling, and circuit breakers;
- assurance findings;
- canonical telemetry and audit events;
- authenticated heartbeat and reconnect;
- quarantine, termination, revocation, eviction, and replacement.

Candidate operations:

```text
attest()
admit()
get_policy()
authorize_workload()
request_secret()
mount_volume()
request_egress()
send_mailbox_message()
receive_mailbox_message()
report_event()
heartbeat()
quarantine_node()
revoke_node()
terminate_workloads(selector)
kill_node()
```

The user-facing lifecycle should remain small:

- `Pending`
- `Active`
- `Quarantined`
- `Revoked`

Disconnected, degraded, and reconnecting are conditions on those states, not
separate primary states.

## Admission and identity

Local mode admits locally without central identity. Managed mode creates a
pending admission request automatically when the host agent first connects.
`mvm-studio` can approve or reject it using node metadata, key fingerprint,
inventory identity, and available assurance evidence.

Admission must be:

- idempotent;
- auditable;
- bound to a public key;
- scoped to a tenant/fleet;
- revocable;
- independent of network reachability alone.

Use a fresh challenge, signatures, session keys, sequence numbers, execution
epochs, and expiry. A shared clock or random number generator alone is not an
authentication or replay-protection mechanism.

## Launch fail-closed invariant

The microVM must not start unless all required checks pass:

1. Load and verify policy signature, issuer, version, scope, and expiry.
2. Verify workload image identity/digest.
3. Verify host-agent and enforcement-provider integrity.
4. Validate node admission, revocation, and execution epoch.
5. Validate volumes, resource reservations, mailbox, egress, and secret grants.
6. Collect attestation when required.
7. Create the enforcement boundary.
8. Start the microVM only after the boundary is established.
9. Emit an authenticated launch receipt and telemetry event.

Independent checks should run concurrently. Cached warm-path results must be
bound to node identity, policy version, image digest, epoch, and validity
deadline. Revocation and dynamic capacity checks must not be bypassed by cache.

## Policy-governed volumes

Continue supporting trusted host locations in read-only and read-write modes,
but expose them as named volume grants rather than arbitrary guest paths:

```yaml
volume:
  id: mission-observations
  source: /trusted/observations
  guest_target: /data/observations
  mode: read_only
  scope: node_local
  purpose: sensor-input
```

Volume policy must enforce path containment, symlink safety, ownership,
mount options, quotas, device/socket exclusion, lifecycle behavior, and
telemetry. Read-write grants require explicit policy. Distributed workloads
must not assume that a node-local volume exists on another node; cross-node
data movement uses authorized mailbox/object transfer or an explicitly
designed shared-volume provider.

The same canonical policy is authored through CLI and `mvm-studio`.

## Resource and traffic governance

The policy and runtime must include:

- admission control by capacity and assurance;
- per-tenant, per-node, per-workload, and per-epoch quotas;
- fair scheduling and noisy-neighbor protection;
- mailbox and egress token buckets;
- circuit breakers;
- payload, nesting, serialization, and decompression bounds;
- dead-letter handling;
- secret/capability lease limits;
- audit-pressure controls that retain security events;
- resource accounting;
- explicit fail-open/fail-closed behavior for every dependency.

Adversarial tests must cover queue flooding, decompression bombs, telemetry
flooding, reconnect storms, resource starvation, repeated denied egress, and
secret lease exhaustion.

## Distributed control plane

`mvm-studio` is the operator surface; it need not be the sole control-plane
instance. `mvmd` may be deployed as a distributed service. The design must
specify:

- replicated state and leader behavior;
- strong versus eventual consistency by data type;
- policy and revocation propagation;
- partition behavior;
- duplicate and out-of-order delivery;
- idempotent commands;
- reconciliation after reconnect.

Admission, identity revocation, and policy publication require stronger
coordination than telemetry and usage reports. Hydro and Cap'n Proto may be
evaluated as implementation choices after these protocol requirements are
written down.

## Offline and reconnect behavior

A node may operate disconnected only under a signed, preloaded policy lease
that defines duration, allowed operations, secret use, queued-message rules,
and expiry behavior.

Reconnect requires a fresh authenticated session, current attestation when
required, policy/revocation reconciliation, queue reconciliation, and epoch
validation. A network connection never restores authorization by itself.

## Secrets and cryptography

Use separate keys for identity, transport, mailbox encryption, telemetry,
policy signing, and data encryption. Use short-lived secret leases, avoid
plaintext logging, and keep private keys/plaintext secrets memory-only by
default. Temporary encrypted state is allowed only with explicit lifecycle
and cryptographic-erasure semantics.

End-to-end mailbox encryption protects content from routing components but
does not make a compromised host agent blind to workload memory or requests.
Zero-knowledge proofs are not a first implementation requirement.

## Observability

The distributed host interface must emit the same canonical telemetry model
as the current product, including:

- admission and attestation;
- policy changes;
- launch and enforcement;
- volume, secret, mailbox, and egress operations;
- denials and limit violations;
- assurance findings;
- heartbeats, reconnects, and telemetry gaps;
- quarantine, revocation, termination, replacement, and kill actions.

Events need identity, tenant, node, workload, epoch, policy version, sequence,
severity, timestamp/clock quality, payload, and integrity metadata. Local
buffering, priority retention, deduplication, and reconnect upload are
required. `mvm-studio` must distinguish current, last-known, and missing
evidence.

## Hosted-service requirements

For public paid hosting, add tenant isolation for identities, policies,
mailboxes, volumes, secrets, telemetry, audit, quotas, and billing. Define
data residency, retention, export, deletion, key destruction, incident
response, and provider-host assurance claims.

## Work breakdown

1. Write the host-interface contract and error model.
2. Define policy schema and defaults.
3. Define node/workload state machine and epoch rules.
4. Define admission, identity, challenge, replay, and revocation protocol.
5. Implement local host-interface adapter without changing existing CLI UX.
6. Implement launch preflight and fail-closed enforcement setup.
7. Add named volume grants and CLI/UI policy authoring.
8. Add resource and traffic governance.
9. Integrate optional attestation providers.
10. Integrate distributed `mvmd` control and mailbox providers.
11. Preserve and extend canonical telemetry.
12. Add reconnect, offline lease, and reconciliation behavior.
13. Add hosted multi-tenant isolation and retention controls.
14. Add performance, failure-injection, security, and BDD coverage.

## Acceptance criteria

- Existing local pack and `mvmctl` workflows work without central admission.
- Managed admission is automatic and visible in `mvm-studio`; no new mandatory
  enrollment command exists.
- TPM/TEE absence does not block default deployments.
- Explicit hardware-assurance policy blocks launch when hardware evidence is
  required but unavailable or invalid.
- Tampered/expired/revoked policy cannot launch a microVM.
- Missing enforcement, invalid volume grants, unavailable required secrets,
  or failed required preflight blocks launch.
- Local and remote host-interface implementations share the same contract.
- Node-local volumes remain supported in read-only and explicitly authorized
  read-write modes.
- Mailbox and egress operations are independently authorized and bounded.
- Disconnected operation follows a signed lease and reconnect rejects replayed
  or stale commands.
- Quarantine, revoke, terminate, replace, and kill actions are audited.
- Existing telemetry coverage is retained and distributed telemetry reports
  evidence gaps explicitly.
- Tenant data and control-plane state are isolated in hosted deployments.
- Cold and warm launch preflight overhead is measured against the 300 ms and
  50 ms budgets.
- Security tests cover tampering, replay, wrong keys, expiry, revocation,
  reconnect, quota exhaustion, volume escape, and telemetry integrity.
- Full repository validation passes before implementation is considered done.

## Open decisions

The implementation issue must resolve, with evidence:

- exact host-interface transport for local and remote modes;
- `mvmd` replication and consistency mechanism;
- whether Hydro or Cap'n Proto is appropriate;
- supported TPM/TEE providers and attestation report format;
- offline lease defaults;
- mailbox delivery and retention guarantees;
- encrypted temporary-storage and key-destruction guarantees;
- hosted retention, billing, and data-residency requirements;
- exact CLI/UI policy-authoring surface.

## Session coverage checklist

This section records the earlier design decisions that must not be lost when
the work is decomposed:

- The companion host process runs as a non-root user, with privilege separation
  from the microVM and least-privilege access to host resources.
- The host process generates a node keypair locally and shares only the public
  identity during admission. Private keys remain local and are protected by the
  strongest available storage mechanism.
- Control-plane and host-agent traffic is mutually authenticated and encrypted
  in transit. Sensitive temporary state is encrypted at rest when it cannot
  remain memory-only.
- Heartbeats are authenticated, encrypted liveness/health reports. Compression,
  including UOR where that is an approved transport optimization, is not a
  substitute for encryption or integrity.
- `mvm-assurance` findings and unexpected traffic/request patterns feed the
  host-interface assurance and telemetry pipeline.
- The host interface owns egress mediation, secret brokering, mailbox
  authorization, policy enforcement, assurance reporting, and lifecycle
  controls, whether the implementation is local or remote.
- Mailbox/message-box communication is the bounded node-to-node data path. A
  mailbox grant does not grant arbitrary network access, control-plane access,
  or shell access.
- The closed-loop story means a private mission network with local policy and
  bounded communication that can continue during disconnection; physical
  air-gapped operation requires a separate approved transfer path.
- Shutdown and termination attempt memory zeroization and revoke active
  sessions. Strong physical erasure is not claimed; cryptographic erasure is
  the supported mechanism for encrypted temporary state.
- Workload containment distinguishes terminate, revoke authority, quarantine,
  evict/revoke a node, kill a node, destroy data, and replace from a known-good
  image.
- Node replacement receives a new execution epoch and cannot use stale
  mailbox messages, capabilities, secrets, or commands.
- Trusted-location volumes remain supported as named read-only or explicitly
  authorized read-write grants, configurable through both CLI and
  `mvm-studio`.
- The local product remains usable without central auth, TPM/TEE, `mvmd`, or a
  security warning banner. Managed and high-assurance behavior is opt-in.
- The hosted paid service may use distributed `mvmd` without requiring
  hardware attestation from every provider host.
- Policy and enforcement tampering blocks microVM startup. Independent
  preflight checks run concurrently so this invariant is compatible with the
  cold and warm launch budgets.

