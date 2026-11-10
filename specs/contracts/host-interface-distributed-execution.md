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

## Demo narrative and validation script

The customer-facing story is:

> Keep the mission running, even when you can no longer trust one of its AI
> workloads.

Do not lead with microVMs or a remote-wipe button. Lead with the operational
dilemma: the customer wants intelligence at the edge, but a compromised AI
must not become a bridge into the rest of the mission. Position MVM as the
execution and containment layer, not as the entire tactical communications
network or fleet-management platform.

The first demo is a **closed mission network with a closed control loop**:
three simulated edge nodes—ship, aircraft, and ground vehicle—communicate
through authorized mailbox/message-box operations without public Internet or
cloud dependency. This is networked closed-loop operation, not a claim that
physically air-gapped platforms can communicate without an approved transfer
path.

### 8–10 minute sequence

1. **Establish the mission.** Each node runs an isolated advisory AI task over
   synthetic sensor observations. The aircraft sends an approved observation
   to the ship; the ship sends an approved summary to the ground vehicle.
   This proves useful collaboration without unrestricted connectivity.
2. **Cut the uplink.** Disconnect one node from headquarters. It continues
   preauthorized local processing under its offline lease. The console shows
   it as disconnected, not remotely contained or wiped.
3. **Introduce a deterministic compromise.** A planted malicious input causes
   the ground workload to attempt an unauthorized mailbox operation,
   outbound connection, or sensitive-data request. Do not rely on a live model
   deciding to behave maliciously.
4. **Show the boundary holding.** The host interface denies the operation and
   records the request in the assurance/audit view. Other nodes continue their
   mission.
5. **Contain and recover.** The operator quarantines the suspect workload,
   revokes its authority, terminates it, and launches a replacement from an
   approved image. The replacement receives a new execution epoch and fresh
   capabilities; stale messages and credentials are rejected.
6. **Close with evidence.** Show a timeline containing admission, policy,
   approved launch, mailbox activity, denied request, assurance finding,
   containment, termination, and replacement.

The emotional high point is the unaffected nodes continuing the mission, not a
red wipe animation. The policy card beside each workload should show:

- assigned synthetic data it may read;
- approved mailbox destinations and reporting service;
- advisory output only, not executable platform commands;
- resource and lifetime budget;
- absence of the reporting service's raw credential;
- response on suspected compromise: deny, contain, terminate, and replace.

The demo must distinguish what is already implemented from integration work:
workload isolation, controlled egress/credential handling, signed launch
provenance, protected images, and mailbox security primitives are foundations;
multi-node dashboarding, live mailbox delivery, quarantine workflow,
authenticated inter-platform messaging, and remote recovery require end-to-end
verification before being presented as shipped capabilities.

The first demo promises **contain, terminate, and rebuild**. It does not
promise verified physical wipe. A remote command cannot immediately affect a
disconnected node, and revocation takes effect only where current revocation
state is known or an offline lease has expired.

### Demo status: what runs today

`crates/mvm-hostd/tests/mission_demo.rs` scripts the sequence above across
three nodes, and `features/suites/s40_mission_demo/` runs it as a conformance
scenario. Run it with
`cargo nextest run -p mvm-hostd --test mission_demo --no-capture`.

Mailbox encryption is host to host: a guest's outbox carries plaintext and a
recipient, and the host service seals and signs it under keys the host holds,
so the host sees the plaintext and a compromised host agent can read messages.
Guest-to-guest or host-blind delivery would need hardware-backed attestation
(key release only to an attested guest), a separate high-assurance track that
is not built.

#### Hermetic (CI)

- The three-node demo: launch preflight and per-workload ledger, quarantine and
  replacement with chain-signed entries, the signed offline lease, the command
  replay gate, the reconnect challenge, and the sealed mailbox envelope with its
  capability, replay and execution-epoch checks. The nodes are simulated nodes
  in one test process; their VMs are gated and audited, and none boots.
- One-host delivery: the sender's sealed envelope crosses a Unix domain socket
  to the receiving node's `MailboxService` (`mvm-hostd::mailbox_service`), which
  opens it and enqueues it under a bounded queue; refusals return as typed
  replies. Only the aircraft node runs a service.
- Two-node delivery: `two_nodes_deliver_over_a_loopback_tcp_peer_transport`
  uses a loopback TCP `PeerTransport` between two nodes with separate state
  directories and audit chains, inside one test process. The transport is
  test-support only.
- The guest mailbox host process (`mvm-mailbox`) and the guest-side outbox are
  covered by their own tests; no booted guest is involved.

#### Live-witnessed (manual, Firecracker and HVF)

The guest mailbox is a backend capability (`VmCapabilities::guest_mailbox`) with
a host-dialed vsock port (`GuestService::Mailbox`). Firecracker and HVF declare
it and serve it. Each was witnessed by its own manual run, and neither is a CI
lane: Firecracker needs a KVM host and a runtime bootstrap of roughly 22
minutes (recorded in issue #5121), and HVF needs a macOS 26+ Apple Silicon
host with a source-built guest runtime.

Firecracker: three runs on a real KVM host (dev profile, alpine guest)
observed the guest-mailbox chain end to end, and a fifth run on a later source
head observed multi-message delivery (below). Observed in the first three:

- A granted run (`--mailbox <64-hex id>`) boots with exactly one `mvm.mailbox=1`
  on the guest command line. Only then does the guest agent create
  `/run/mvm/mailbox` (uid 901, mode 0700). The host spawns a separate
  `mvm-mailbox` process holding derived keys only: its argv is just its path,
  and its environment and argv contain no seed-like hex, mailbox id or
  host-signer path. Its socket is mode 0600.
- A test-only writer calling `mvm_agentd::mailbox_outbox::write_outbox` as uid
  901 delivered one frame to the host. `mvmctl machine mailbox recv <name>`
  returned the exact plaintext, then empty. The chain-signed `mailbox.read`
  entry carries the length and totals but not the body (no plaintext or base64
  match in the audit log), and `mvmctl trust audit verify` passed.
- Addressing: the guest may name the all-zero recipient or its own mailbox id.
  Any other recipient is refused: the guest console shows the refusal, `recv`
  returns empty, and the refusal text leaks nothing.
- `machine stop` leaves no `mvm-mailbox` process (gone within about 2 s). An
  ungranted VM has no token, directory, process or socket.

HVF (isolated `MVM_HOME`, `--builder hvf --hypervisor hvf`, source-built guest
runtime): one run observed the same properties on the in-house VMM. That run
predates multi-message delivery and the re-dial window change: it delivered one
message per VM and the host dialed for about 30 s. HVF has not been
re-witnessed with either, and a re-witness is pending. Observed:

- Exactly one `mvm.mailbox=1` on the guest command line; `/run/mvm/mailbox` is
  mode 0700 and owned by the workload user (uid 901).
- The host `mvm-mailbox` process has a one-word argv and no mailbox id, key or
  seed path in its environment. `mailbox.sock` is mode 0600.
- A frame written as uid 901 (a 32-byte all-zero recipient followed by the body)
  was returned exactly by `mvmctl machine mailbox recv`. The frame was written
  from the workload's own boot command: a later `machine exec` missed the
  host's dial window under heavy load.
- `mvmctl trust audit verify` passed, and the `mailbox.read` entry carries
  counts only, no body.
- `machine stop --yes` ended the mailbox process within 1 s. An ungranted run
  had no token, directory, process, socket or bridge.

Many messages per granted VM (Firecracker, a real KVM host, source head at the
change that makes the host bind one `MailboxService` and re-dial for the
launch's life into the same queue; manual, not a CI lane). Observed:

- Message A, then message B two seconds later, were each returned exactly by
  `mvmctl machine mailbox recv`; an empty queue prints nothing and exits 0.
- A frame addressed to a wrong recipient was refused and returned empty, and two
  valid frames written afterwards were both delivered: a refused frame never
  stops the loop.
- `recv` in a tight loop for 20 s (186 calls) while three messages arrived 4 s
  apart returned each exactly once, in order, with no loss, duplicate or hang.
  The idle `mvm-mailbox` process used about 0.2% CPU and about 5 MB RSS.
- 100 writes 0.15 s apart returned exactly the first 64: a full queue (64
  messages) drops newer messages and keeps the oldest, the guest console logs
  `mailbox queue is full (64 messages)`, and the process stayed alive with flat
  RSS and `recv` still working.
- `machine stop` ended `mvm-mailbox` about 2.6 s later for every VM, including
  one that never received a frame, leaving no sockets.
- Exactly one `mvm.mailbox=1`; `/run/mvm/mailbox` uid 901 mode 0700, socket
  0600; no seed, mailbox id or host-signer path in the process environment or
  argv; an ungranted VM has none of it; `recv` on a nonexistent or ungranted
  name fails cleanly. `trust audit verify` passed and `mailbox.read` entries
  carry counts only.
- Three concurrent granted launches while a stop ran all had a `plan.json` and
  served `recv`. Pool-claimed VMs lacked `launch.sh`; whether that predates this
  work is not confirmed.

The outbox is a spool directory, `/run/mvm/mailbox/outbox/`: one file per
message, delivered oldest first, one frame per host dial. A writer adds a file
atomically and is refused (`QueueFull`) once 256 are waiting. This replaced a
single file in which a second write overwrote the first. The burst fix is
hermetic-tested only; a live back-to-back burst has not been re-run.

Guest console noise is bounded: while the host re-dials, the guest logs
`mailbox frame not delivered` (9 to 17 lines over a 20 s run), and an idle VM
logs 6 to 9 `frame is malformed` lines in its first 70 s or so. The source of
the `malformed` lines has not been traced.

Reproduce, on a Linux host with KVM and a sibling or installed mvm-images set:

```sh
cargo build                                   # mvmctl
export MVM_FIRECRACKER_BIN=<path to the pinned firecracker>  # Linux source build, first launch
cargo build -p mvm-hostd --bin mvm-mailbox    # beside mvmctl; or set MVM_MAILBOX_PATH
MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build ./target/debug/mvmctl bootstrap
./target/debug/mvmctl machine run --image alpine --mailbox <64-hex id> \
    --hypervisor firecracker --name n -- sleep 900
# as uid 901 in the guest (machine cp / machine exec), run a writer that
# calls mvm_agentd::mailbox_outbox::write_outbox (or writes a dot-prefixed
# temp file in /run/mvm/mailbox/outbox/ and renames it to a name that sorts
# after every earlier one); no need to wait between frames
./target/debug/mvmctl machine mailbox recv n  # each plaintext once, then empty
./target/debug/mvmctl trust audit verify
./target/debug/mvmctl machine stop n --yes    # no mvm-mailbox process remains
```

The HVF variant runs on macOS 26+ Apple Silicon with the same sequence, adding
`--builder hvf` and using `--hypervisor hvf` in place of `--hypervisor
firecracker`. The HVF run wrote its frame from the workload's own boot command.

All witnesses are in the dev profile and manual.

#### Not wired / not claimed

- libkrun, QEMU, apple-container, wasm and the mock backend refuse a granted
  plan before boot. libkrun and QEMU accept arbitrary host-dialed ports, but
  they bind them at the flat per-port path while the mailbox process dials the
  `vsock/` subdirectory path HVF uses; reconciling the two is a follow-up.
- A granted warm-claimed or forked HVF child is untested.
- Late frames: the host re-dials every 100 ms for about 30 s, then every 2 s
  for the VM's life, so a late frame is delivered. Firecracker witnessed this;
  HVF has not been re-witnessed.
- A full host queue of 64 drops newer messages, and a full spool of 256 refuses
  the writer. Neither is a delivery guarantee.
- Multi-message delivery is Firecracker-witnessed only; HVF delivered one
  message per VM when last run.
- `build_config` still names the per-port socket and the Firecracker mux path
  itself rather than taking them from the backend, because `GuestChannelInfo`
  carries only a cid and a port. Moving that onto the backend is a follow-up.
- `machine run -d` printed an unrelated `session i/o error` on the HVF run
  although the machine ran.
- There is no cross-host transport in the product and no node-to-node delivery
  between physical hosts. Iroh is not wired (#4633 is open); the loopback TCP
  transport above exists only in tests.
- The live runs are manual witnesses, not CI lanes.
- The three-node demo boots no VM, and no test attests hardware.
- Mailbox encryption is host to host, as described above.
