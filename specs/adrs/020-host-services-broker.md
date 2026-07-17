# ADR-020: Host services broker over vsock

## Status

Accepted

## Context

A running microVM's only host-facing channels are its boot-time content (an
image and any explicitly declared read-only volumes) and the fixed vsock RPC
the guest agent already speaks for host-initiated lifecycle control. Neither
gives a workload a way to call back into the host and have that call land on
the same tamper-evident record its own admission already writes to (claim
8's chain-signed audit log). A workload that wants to assert something about
its own execution, for its operator to review later, has no host-side
channel for that today.

Any such channel is guest-reachable, so it is untrusted-input surface: a
hostile or merely buggy guest must not be able to forge which workload a
call came from, address another workload's audit chain, or reach a host
capability it was never registered for. And it has to fit how mvm actually
runs — many microVMs per host, belonging to relatively few tenants — so a
channel that costs a process (or several) per VM does not fit. The isolation
this needs is per *role* (the part that parses untrusted frames vs. the part
that holds a signing key), not per VM.

## Decision

```
guest workload
  │ vsock BROKER_PORT (5300)           [crates/mvm-guest/src/broker_client.rs]
  ▼
per-VM Unix socket                     (bound on Register, one per VM)
  │
mvm-host-agent — per tenant, keyless   [crates/mvm-hostd/src/broker/daemon.rs]
  │ per-VM Registry: dispatch, or NotBound
  │ UDS (already-gated append requests only)
  ▼
mvm-signer-helper — per tenant, holds the chain-signing key
  │ appends
  ▼
workload_audit_path(tenant, vm)        [mvm_core::config::workload_audit_path]
  JCS-canonical, hash-chained, Ed25519-signed
```

### Wire envelope and identity

A workload reaches the host over one small typed envelope:
`ServiceCall { service, verb, correlation_id, payload }` out,
`ServiceResponse::Ok { correlation_id, payload }` or
`::Err { correlation_id, code, message }` back — JSON via `serde_json`,
`deny_unknown_fields` on the envelope, with the handler's own typed parse of
`payload` as the real schema gate on the part that varies per service
(`crates/mvm-protocol/src/protocol/broker.rs`). `service` is a reverse-DNS
identifier with a mandatory version segment (`host.audit.v1`), validated at
construction so a malformed id never reaches dispatch.

The guest's own `correlation_id` is never trusted. The host mints a fresh
one (`brk-<pid>-<counter>`) the instant a frame is read and uses only that
value in the audit entry and the response, so a workload cannot choose an id
that collides with or impersonates another chain entry.

Identity is a property of the channel, not of anything the guest presents.
A workload dials the broker on its own vsock port (`BROKER_PORT`, 5300),
which the backend relays to a Unix socket bound for that one VM; the host
already knows which workload is calling from which socket accepted the
connection, before it parses a single byte of the frame. The channel itself
carries no per-frame signature and asks the guest to hold no key
(`crates/mvm-guest/src/broker_client.rs`) — a compromised guest can write
raw frames to the port, but every gate that matters (which service is
reachable, what category an audit entry lands under, the size and rate
caps) is enforced host-side regardless of what the guest sends.

### Two per-tenant roles, never a process per VM

Host services run behind exactly two long-lived roles per tenant:

- **`mvm-host-agent`** (`crates/mvm-hostd/src/bin/mvm-host-agent.rs`) binds a
  control Unix socket (mode 0700) and, per registered VM, a guest-facing
  broker socket. It parses every untrusted `ServiceCall` frame and
  dispatches it through that VM's own handler `Registry` — and holds no
  signing key anywhere in its address space. It runs as a self-supervising
  wrapper/worker pair: the wrapper restarts the worker on crash without
  losing any registration.
- **`mvm-signer-helper`** (`crates/mvm-hostd/src/bin/mvm-signer-helper.rs`)
  holds the tenant's chain-signing key. It never parses a guest frame
  directly; it only accepts already-gated append requests from the
  host-agent over a local UDS, opens each registered VM's audit chain, and
  appends a JCS-canonical, hash-chained, Ed25519-signed entry per call.

Ten workloads for one tenant cost the same two roles as one — the
untrusted-parser/key-holder split scales with tenant count, not VM count.

### VM lifecycle is registration, not process spawn

Starting a VM does not spawn a host-services process. The backend that
starts the VM (`crates/mvm-backend/src/host_agent_spawn.rs`) lazily ensures
the tenant's daemon is running, then signs and sends a `RegisterVm` control
message (`crates/mvm-core/src/protocol/broker_control.rs`) carrying the
VM's id, its broker socket path, its workload audit-chain path, and the set
of services its registration may reach. The message is signed — Ed25519
over its JCS canonical bytes, by the host signer key — so a guest, which
holds neither that key nor the control socket, cannot register itself,
redirect another VM's chain, or unbind a sibling's socket
(`SignedControl::verify`, exercised against tampering, the wrong key, and
malformed encoding).

On `Register`, the daemon binds a fresh listener at that VM's broker socket
and builds a `Registry` scoped to that one connection; on `Deregister` it
drops the listener and closes out the VM's chain. Restart is not data loss:
the daemon journals its live registrations to disk and replays every one —
reopening chains, rebinding sockets — the moment it or its signer helper
comes back up. A tenant with no registered VMs for a configured idle window
(five minutes by default) exits rather than staying resident forever; the
next `Register` re-spawns it. `per_tenant_daemon_paths_are_isolated`
(`crates/mvm-hostd/tests/per_tenant_isolation.rs`) is the end-to-end proof
that two tenants' daemons never share a control socket, a broker socket, or
a chain.

An opt-out (`MVM_HOST_AGENT_DAEMON=0`) falls back to a one-process-set-per-VM
variant of the same substrate. It exists as a transition valve, carries its
own test coverage, and is not the default.

### `host.audit.v1` is the one service wired end to end

The daemon dispatches one real handler today:
`host.audit.v1` (`crates/mvm-hostd/src/broker/handlers/host_audit_v1.rs`),
with verbs `emit` (one entry) and `emit_batch` (up to 100 entries / 256
KiB). Every accepted entry is forced onto the `workload_audit` audit
category — distinct from every host- or system-asserted category, so a
chain verifier can tell "the workload claimed this" from "the supervisor
observed this" — and stamped with the caller's channel-derived
`workload_id` / `tenant_id` / `session_id` / `correlation_id`, never
anything the payload supplied. A single record is capped at 4 KiB; a
workload is rate-limited to 20 emits/second; the call does not return until
its entry is durably appended.

A call for anything the receiving VM's `Registry` does not hold returns
`NotBound` before any handler-specific logic runs — the same refusal
whether the service genuinely doesn't exist anywhere or simply isn't
reachable from this connection, and the binding-gated dispatch invariant
ADR-001 tracks as claim 12. `host.audit.v1` is the one service every
registration gets without being asked for by name, because letting a
workload assert its own audit trail is low-risk and broadly useful; nothing
else is.

### Adding a service costs one handler

A new service is one `ServiceHandler` impl (`crates/mvm-core/src/protocol/handler.rs`:
`id`, `profiles`, `audit_durability`, `idempotency`, `call_timeout`,
`dispatch`, with a 64 KiB response cap by default) registered into a VM's
`Registry` — the envelope, the daemon, the registration control plane, and
the correlation-id/audit substrate are all shared and untouched by adding
one. Two service ids already have a typed guest-side client and wire shape
with no host handler behind them yet (`host.time.v1`, `host.cost.v1` in
`crates/mvm-guest/src`); calling either today returns `NotBound`,
identically to any other unregistered service.

## Consequences

Positive:

- One daemon pair per tenant, not one process set per VM — host process
  count is `O(active tenants)`, and adding another workload to a tenant
  costs a socket bind, not a spawn/probe cycle.
- A guest has nothing worth forging: workload identity is derived from
  which socket accepted the connection, never from the frame, so no field
  in a `ServiceCall` carries any authority.
- The parser/key-holder split survives the per-tenant consolidation:
  `mvm-host-agent` never holds a key, `mvm-signer-helper` never parses a
  guest frame.
- Restart is cheap: the registration journal plus the persisted chain head
  let a daemon or its signer helper come back and resume exactly where it
  left off, without the backend re-registering anything it didn't already
  know.

Negative:

- `host.audit.v1` is the only service actually dispatched. `host.time.v1`
  and `host.cost.v1` are guest-visible but host-unimplemented, and a call to
  either fails the same way a made-up service id would — a real completeness
  gap, though not a security one, since it fails closed.
- The per-VM `services_bindings` a registration carries is not fed from
  anything yet — every current caller sends an empty list — so the explicit
  per-workload binding this design anticipates for future catalog services
  is unexercised; only `host.audit.v1`'s always-on default has ever run.
- Neither `mvm-host-agent` nor `mvm-signer-helper` runs under a dedicated
  uid, seccomp filter, or cgroup/namespace yet. The only isolation beyond
  the process boundary itself is a parent-death watchdog that exits an
  orphaned helper rather than letting it leak — privilege separation for
  these two roles is not built, not merely undocumented.
- The broker channel carries no per-frame cryptographic authentication; a
  bug that let one VM's traffic reach another VM's socket would defeat the
  identity guarantee, which rests entirely on process/socket topology, not
  on a signature.
- The per-VM fork fallback (`MVM_HOST_AGENT_DAEMON=0`) keeps a second,
  less-scalable code path alive and tested; retiring it is unfinished
  cleanup, not a decision made here.

## Trust gradient ledger

The broker's parser/key-holder split is one instance of a wider invariant
that governs every long-lived mvm daemon — host, builder, and workload —
machine-checked by `xtask check-trust-gradient` below.

<!-- trust-gradient:begin -->
---
claim: trust-gradient
status: Shipped
gated_phrases: []
exempt_paths: []
---

# Trust gradient ledger

Machine-checked by `xtask check-trust-gradient`. Authority and resident weight
decrease monotonically host → builder → workload. No daemon may hold authority
below its tier; `signing-key`, `plan-admission`, and `audit-writer` never exist
below the host. All three daemon tiers are covered: the builder row joined once the
`mvm-builderd` binary existed.

| Tier | Layer | Daemon | Forbidden authorities | Witnesses |
| --- | --- | --- | --- | --- |
| 2 | host | control-daemon | (none — holds all authority) | fn:per_tenant_daemon_paths_are_isolated |
| 1 | builder | mvm-builderd | signing-key, plan-admission, audit-writer | ci:builderd-no-authority |
| 0 | workload | guest-agent | signing-key, plan-admission, audit-writer, do-exec, console | ci:prod-agent-no-authority, ci:prod-agent-runentry-contract, ci:prod-agent-no-console |
<!-- trust-gradient:end -->
