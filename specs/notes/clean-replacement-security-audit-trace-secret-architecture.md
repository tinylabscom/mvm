# Note — Security, audit, trace, and secret architecture for the clean replacement

**Status:** Architecture note
**Date:** 2026-06-27
**Owner:** mvm
**Relates to:** [ADR-002](../adrs/002-microvm-security-posture.md),
[ADR-049](../adrs/049-vsock-substitution-service.md),
[ADR-059](../adrs/059-host-services-broker.md),
[ADR-098](../adrs/098-macos-raw-hvf-performance-backend.md),
[Plan 214](../plans/214-clean-replacement-architecture.md),
[Research note](../research/clean-replacement-architecture-review.md)

Security, auditability, traceability, least privilege, blast-radius reduction, and
closed-by-default behavior are the highest-priority architecture requirements for
the clean replacement. This note specifies the networking, secret, audit, and
trace model so that [Plan 214](../plans/214-clean-replacement-architecture.md) can
implement against it. It builds on mvm's existing posture rather than replacing it:
the chain-signed audit log, the host-services broker, the vsock substitution
endpoint, default-deny egress, and the standing SSH ban all stay. The changes are
the no-NIC networking default, the consolidation of the network path into named
broker roles plus a guest network daemon, end-to-end trace correlation, and
per-destination redaction.

## Required posture (closed by default)

The architecture enforces, with no exceptions and no escape that survives into
production:

- default deny everywhere
- no guest NIC by default
- no SSH in production
- no unrestricted host networking reachable from a guest
- no hidden egress path and no unmediated ingress path
- no secrets baked into images, rootfs, env files, snapshots, or logs
- no production debug backdoor
- no accidental fallback to less-secure networking
- no silent backend downgrade when a security capability is required
- no unbounded parsing of guest-controlled or tenant-controlled data

Each is realized below.

## Networking: no guest NIC, host/vsock-mediated

### Network modes

The plan carries a typed network mode instead of a host-wide environment
selection:

```rust
pub enum NetworkMode {
    /// No guest NIC, no broker. The default. Workload cannot reach the network.
    None,
    /// No guest NIC. Egress and ingress are mediated by host brokers over vsock.
    HostVsockProxy,
    /// Real virtio-net NIC. Opt-in compatibility only; reintroduced only when a
    /// workload genuinely needs NIC semantics (UDP, ICMP, raw sockets, VPNs).
    CompatNat,
}
```

The first clean implementation may ship with only `None` and `HostVsockProxy`.
`CompatNat` is added later, and only if a real workload requires NIC semantics;
the existing NIC providers are kept dormant for that future, not on the hot path.

`None` is the default. A NIC never appears just because networking is requested:
`--net` selects `HostVsockProxy`, not a NIC, and grants nothing until an endpoint
is allowed.

### Egress path

```
guest app
  -> proxy env vars (cooperative) or transparent local redirect (mvm-netd)
  -> guest mvm-netd (loopback listener inside the guest)
  -> vsock
  -> host mvm-egress-broker
  -> policy engine (default-deny; endpoint allowlist)
  -> host-side secret substitution where allowed (placeholder -> real value)
  -> redaction of configured fields
  -> DNS / TCP / TLS / HTTP to the outside or to a private service
```

The host egress broker resolves DNS on the host, exposes TCP connect, HTTP
CONNECT, SOCKS5, and DNS broker operations, enforces endpoint allowlists and
secret-destination policy, performs host-side request signing or injection where
allowed, redacts configured fields before logging, emits a structured audit event
and a trace span per flow, and never leaks unrestricted host networking into the
guest. It is compatible with the signed `ExecutionPlan` policy: the allowlist and
secret-destination rules come from the admitted plan, not from guest input.

### Ingress path

```
host listener (created only from explicit plan policy)
  -> host mvm-ingress-broker
  -> policy engine (authn/authz, allowlist)
  -> audit event + trace span
  -> vsock
  -> guest service
```

Ingress is also mediated. There is no guest NIC and no directly exposed guest TCP
service by default. A host listener exists only because the plan declared it, and
it fails closed. No ingress path bypasses the host policy/audit layer.

### Guest network daemon (`mvm-netd`)

`mvm-netd` listens on loopback inside the guest, accepts proxy requests from the
app, forwards them over vsock to the host egress broker, optionally performs
transparent TCP redirect, receives DNS config from `mvm-init` or launch metadata,
fails closed when the broker is unavailable, stores no secrets durably, and logs
no secrets. It consolidates the guest-side proxy and substitution clients that
exist today into one daemon.

Cooperative applications are pointed at it by injected proxy environment variables:
`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`. Uncooperative applications
are handled by transparent TCP redirect where feasible.

### Endpoint allowlisting

When networking is enabled, every reachable endpoint is explicitly controlled. No
endpoint is reachable merely because `HostVsockProxy` is on. The CLI surface:

- `--net` → enable `HostVsockProxy` (no endpoints yet)
- `--allow-host example.com` → allow brokered egress to a host
- `--allow-port 443` → allow a port
- `--allow-endpoint https://api.example.com` → allow an endpoint pattern

These compile into the plan's egress allowlist; the broker enforces them. `:22` is
rejected at parse time, consistent with the SSH ban.

### Protocol framing (guest ↔ broker)

The vsock framing for the brokers reuses the existing broker substrate: simple,
length-prefixed, with a hard byte cap enforced before allocation, versioned,
`#[serde(deny_unknown_fields)]`, deny-by-default, trace-context aware, and
secret-reference aware. Guest-supplied correlation values are never trusted; the
host reassigns them at ingress. The parsers are fuzzed under the same discipline as
the existing vsock and supervisor-config fuzz targets.

## No SSH in production

Production never supports SSH — not as a flag, a hidden debug mode, a fallback
shell, a troubleshooting path, or a compatibility path. The production access model
is:

- `mvm exec` over vsock
- `mvm shell` over vsock/PTY (dev-only console transport)
- control-plane operations over authenticated host APIs
- no sshd in the guest, no exposed guest TCP listener for management

The standing posture already enforces this: TCP/22 is a banned egress port at
admission and at runtime; there is no sshd, SSH user, or SSH key in any rootfs; the
interactive console transport is gated behind the `dev-shell` feature so a sealed
prod agent links no console symbol. The clean-replacement change is to feature-gate
the dev-tier SSH-agent forwarding path (a host capability, not a guest server) so
it cannot link into a sealed prod agent either — mirroring the console/`do_exec`
exclusion. Any plan that requests production SSH is rejected by capability check.

## Secrets

Secrets are referenced, resolved by host-side policy, and **never enter the
microVM** — not baked into images, not delivered at runtime, not captured in
snapshots or logs. The microVM cannot hold a secret: the guest holds only an
opaque placeholder, and the real value lives only in the host broker's address
space.

- Secrets are referenced by id in the plan, never carried as raw values.
- Secrets are resolved only by authorized host-side components.
- Secrets are **never delivered to the guest under any policy.** There is no
  guest-injection path. The guest holds a placeholder; the host substitutes the
  real value on egress, after terminating the guest hop, without the guest ever
  seeing it.
- Secrets are substituted into egress **host-side**, only for allowed
  destinations, headers, and fields.
- Secrets are redacted from logs and traces, and from ingress before it reaches
  the guest.
- Secrets are excluded from snapshots and from deterministic image artifacts by
  construction.
- Secret material is zeroized on drop and never crosses the broker channel — nor
  the vsock boundary into the guest — as raw bytes.
- Secret values can be rotated without rebuilding images.
- Host-side secret substitution can be disabled per plan.

### Egress secret substitution (host-side)

The host egress broker terminates the guest hop and, for allowed destinations
only, performs in its own address space:

- placeholder → real-credential substitution in request headers
- host-side `Authorization` header substitution per policy
- host-side request signing with a host-held key
- token exchange on the host side
- field-level redaction before audit logging

The guest only ever holds an opaque placeholder; the broker substitutes the real
credential bound to the destination, in host memory, and never returns it to the
guest. A leaked placeholder on an egress path is dropped and audited. No outcome
delivers a secret to the guest. (Because substitution happens host-side, the
broker originates egress TLS — the guest cannot do end-to-end TLS to the
destination *and* have the host substitute a secret; the host is the egress TCB.)

### Secret policy expression

Plan policy expresses, per secret reference:

- secret id
- allowed workload identity
- allowed destination endpoint
- allowed header / field
- allowed operation (host-side substitute, sign, exchange — all host-side; never
  guest delivery)
- redaction rule

This is authored through the CLI flags/config, the decorator SDK, and the runtime
SDK; resolved by the host egress broker and `mvm-init`; and recorded in the audit
sink by reference id.

## Audit and trace

Audit events are structured, append-only, tamper-evident (per-tenant Ed25519
chain, JCS-canonical), and correlate across:

`tenant id`, `machine id`, `execution plan id`, `plan digest`, `backend id`,
`host id`, `process id (where relevant)`, `guest lifecycle marker`, `request id`,
`trace id`, `span id`, `policy decision id`, `network flow id`, `secret reference
id`, `snapshot id`, `timestamp`.

Today the chain carries `correlation_id`, `(plan_id, plan_version)`, tenant,
workload, session, and image identity. The clean-replacement additions are a
`trace_id` and `span_id` carried end to end (guest → broker → audit) using a
W3C-style trace context, threaded through the canonical entry, and a `network
flow id` per brokered flow. The host reassigns guest-supplied correlation values at
ingress so the guest cannot forge identity into the chain.

### Egress events record

requested host, requested port, requested protocol, resolved IPs, selected IP, SNI
(where applicable), HTTP method (where applicable), HTTP authority/host (where
applicable), policy rule matched, allow/deny decision, bytes in/out (where safe),
duration, error code, redaction status. Secret usage is recorded by reference id
only.

### Ingress events record

host listener created, guest service exposed, allowed source, allowed destination,
port or vsock route, policy rule matched, allow/deny decision, bytes in/out (where
safe), duration, error code, redaction status.

### Audit must never record

raw secret value, derived bearer token value, private key material, session cookie
value, `Authorization` header value, sensitive request-body fields.

## Snapshot security

Snapshot frames exclude secrets, host tokens, SSH material, unredacted broker
state, and unbounded logs by construction. The frame carries integrity (the
existing HMAC + Ed25519 + epoch envelope) and records the artifact digests it
restores. The frame parser caps every count before allocation, checks region
bounds and page alignment with overflow-safe offset math, and is fuzzed. See
[Plan 214](../plans/214-clean-replacement-architecture.md) Phase 8.

## Least privilege and blast radius

The existing per-service uid, seccomp tier, `setpriv --no-new-privs`, read-only
identity files, mode-0700 state dirs, and process-moat subprocess separation are
preserved. The new components inherit them: `mvm-netd` runs unprivileged in the
guest and stores no secrets; the egress and ingress brokers run host-side with the
broker's existing isolation; the consolidated `mvm-init` drops privileges before
exec and never starts a network server in production.

## Remaining risks

- The transparent-redirect surface in `mvm-netd` is new untrusted-input handling
  and must be fuzzed and kept minimal.
- DNS brokering on the host must guard against resolution-time TOCTOU: resolved IPs
  are validated against policy before connect.
- Per-destination redaction actions must not become a covert channel; the leak-gate
  witnesses must cover the new broker path.
- A malicious host remains out of scope, consistent with the standing threat model.
