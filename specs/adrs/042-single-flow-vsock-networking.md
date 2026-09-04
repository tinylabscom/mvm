# ADR-042 — One flow-aware vsock networking path

**Status: Accepted**
**Date: 2026-08-11**
**Supersedes: ADR-036 (L3 TUN-over-vsock) and ADR-052
(`052-userspace-socket-datapath.md`) for the production workload networking
path. Their measurements, threat analysis, and historical rationale stand;
their implementations stop being a supported production transport.
Complements ADR-003 (hypervisor egress policy), ADR-014 (signed/audited
execution plans), ADR-020 (host-services broker), and ADR-023 (secrets
subsystem / egress substitution).**

## Context

A workload microVM was designed with no NIC. Every byte a guest sends leaves
over AF_VSOCK to a host-side endpoint that originates the real connection.
That is what makes claim 10 (default-deny egress), claim 13 (no raw secret
reaches the guest), and the chain-signed audit log enforceable: the host, not
the guest, is the party that opens sockets.

ADR-036 then added `l3-vsock`, an opt-in compatibility mode that gives the
guest a real IP stack on a `mvm0` TUN and tunnels raw IPv4/IPv6 packets to a
host forwarder. ADR-052 added a second, unprivileged forwarding backend for
it. Both shipped. The tree therefore carries **two** production workload
networking paths with different policy code, different resource accounting,
different audit shapes, and different security properties — and
`specs/refactor/03-networking.md` still asserts the raw-packet path was
deleted, which stopped being true when it was reintroduced.

Two paths is the problem this ADR resolves. It is not primarily a performance
or a code-size argument. It is that claim 10's "one decision point" is only
true of one of the two paths, and a reader cannot tell from a workload which
one applies.

## Decision

There is exactly one external networking path for an untrusted workload:

```text
guest loopback adapter
  -> authenticated FlowMux session on GuestService::NetworkFlow (vsock port 5253)
  -> one per-VM mvm-network-endpoint
  -> canonical policy, DNS, substitution/redaction, rate and audit pipeline
  -> host-originated TCP/UDP socket or host-owned ingress listener
```

The endpoint is **flow-aware at L4, with selective L7** — not universally L7.

- TCP and UDP payloads whose signed plan requests no content transformation
  are relayed as opaque bytes. The host does not parse them, does not
  reconstruct a guest TCP stack, and does not claim to have inspected them.
- L7 parsing, host TLS origination, credential substitution, reversible
  replacement, and redaction run **only** for an explicitly typed
  HTTP/connector flow whose signed plan requires them.
- If a plan requires a transformation, admission refuses an opaque flow shape
  rather than silently downgrading it.

`Off` is the absence of a network grant and the absence of `NetworkFlow`. It
is not a second networking mode, and there is no transport selector.

## Why not universal L7

The obvious way to make every flow transformable is to terminate all guest TLS
at the host. That requires the host to present certificates the guest trusts,
which requires a host-controlled CA in the guest trust store — a
man-in-the-middle CA applied universally.

We reject that as the universal path, for reasons that are independent of how
well it is implemented:

- **It is not achievable in general.** Certificate pinning, mutual TLS, QUIC,
  and ECH each defeat it, and each is common in exactly the workloads that
  care most. A mechanism that silently stops applying for a subset of traffic
  is worse than one that never claimed to apply, because the operator cannot
  tell the difference from the outside.
- **It inverts the trust story.** The project's stated posture is that the
  guest is untrusted and the host does not need to read guest payloads to
  enforce policy. A universal MITM CA makes the host's ability to enforce
  depend on its ability to decrypt everything the workload does, which is a
  strictly larger and more fragile capability than the one claim 10 needs.
- **It enlarges the blast radius of the endpoint.** The endpoint already holds
  credentials in the clear for substitution. Giving it a CA key that the guest
  trusts for every destination turns a per-destination compromise into a
  universal one.
- **It would make claim honesty impossible to state.** "Every flow is
  inspected" would be false in practice while being the documented behavior.

So arbitrary guest-originated TLS and host-side credential replacement are
**mutually exclusive**, and this ADR makes that explicit rather than implicit.
A workload that wants host-side substitution or redaction declares a typed
transform flow, whose TLS the host originates to a plan-bound destination. A
workload that wants opaque TLS gets opaque TLS, and gets told plainly that no
transformation applies to it.

## Consequences

**Accepted.**

- The raw-packet transport is retired. `NetworkMode`, `L3Vsock`,
  `HostVsockProxy`, `raw_ip_stack`, the guest `mvm0` TUN, `mvm-net-agent`,
  `mvm-netd`, `NetworkControl`, `NetworkData`, host TUN, nftables forwarding,
  and the smoltcp datapath are removed.
- Raw sockets, arbitrary IP protocols, custom in-guest resolvers, and general
  ICMP are **unsupported** for production workloads. A program that ignores
  the supported loopback adapters has no network route and fails closed. This
  is a deliberate compatibility ceiling, not an unfinished feature.
- Compatibility is served by adapters that terminate in the single FlowMux
  client: the loopback HTTP proxy, SOCKS5h, SOCKS5 UDP, the controlled DNS
  stub, the mediated ping helper, and the typed SDK connectors.
- No compatibility concession may weaken `PR_SET_DUMPABLE`, ptrace isolation,
  capability bounding, seccomp, Landlock, verified boot, the read-only
  workload rootfs, or secret handling. Reading workload memory or installing
  seccomp user-notification to fake up transparent connect interception is
  rejected.

**Claim effects.**

- **Claim 10 strengthened.** The sole network decision and socket creation
  site is the per-VM endpoint, so no compatibility path can diverge from it.
- **Claims 12 and 13 preserved.** Typed connectors and listeners stay bound to
  the signed `ExecutionPlan` before dispatch; broker calls can request
  destination-bound use of a credential but never receive or transmit its raw
  value.
- **Preview claim 16 strengthened but still scoped.** Substitution and its
  leak gate sit on the only endpoint that can create an external connection.
  The claim remains scoped to typed transform flows and never extends to
  opaque ciphertext — which is precisely the honesty this ADR buys.
- **Claims 5 and 8 preserved.** The new frame decoder is fuzzed, and every
  endpoint capability derives from the admitted signed plan.

**Costs.**

- Workloads that genuinely need an in-guest IP stack lose their supported
  path. `raw_ip_stack=true` is refused with a migration error naming the
  loopback proxy and typed-connector alternatives.
- The migration is staged rather than atomic. During it, no new production L3
  workload may boot, so the tree never runs three live production paths.

## Alternatives considered

- **Keep both paths and document the difference.** Rejected: it is the status
  quo, and it is the thing that made ADR-001's claim-10 section wrong. Two
  policy implementations drift; one of them is always the one nobody audited
  most recently.
- **Universal host TLS termination via a MITM CA.** Rejected above.
- **Transparent connect interception via ptrace/seccomp user-notification.**
  Rejected: it requires weakening `PR_SET_DUMPABLE` and ptrace isolation, or
  reading workload memory, to buy compatibility for programs that deliberately
  bypass the supported adapters. The isolation is worth more than the
  compatibility.
- **Keep a raw-packet path as a dev/test escape hatch.** Rejected: a real
  alternate network implementation retained for testing is a second production
  path with a different label. Hermetic protocol doubles are allowed; a second
  network stack is not.

## Migration

Staged in `specs/plans/316-single-flow-vsock-networking.md`, phases 0–8. The
plan's performance gate is a merge gate: opaque TCP/UDP may regress at most 5%
on p50/p95 latency, must retain at least 95% throughput, and may not grow peak
RSS by more than 10%, measured against baselines recorded before the endpoint
changes.
