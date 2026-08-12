# Consolidated Vsock Networking

## Actual state today: two paths, not one

This document previously said the raw-packet tunnel was retired and that no
raw packet tunnel or userspace L3 forwarder was part of the production path.
That stopped being true when ADR-036 reintroduced the tunnel as `l3-vsock` and
ADR-037 added a second, unprivileged forwarder for it. Both shipped. The
statement was never corrected here, which is exactly the failure this section
now records rather than repeats.

The tree carries **two** production workload networking paths:

1. **Socket-aware vsock (the default).** The guest has no network device. Its
   loopback adapters hand traffic to a host-side endpoint over AF_VSOCK; the
   host originates every outbound connection, so admission, substitution,
   redaction, and the audit record are all possible.
2. **`l3-vsock` (opt-in, `raw_ip_stack=true`).** The guest gets a real IP
   stack on an `mvm0` TUN and tunnels raw IPv4/IPv6 packets to a host
   forwarder (Linux host TUN + nftables, or the unprivileged userspace socket
   datapath). The *guest* originates connections, so host-side substitution
   and redaction cannot apply to them.

Two paths means two policy implementations, two resource accountings, and two
audit shapes. Claim 10's "one decision point" describes only the first.

## Target invariant

ADR-042 and `specs/plans/316-single-flow-vsock-networking.md` collapse this to
one path:

```text
guest loopback adapter
  -> authenticated FlowMux session on GuestService::NetworkFlow (vsock port 5253)
  -> one per-VM mvm-network-endpoint
  -> canonical policy, DNS, substitution/redaction, rate and audit pipeline
  -> host-originated TCP/UDP socket or host-owned ingress listener
```

The endpoint is flow-aware at L4 with selective L7: opaque TCP/UDP is relayed
without parsing, and L7 parsing, host TLS origination, substitution,
reversible replacement, and redaction run only for an explicitly typed
HTTP/connector flow whose signed plan requires them. `Off` is the absence of a
network grant and of `NetworkFlow` — not a second mode. There is no transport
selector.

## Migration state

The raw-packet path is **frozen, not yet deleted**. New
`raw_ip_stack=true` / `NetworkMode::L3Vsock` launches are refused at synthesis
and admission with a migration error naming the loopback proxy and
typed-connector alternatives; already-running VMs drain. A temporary
`xtask check-l3-expansion-freeze` ratchet forbids new non-test references to
`L3Vsock`, `raw_ip_stack`, `NetworkControl`, `NetworkData`, `spawn_netd`, and
`host_datapath` outside a shrink-only allowlist of the files scheduled for
deletion. Plan 285 and Plan 287 are frozen: only security fixes may touch
their runtime path.

Deletion of `mvm-contract::l3`, `NetworkMode`, `mvm-net/src/l3/`,
`mvm-agentd/src/l3/`, `mvm-hostd/src/netd/`, `mvm-netd`, `mvm-net-agent`,
`netd_spawn`, and smoltcp lands in Plan 316 Phase 7; the permanent
`check-single-network-path` and socket-owner gates replace the temporary
ratchet in Phase 8.

## Security properties on the socket-aware path

Firecracker, libkrun, and HVF all bind
`WorkloadRunner<VmmDriver, RealEndpointSpawner, RealBrokerRegistrar>`; their
capability shape advertises host-vsock mediation and no routable guest NIC.
The runner owns admission and default-deny. The endpoint spawner owns admitted
host/port connections. The broker and substitution endpoint own secret-bearing
requests, so credentials never enter the guest. The supervisor L4 gate applies
the final host/port policy and audit boundary. Plan 316 keeps this seam and
makes it the only one.

QEMU remains an explicit development/test substrate outside the production
workload claim boundary. Its networking behavior is not a production egress
fallback.
