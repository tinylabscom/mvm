# Consolidated Vsock Networking

## Actual state today: one admitted public path

FlowMux is the only networking path a new workload can select. The public IR,
SDKs, generated schema, CLI preflight, and admitted `NetworkMode` domain no
longer represent the raw-packet compatibility path. Stale serialized
`raw_ip_stack` and `l3_vsock` inputs fail at their outer compatibility boundary
with guidance toward the supported loopback adapters and typed connectors.

The superseded implementation is physically deleted. Only the narrow stale-
input refusal remains at the public decoding boundary.

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

The raw-packet path is physically deleted. New stale declarations are refused
before they enter the admitted domain, while already-running VMs from an older
release may drain during an upgrade. The permanent
`xtask check-single-network-path` gate rejects a second endpoint or spawn seam,
a backend without `NetworkFlow`, retired L3 or guest-NIC symbols, and any new
workload socket owner outside the endpoint's exact allowlist. Synthetic tests
prove every forbidden case and each narrow infrastructure exemption.

## Security properties on the socket-aware path

Firecracker, libkrun, and HVF all bind
`WorkloadRunner<VmmDriver, RealNetworkEndpointSpawner, RealBrokerRegistrar>`; their
capability shape advertises host-vsock mediation and no routable guest NIC.
The runner owns admission and default-deny. The endpoint spawner owns admitted
host/port connections and ingress listeners. The broker authorizes typed
connector bindings but delegates their network execution to the endpoint, so
credentials never enter the guest and no second socket owner exists. The
endpoint's shared L4 gate applies the final host/port policy and audit boundary.

QEMU remains an explicit development/test substrate outside the production
workload claim boundary. Its networking behavior is not a production egress
fallback.
