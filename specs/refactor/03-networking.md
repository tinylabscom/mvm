# Consolidated Vsock Networking

## Current invariant

Every workload backend uses the authenticated, default-deny vsock runner seam.
The workload guest has no NIC surface, and no raw packet tunnel or userspace
L3 forwarder is part of the production path.

## Data path

```
guest app → guest loopback / mvm-egress-client → authenticated vsock
  → WorkloadRunner → RealEndpointSpawner / broker / substitution
  → supervisor L4 policy gate → approved endpoint
```

The runner owns admission and default-deny. The endpoint spawner owns admitted
raw host/port connections. The broker and substitution endpoint own
secret-bearing requests, so credentials never enter the guest. The supervisor
L4 gate applies the final host/port policy and audit boundary.

## Retired Model A

The former guest-TUN → framed raw-packet vsock → host-UDS → smoltcp path is
retired. Its guest TUN device, host packet worker, network-tunnel protocol,
smoltcp dependency, and guest-netd binary are deleted. No backend may restore
that path as a fallback: the uniform runner must fail closed if its host vsock
seam is unavailable.

## Model B and security properties

Model B is the sole workload egress model. Firecracker, libkrun, and HVF all
bind `WorkloadRunner<VmmDriver, RealEndpointSpawner, RealBrokerRegistrar>`;
their capability shape advertises host-vsock mediation and no routable guest
NIC. The same typed seam enforces default-deny egress and secret substitution
for every workload backend.

QEMU remains an explicit development/test substrate outside the production
workload claim boundary. Its networking behavior is not a production egress
fallback.
