# User-space egress evaluation

**Date:** 2026-07-24
**Decision:** keep the production workload path NIC-less and add SOCKS5 TCP
CONNECT plus UDP ASSOCIATE over the authenticated vsock egress seam. Use the
existing QEMU dev/test backend as the transparent rootless TCP/UDP prototype.

## Requirements

The candidate must support rootless operation, host-route/VPN awareness,
default-deny policy enforcement, bounded untrusted input, and an auditable
host-side decision point. A transparent path must also work for ordinary guest
TCP and UDP sockets without requiring applications to understand SOCKS5.

## Candidates

| Candidate | Transparent TCP/UDP | Rootless | Fits NIC-less production path | Decision |
| --- | --- | --- | --- | --- |
| QEMU user-mode networking | Yes, through an ordinary guest virtio NIC | Yes | No; it is an L3 guest-network model | Keep as the dev/test prototype. |
| slirp4netns/libslirp | Yes, through a namespace TAP file descriptor | Yes in its intended namespace/container model | No; it still needs a guest network endpoint and routing setup | Do not add as a production dependency. |
| gVisor netstack | Yes, with a user-space network stack | Depends on the endpoint supplied to the stack | No; the stable integration boundary is a Go userspace-kernel stack, not a Rust library API | Do not embed; revisit only as a separately governed backend. |
| gost | SOCKS5, TCP/UDP forwarding, and firewall-based transparent modes | The proxy process can be unprivileged, but transparent interception needs a redirect/TUN/TAP boundary | No; it adds an external proxy and a second policy/audit implementation | Do not vendor or shell out to it. |
| redsocks | Transparent TCP and selected UDP-over-SOCKS modes | Requires firewall redirection or equivalent interception | No; same missing packet interception boundary | Do not use for production. |
| Custom vsock SOCKS5 relay | Cooperative TCP and UDP | Yes | Yes; uses the existing authenticated host endpoint and policy gate | Implement and make it the production path. |

The external projects document the same boundary: QEMU's `-net user` is a
complete user-mode network stack with no host root requirement; slirp4netns
connects a user-space stack to a TAP file descriptor; gVisor netstack is part
of a Go userspace kernel and does not promise a stable standalone API; gost and
redsocks obtain transparency through a network redirect or virtual interface.

References:

- QEMU user-mode networking: <https://qemu.readthedocs.io/en/latest/system/devices/net.html>
- slirp4netns: <https://github.com/rootless-containers/slirp4netns>
- gVisor networking: <https://gvisor.dev/docs/architecture_guide/networking/>
- gost: <https://github.com/ginuerzh/gost>
- redsocks: <https://github.com/darkk/redsocks>

## Decision and boundary

There is no transparent packet path from a NIC-less guest that only has a
vsock device. Something must intercept the guest's socket or packet boundary;
adding a hidden guest NIC, TUN, TAP, or firewall redirect would recreate the
second production egress model that the uniform-vsock convergence removed.

The implementation therefore has two explicit modes:

1. Production HVF/libkrun/Firecracker workloads use the existing loopback
   SOCKS5 client and the host's authenticated vsock endpoint. TCP CONNECT and
   UDP ASSOCIATE share the host policy gate and host-side DNS resolution.
2. Linux QEMU dev/test workloads use QEMU's rootless user-mode virtio network.
   Ordinary guest TCP and UDP sockets are transparent to the workload. This
   mode is intentionally outside the production security claims and is useful
   for compatibility testing and comparison measurements.

The distinction is surfaced in the backend capability matrix rather than
hidden behind a fallback: QEMU reports `UserModeVirtio`; production workload
backends report no guest NIC and `vsock` mediation.
