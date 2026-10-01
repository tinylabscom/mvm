# Vsock-only guest devices

Backing: shipped-source
Validation: check-single-network-path

## Boundary

The guest may use loopback sockets for local DNS and proxy adapters, but no
microVM may acquire a network device that connects it to the host or network.
Outbound traffic crosses the host vsock endpoint, where policy is enforced.
This applies to workload VMs, builder VMs, and dev/test backends alike.

## VMM launch invariant

QEMU creates an implicit user-network NIC unless its launch arguments disable
networking. Every workload and builder QEMU invocation therefore passes
`-nic none`. The Firecracker pool-builder mode that attached TAP is retired;
requests for its former modes fail before VM setup. The remaining builder
backends use vsock and disk transport without guest NICs.

The source guard checks QEMU launch arguments and rejects builder TAP setup.
Focused argument tests cover the executable launch surfaces; backend capability
metadata reports no guest NIC rather than describing an obsolete dev-tier
exception.

## Builder kernel and cache invariant

A NIC-less VMM configuration alone does not prove a zero-TUN guest. A cached
aarch64 builder kernel from the earlier cache contract had `CONFIG_TUN=y` and
`CONFIG_VIRTIO_NET=y`. Cache reuse therefore requires the resolved kernel
configuration from the same builder-image output. The validator requires
`# CONFIG_NETDEVICES is not set`, rejects enabled network-device symbols, and
requires built-in virtio-vsock support. A missing config or an older cache
contract is a cache miss, never permission to boot the cached kernel.

Published image sets bind each builder `kernel.config` asset to the signed set
manifest and its per-architecture builder manifest. The image lock pins the
signed `image-set/v0.2.3` train and builder cache contract 5. Source-built
contributor caches produce their configuration and kernel together; guest
runtime binaries still cross-compile from the checkout in the designed
contributor tier, while release binaries acquire the published overlay.

## Verification boundary

Unit and integration tests cover QEMU arguments, retired builder modes,
kernel-config rejection, cache reuse, published asset pins, and the image-lock
reader. `check-single-network-path` protects the source invariant. A live
Linux builder/workload boot is the separate runtime witness: confirm only
loopback appears under `/sys/class/net`, no `/dev/net/tun` exists, and allowed
and denied outbound attempts traverse the vsock endpoint. Run Linux-specific
operations inside the project builder VM; host-only tests do not substitute
for that witness. Issue #3888 owns acceptance and the current verification
state.
