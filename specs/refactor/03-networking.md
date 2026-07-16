# Consolidated Vsock Networking

The headline design of this restructure: one standardized protocol, one seam, for every byte a guest sends or receives.

## The invariant

ALL guest ingress/egress rides vsock through a single authenticated, default-deny, auditable boundary — no NIC, no TAP, no bridge, ever.

## Data path

```
guest app → guest Linux stack → guest TUN (mvm-net0) → mvm-agentd [net role]
  → framed vsock protocol → per-VM host UDS (~/.mvm/run) → mvm-hostd [net worker]
  → identity check + default-deny policy + DNS + audit → smoltcp userspace stack → approved endpoints
```

## Two capabilities over that one seam

- **Generic transparent L3 tunnel** — carries no secrets; guest uses ordinary sockets (no proxy-awareness); all protocols (TCP/UDP/DNS/ICMP) as raw IP over vsock; host terminates in **userspace smoltcp** (no host TUN/NAT, no shell-out, cross-platform).
- **Typed connectors** — secret-bearing requests; the host holds the credential and performs the request; secrets never enter the guest. Reuses the existing broker; replaces the global `HTTP_PROXY=:1080`.

The tunnel and the typed connectors are deliberately kept separate: the tunnel is a dumb, secret-free pipe that any guest socket call can use unmodified; typed connectors are the only path that ever touches a credential, and that path is proxy-aware by design (the guest asks for it explicitly). See [04-security.md](04-security.md) for how secret substitution rides the typed-connector path specifically.

## Standardized protocol

Wire types live in `mvm-protocol` (no_std, fuzzable — see the crate map in [02-architecture.md](02-architecture.md)).

**Frame shape:** length-prefixed frames `magic|version|type|flags|flow_id|len|seq`; strict max size.

**Message types:** `HELLO/HELLO_ACK/CONFIG/PACKET/CREDIT/HEARTBEAT/ERROR/SHUTDOWN` + extensions (`FLOW_OPEN/CLOSE/RESET`, `DNS_QUERY/RESPONSE`, `POLICY_UPDATE`, `STATS`, `AUDIT_EVENT`).

**Backpressure:** credit-based; bounded queues; separate control + packet (+ audit) streams — a slow or malicious guest can't starve control traffic by flooding the packet stream, and vice versa.

**Handshake:** session fields `protocol_version/vm_id/boot_id/session_nonce/agent_version/features/max_frame`, validated host-side. **Fresh `boot_id` + `session_nonce` per boot and per snapshot-restore** — this is what makes CID reuse safe: a restored or cloned VM can't replay a stale session against the host, because the host only accepts a handshake whose nonce it hasn't seen for that vm_id/boot_id pair.

**Default-deny / fail-closed rules:** block loopback/link-local/multicast/metadata/RFC1918/IPv6-local by default; DNS-rebinding protection; every failure mode (unmediated backend, expired handshake, malformed frame) fails closed, never open.

**Transport abstraction:** a `VmDuplexTransport` trait keeps protocol/policy/audit hypervisor-independent — Firecracker UDS, libkrun unixgram, HVF vsock, and an in-memory transport for tests all implement the same trait, so the protocol/policy/audit code is written once and never branches on backend.

**Process model:** the host worker is one process (Option A — see the binary model in [02-architecture.md](02-architecture.md)) under cap-drop + seccomp + landlock.

**Identity:** per-VM; mvmd layers tenant policy/quotas on top of the handshake fields — this crate/protocol boundary doesn't know about tenants, only about VMs, which is what keeps `mvm-protocol` usable outside the fleet-orchestration context (including the wasm/browser path).

## Where this replaces prior art

This design retires **every userspace network gateway** — passt (Linux), gvproxy (macOS), and the opt-in native/rvproxy path — because once all egress rides the one vsock seam they have nothing left to do. It also folds in Firecracker's TAP+iptables egress (PR #1717 / issue #1701), HVF's host-vsock-proxy (issue #1601), the `native_gateway` subsystem (~1,281 lines), and the `NetworkingPreference`/`MVM_NETWORKING` knob. Execution detail and current status: [06-execution-plan.md](06-execution-plan.md) WS-NET, [07-progress-and-decisions.md](07-progress-and-decisions.md).
