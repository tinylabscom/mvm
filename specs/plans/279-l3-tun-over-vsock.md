# Plan 279 — L3 TUN-over-vsock network mode

**Status: In progress**
**ADR: [035](../adrs/035-l3-tun-over-vsock.md)**

Opt-in `l3-vsock` network mode: the guest gets a point-to-point `mvm0`
TUN interface, the guest agent frames raw IP packets over dedicated
vsock connections, and a machine-scoped host gateway applies policy
before anything reaches host networking. No guest NIC, no TAP, no
bridge, no L2.

Read ADR-035 first; this plan is the sequencing and the checkbox ledger.

## W1 — Canonical mode + plan representation

- [x] `NetworkMode::L3Vsock` in `mvm-protocol::plan::types`
- [x] `L3NetworkSpec` on `ExecutionPlan` (`#[serde(default)]`, absent =
      not an L3 workload): protocol version/features, MTU, limits,
      DNS policy, private-network policy, ICMP policy, ingress
      mappings, address-allocation reference, policy epoch
- [x] `NetworkMode::L3Vsock` in `mvm-runtime::machine`, with
      `RequiredCapabilities { l3_vsock, no_routable_guest_nic }`
- [x] `VmCapabilities::l3_vsock` + `shortfall` wiring; backends that
      cannot serve it fail closed with a named shortfall
- [x] **no operator-facing mode selector.** The transport is derived from
      what the plan requires, so it cannot be chosen wrongly; the mode stays
      in the signed plan as the admitted contract
- [x] `--allow-host` compiles into the same `CanonicalEgress` the
      gateway consumes — no second policy representation
- [x] machine inspect / receipt output names the admitted mode

## W2 — Shared protocol (`mvm-protocol::l3`)

- [x] `limits.rs` — MTU, frame/payload caps, queue caps, table caps
- [x] `frame.rs` — `u32` length prefix + 24-byte fixed header;
      encode/decode; every rejection before allocation
- [x] `message.rs` — HELLO / CONFIG / READY / PACKET / HEARTBEAT /
      SHUTDOWN / ERROR, fixed binary layouts, explicit endianness
- [x] `ip.rs` — bounded IPv4/IPv6 validation: version, IHL, total
      length, protocol, ports, fragment detection, bounded IPv6
      extension-header traversal
- [x] unit + property tests; arbitrary binary input never panics
- [x] `fuzz_l3_frame` target

## W3 — Policy core (`mvm-net::l3`)

- [x] `session.rs` — host-minted session IDs, per-boot nonce,
      invalidation on stop/restart/restore
- [x] `alloc.rs` — /30 point-to-point allocator over a configurable
      pool, collision-avoiding, leases released on session end
- [x] `flow.rs` — bounded flow table, idle expiry, per-VM caps,
      exhaustion counters
- [x] `admit.rs` — anti-spoof + `CanonicalEgress` + mandatory-deny +
      private/multicast/broadcast/reserved deny + fragment policy +
      ICMP policy
- [x] `dns.rs` — bounded binding store over `DnsPinRegistry`, TTL
      expiry, rebinding guard
- [x] `ingress.rs` — declared mappings, conflict detection, per-session
      ownership

## W4 — Guest agent (`mvm-agentd::l3`, `[[bin]] mvm-net-agent`)

- [x] `TunDevice` trait; `/dev/net/tun` + `TUNSETIFF` impl (Linux);
      in-memory impl for tests
- [x] interface configuration via ioctl + raw netlink; no dependency on
      `ip`, `ifconfig`, `ethtool`, NetworkManager, or systemd-networkd
- [x] capability drop after setup (all sets + bounding set,
      `PR_SET_NO_NEW_PRIVS`)
- [x] packet pump: one IP packet per `PACKET` frame, version nibble
      selects v4/v6, no Ethernet header, preallocated buffers
- [x] lifecycle: readiness observable, explicit setup errors, clean
      stop, interface marked down on transport failure, no reconnect
      onto a stale session
- [x] `CONFIG_TUN` in `nix/images/kernel/workload.nix`

## W5 — Host gateway (`mvm-hostd::netd`, `[[bin]] mvm-netd`)

- [x] session bind from the per-VM listener (structural identity, never
      guest-asserted)
- [x] frame validation, bounded queues both directions, tail-drop with
      counters
- [x] policy application through `mvm-net::l3`
- [x] DNS service on the synthetic resolver address
- [x] `L3Datapath` / `DatapathHandle` platform seam
- [x] Linux datapath: host TUN + per-machine netns + narrow routes +
      nftables via the existing `NftApplier` seam; no bridge, no TAP,
      no Firecracker net device
- [x] macOS datapath: fails closed with a named error; admission
      refuses `l3-vsock` on macOS
- [x] deterministic cleanup on stop and on failed startup

## W6 — Audit + metrics

- [x] `LocalAuditKind` variants for the tunnel/flow/DNS/ingress events
      in ADR-035 §Audit
- [x] bounded metrics: packets/bytes by direction, active flows, denied
      flows, malformed frames, queue drops, DNS decisions, reconnects
- [x] no payloads, no DNS payloads beyond normalized metadata, no
      secrets, no per-packet logging at normal levels

## W7 — Tests

- [x] protocol: handshake, version mismatch, truncated header,
      inconsistent lengths, oversized frame, oversized packet, unknown
      type, stale session, malformed v4, malformed v6, excessive v6
      extension headers, fuzz-style arbitrary input
- [x] guest: TUN creation/config abstraction, route installation,
      readiness, privilege drop, disconnect marks networking
      unavailable, no shell-tool dependency
- [x] policy: allowed dest/port, denied dest, denied port, spoofed
      source, loopback, link-local, metadata, private denied by
      default, explicit CIDR allowance, unsolicited inbound, admitted
      return traffic, flow timeout, flow-table capacity, fragments,
      ICMP/ICMPv6
- [x] DNS: approved domain, denied domain, CNAME chain, TTL expiry,
      alternate DNS blocked, rebinding to private/loopback, direct IP
      denied under a domain-only rule, explicit IP rule independent of
      DNS
- [x] unprivileged end-to-end over an in-memory transport: real
      protocol, real policy, real gateway, mock datapath — covers
      scenarios 1–8 of the brief
- [x] privileged Linux end-to-end with real TUN/nftables, gated behind
      `MVM_L3_PRIVILEGED_TESTS=1`; executed on a Linux/KVM host — 6/6 green,
      including a live forwarding witness that reads the kernel's own RX
      counter, and a verified-clean teardown
- [x] BDD suite `s25_l3_vsock` (23 scenarios)
- [x] `UdsGuestChannelProvider` — the concrete per-port Unix-socket
      transport behind the backend-neutral abstraction, covering
      Firecracker, libkrun, and HVF; identity comes from the listener, not
      the reusable socket path
- [x] measured overhead on two hosts, recorded in ADR-035 §"Measured
      overhead"
- [x] `mvm-netd` as a real per-VM process: config on stdin, channels bound
      before the ready marker so the guest cannot race it, deterministic
      teardown; live-tested against the real guest agent on Linux
- [x] guest-side spawn: the host emits `mvm.l3=1` from the admitted plan,
      the guest init resolves and starts `mvm-net-agent`, waits for the
      readiness file, and refuses to start the workload if the tunnel does
      not come up; `mvm-net-agent` staged into the runtime overlay
- [x] live boot witness on real Firecracker: `CONFIG_TUN` kernel built,
      guest has only loopback before the agent runs, `mvm0` created with
      `ARPHRD_NONE` and no MAC — recorded in ADR-035 §"Live boot witness"
- [x] mode/plan compatibility gate — a plan that binds secrets, enables
      reversible replacement, or enables redaction cannot select
      `l3-vsock`, and the two plan fields cannot disagree in the hermetic lane: launch
      guard, admission, controlled DNS, session lifecycle, lease identity,
      capability gating, and control/data channel separation

## W8 — Documentation

- [x] ADR-035
- [x] user-facing guide with an example and an explicit warning that
      L3 mode cannot inspect or substitute inside encrypted traffic
- [x] claim catalog: the mode's guarantees and its named limits

## W9 — Amendment: backend-neutral transport, identity, and leases

- [x] `GuestChannelProvider` + typed `GuestService` normalize Firecracker
      UDS, libkrun UDS, HVF streams, native AF_VSOCK, and a future
      AF_HYPERV behind one abstraction
- [x] `VmInstanceIdentity { node_id, vm_id, boot_id, plan_digest }` — the
      host-owned per-boot identity everything authorizes against; a CID,
      a socket path, and a port are never authorization inputs
- [x] `NetworkLease` + `LocalLeaseAuthority`: one signed grant per boot,
      the same object a control plane will later issue; replay, transfer,
      wrong-node, epoch drift, and expiry all fail closed
- [x] `ControlPlaneLossPolicy` — hold-existing / hold-until-expiry /
      deny-immediately, none of which permit anything after expiry
- [x] `ForwardingCapabilities` — admission refuses a plan the selected
      backend cannot serve instead of degrading
- [x] `nic_guard` — the launch specification carries no guest
      network-device field, regression-gated, and `l3-vsock` is refused on
      any backend that does not advertise both `l3_vsock` and
      `no_routable_guest_nic`
- [x] launch-path audit recorded in ADR-035 §"Launch-path convergence"
- [x] macOS: `MacosUserspaceGateway` declares its intended capabilities and
      refuses until implemented
- [x] platform matrix (Linux / macOS / WSL2 / native Windows) documented
      without overclaiming
- [ ] node-to-node transport for cross-host VM traffic — interface
      described in the ADR, not implemented; the local path does not
      depend on it
- [ ] `mvmd`-facing node-control API — the responsibility split is
      documented and the lease is the contract, but no RPC surface exists

## Deferred (explicitly not in this change)

- [ ] **UDP ingress.** TCP ingress ships; UDP ingress needs a
      per-mapping datagram association table with its own bounds and is
      not implemented. Declaring a UDP ingress mapping is rejected at
      admission rather than silently ignored.
- [ ] **macOS userspace socket gateway.** The intended first macOS
      backend: TCP, UDP, and controlled DNS translated into host sockets,
      needing no privileges at all. Capability declaration and refusal
      ship; the flow translator does not.
- [ ] **macOS `utun` + PF datapath.** The later full-packet backend.
      Requires a privileged host helper mvm does not have. ADR-035 §macOS
      names the exact four privileged operations. Follow-up must add a
      helper whose API is only those operations plus status and cleanup —
      no arbitrary exec, no arbitrary PF rules, no file access.
- [ ] **WSL2 validation.** Architecturally supported; no runner has
      executed the suite there, so it is not claimed as tested.
- [ ] **Native Windows.** No Windows VMM backend exists to attach to.
- [ ] **Multi-queue.** The header field, the port base, and the
      negotiation slots exist in v1; the runtime opens one queue.
- [ ] **IPv6 datapath.** Blocked on `CONFIG_IPV6` in the workload
      kernel. The protocol and the host validator already handle v6.
- [ ] **Zero-copy / batched transfer.** The v1 copy path
      (guest kernel → guest buffer → vsock → host buffer → host TUN) is
      deliberate; optimize only against measurements.
