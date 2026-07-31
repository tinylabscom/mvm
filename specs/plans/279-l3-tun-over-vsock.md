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
- [x] `mvmctl machine run --network-mode <none|host-vsock-proxy|l3-vsock>`;
      never implicit, never inferred from the presence of an egress rule
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
- [x] privileged Linux end-to-end with real TUN/netns/nftables, gated
      behind `MVM_L3_PRIVILEGED_TESTS=1`

## W8 — Documentation

- [x] ADR-035
- [x] user-facing guide with an example and an explicit warning that
      L3 mode cannot inspect or substitute inside encrypted traffic
- [x] claim catalog: the mode's guarantees and its named limits

## Deferred (explicitly not in this change)

- [ ] **UDP ingress.** TCP ingress ships; UDP ingress needs a
      per-mapping datagram association table with its own bounds and is
      not implemented. Declaring a UDP ingress mapping is rejected at
      admission rather than silently ignored.
- [ ] **macOS `utun` + PF datapath.** Requires a privileged host helper
      mvm does not have. ADR-035 §macOS names the exact four privileged
      operations. Follow-up must add a helper whose API is only those
      operations plus status and cleanup — no arbitrary exec, no
      arbitrary PF rules, no file access.
- [ ] **Multi-queue.** The header field, the port base, and the
      negotiation slots exist in v1; the runtime opens one queue.
- [ ] **IPv6 datapath.** Blocked on `CONFIG_IPV6` in the workload
      kernel. The protocol and the host validator already handle v6.
- [ ] **Zero-copy / batched transfer.** The v1 copy path
      (guest kernel → guest buffer → vsock → host buffer → host TUN) is
      deliberate; optimize only against measurements.
