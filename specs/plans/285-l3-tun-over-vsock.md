# Plan 285 — L3 TUN-over-vsock network mode

**Status: RETIRED AND DELETED — preserved as historical implementation record**
**ADR: [036](../adrs/036-l3-tun-over-vsock.md)**

Plan 316 and ADR-042 replaced this production path with FlowMux. The complete
L3 implementation was deleted by the FlowMux single-path closeout; the checked
items below record what previously shipped and are not current product claims.

Opt-in `l3-vsock` network mode: the guest gets a point-to-point `mvm0`
TUN interface, the guest agent frames raw IP packets over dedicated
vsock connections, and a machine-scoped host gateway applies policy
before anything reaches host networking. No guest NIC, no TAP, no
bridge, no L2.

Read ADR-036 first; this plan is the sequencing and the checkbox ledger.

## W1 — Canonical mode + plan representation

- [x] `NetworkMode::L3Vsock` in `mvm-contract::plan::types`
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
- [x] plan synthesis derives `L3NetworkSpec` from the admitted
      `NetworkMode`, so the mode and the spec cannot disagree and the
      compatibility gate never sees a half-formed L3 plan
- [x] machine inspect / receipt output names the admitted mode

## W2 — Shared protocol (`mvm-contract::l3`)

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
- [x] Linux datapath: host TUN + narrow routes + a shared `inet mvmn`
      nftables table with one host-wide default-drop forward hook and
      per-machine filter/NAT chains; no bridge, no TAP, no Firecracker net
      device. The machine chains pin the assigned IPv4 source and the
      opt-in IPv6 source, with stateful return filtering and masquerade.
- [x] Linux datapath: host TUN + per-machine netns + narrow routes +
      nftables via the existing `NftApplier` seam; no bridge, no TAP,
      no Firecracker net device
- [x] nftables isolation: all machines share one `inet mvmn` table and one
      `forward` base chain with a host-wide default drop; each machine owns
      interface-scoped jump chains for filtering and NAT, and serialized
      updates/teardown remove only that machine's rules
- [x] macOS datapath: fails closed with a named error; admission
      refuses `l3-vsock` on macOS
- [x] deterministic cleanup on stop and on failed startup
- [x] launch-path wiring: the workload runner starts the gateway and
      waits for it to report both channels bound **before** the VM boots
      (a guest that dials an unbound channel fails closed for no
      reason), and every stop path — clean stop, crashed-guest stop —
      reaps it, so a host TUN and an nft table never outlive the guest
- [x] the boot path reads the declaration. `machine run` passed a
      hardcoded `false` to `preflight_network`, so only the admission-only
      `--mode plan` route honoured `raw_ip_stack` and no *booting* workload
      could reach the tunnel. `runtime.rs` now reads the same workload-IR
      field the admission path reads, so a workload cannot be admitted for
      one transport and booted on another; unreadable IR fails closed
      rather than guessing
- [x] live derivation witness on a Linux/KVM host, through the real
      `machine run` boot path — same binary, same command, same host, the
      workload's declaration the only difference:

      ```text
      raw_ip_stack=true  -> derived machine networking network_mode=L3Vsock
      (not declared)     -> derived machine networking network_mode=HostVsockProxy
      ```

      Both then stop on the supplied manifest, which confirms the
      transport is settled before any build or boot work. Against the
      previous hardcoded `false` both lines read `HostVsockProxy`.

## W6 — Audit + metrics

- [x] `LocalAuditKind` variants for the tunnel/flow/DNS/ingress events
      in ADR-036 §Audit
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
      `MVM_L3_PRIVILEGED_TESTS=1`; 13/13 green on the Linux/KVM builder,
      covering dual-stack address assignment, IPv6 anti-spoofing, ULA
      isolation, shared-table teardown, and two-machine forwarding.
      `MVM_L3_PRIVILEGED_TESTS=1`; the lane now contains nine tests,
      including live forwarding witnesses for two concurrent machines,
      kernel counters, and verified-clean teardown; Linux/KVM execution is
      the acceptance gate
- [x] BDD suite `s25_l3_vsock` (23 scenarios)
- [x] `UdsGuestChannelProvider` — the concrete per-port Unix-socket
      transport behind the backend-neutral abstraction, covering
      Firecracker, libkrun, and HVF; identity comes from the listener, not
      the reusable socket path
- [x] measured overhead on two hosts, recorded in ADR-036 §"Measured
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
      `ARPHRD_NONE` and no MAC — recorded in ADR-036 §"Live boot witness"
- [x] `network.raw_ip_stack` end to end: declared in the workload's
      decorator, parsed into the IR, read by the run path, and derived into
      the signed plan's `network_mode`
- [x] mode/plan compatibility gate — a plan that binds secrets, enables
      reversible replacement, or enables redaction cannot select
      `l3-vsock`, and the two plan fields cannot disagree in the hermetic lane: launch
      guard, admission, controlled DNS, session lifecycle, lease identity,
      capability gating, and control/data channel separation

## W8 — Documentation

- [x] ADR-036
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
- [x] launch-path audit recorded in ADR-036 §"Launch-path convergence"
- [x] macOS: a capability declaration plus a refusal until implemented.
      (The `MacosUserspaceGateway` type that carried it is now deleted —
      see the deferred set below.)
- [x] workload launch mapping carries `GuestService::NetworkControl` and
      `GuestService::NetworkData { queue: 0 }` into the backend-neutral
      `VmmSpec`; `mvm-netd` selects the matching Firecracker/libkrun or HVF
      socket-directory layout from the selected backend
- [x] `VmmSpec::vsock` identifies every standing channel by `GuestService`;
      numeric vsock ports are derived only at the VMM transport boundary,
      including the dynamic dev-console data channels
- [x] `VmmSpec` no longer carries builder-role policy; every boot, including
      builder boots, requires the typed `GuestService::Substitution` channel,
      while the builder endpoint remains owned by the builder runner above the
      VMM driver seam
- [x] macOS: `MacosUserspaceGateway` declares its intended capabilities and
      refuses until implemented
- [x] platform matrix (Linux / macOS / WSL2 / native Windows) documented
      without overclaiming
- [~] node-to-node transport for cross-host VM traffic — **designed in
      ADR-040 and deliberately not implemented**; the local path does not
      depend on it. Three of the hop's four invariants are unpreservable
      today and none of the three is fixable inside a transport: there is
      no cross-node trust root and adding one here would be a second root
      beside plan signing; `PoolAllocator` has no node discriminator, so a
      peer's address collides with a local machine's and the two are not
      distinguishable from the packet; `CanonicalRule` cannot name a peer
      workload and `IngressTable::admits` takes only a protocol and a
      guest port, so admitting a peer admits the host network too; and the
      chain-signed audit log does not reach `netd`, so the hop has no
      local record to preserve. ADR-040 carries the unblock checklist
- [ ] `mvmd`-facing node-control API — the responsibility split is
      documented and the lease is the contract, but no RPC surface exists

## Deferred (explicitly not in this change)

- [x] **UDP ingress.** Delivered by
      `specs/plans/287-userspace-socket-datapath.md` WS2. A UDP mapping is
      declarable end to end — plan, lease, netd config, `IngressTable` —
      and the userspace socket datapath binds a host listener per mapping,
      with a bounded per-listener peer table for the reply path. Delivery
      still goes through `admit_inbound`, so a withdrawn declaration stops
      it. **TCP** ingress remains unserved on the socket backend: it needs
      a listener whose accepted connections are originated toward the
      guest, which that backend does not build. The packet backend serves
      both.
- [x] **macOS userspace socket gateway.** Delivered by
      `specs/plans/287-userspace-socket-datapath.md` (ADR-052), and widened
      on the way: `UserspaceSocketDatapath` is platform-neutral, so it also
      serves a Linux host that holds no `CAP_NET_ADMIN`. The
      `MacosUserspaceGateway` placeholder — declaration plus refusal — is
      deleted. ICMP, raw IP protocols and arbitrary IPv4/IPv6 stay refused
      at admission on it, and two gaps are open rather than closed:
      declared ingress is advertised with nothing listening behind it, and
      the readiness descriptor has nothing registered on it, so every
      host-driven step waits for a 50 ms tick. Both are recorded in ADR-052
      §"Known defects in what shipped".
- [ ] **macOS `utun` + PF datapath.** The later full-packet backend.
      Requires a privileged host helper mvm does not have. ADR-036 §macOS
      names the exact four privileged operations. **Closed rather than
      queued:** ADR-039 proposed exactly that helper and is Rejected — mvm
      adds no root-capable component — so this stays undone unless a
      workload with a demonstrated need reopens the decision.
- [ ] **WSL2 validation.** Architecturally supported; no runner has
      executed the suite there, so it is not claimed as tested.
- [ ] **Native Windows.** No Windows VMM backend exists to attach to.
- [ ] **Multi-queue.** The header field, the port base, and the
      negotiation slots exist in v1; the runtime opens one queue.
- [x] **IPv6 datapath.** The parser, validator, lease, guest configuration,
      host address assignment, capability declaration, and Linux nftables
      source pinning are implemented and covered by 13/13 green Linux/KVM
      privileged witnesses. macOS remains on the userspace socket backend
      for full-packet IPv6.
- [ ] **Zero-copy / batched transfer.** The v1 copy path
      (guest kernel → guest buffer → vsock → host buffer → host TUN) is
      deliberate; optimize only against measurements.
