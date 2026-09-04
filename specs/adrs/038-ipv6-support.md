# ADR-038 — IPv6 as a first-class address family

**Status: Accepted — implemented end to end 2026-08-04. Host admission,
guest kernel, in-guest configuration, and host-side v6 address allocation
have all landed. IPv6 is opt-in per plan; it is not on by default.**
**Date: 2026-08-02**

**What shipped.** The admission guard admits IPv6; `embedded_v4` extracts
all four embedded forms ahead of every other rule and hands the result to
the unchanged v4 class check; native v6 classes mirror their v4
analogues; and the capability seam carries `ipv6_flows` separately from
`arbitrary_ipv6`. The ordering constraint below — fuzz the ingress parser
*before* relaxing the guard — was honoured: the fuzz target and its IPv6
corpus landed first.

**The guest kernel too.** `CONFIG_IPV6=y` in the workload kernel, at a
measured cost of 200,704 bytes and no IPsec — the IPsec-for-v6 options that
would have dragged XFRM in are disabled explicitly, and the required-disable
guard proves their absence on every build. See §"`CONFIG_IPV6` in the
workload kernel".

**And the guest agent.** A `CONFIG` carrying a v6 half now brings that half
up beside the v4 one — address, on-link peer, default route, resolver —
over rtnetlink, in the same privileged setup phase, before the drop. See
§"In-guest configuration: rtnetlink, not ioctl".

**And the host allocation.** A plan setting `features::IPV6` in its `l3`
network spec is leased a unique-local `/126` at the same index as its
`/30`; `assign_config` sends it; the granted feature bits say so; and the
gateway requires `ipv6_flows` of whichever forwarding backend was selected.
A plan that does not ask for IPv6 is unchanged in every byte. See §"Host
allocation: a unique-local /126 per machine, on request".
**Complements ADR-036 (L3 TUN-over-vsock) and ADR-052 (the userspace
socket datapath). Supersedes nothing; it removes IPv6 from ADR-036's
deferred set and gives it a design.**

## Context

`l3-vsock` carries IPv4 only. IPv6 was deferred in ADR-036 as "blocked on
`CONFIG_IPV6` in the workload kernel", with the note that the protocol and
the host validator already handle v6. That framing understated what is
present and overstated what blocks it.

What already exists:

- `mvm_protocol::l3::ip::parse_v6` parses IPv6, walking extension headers
  under explicit bounds (`MAX_IPV6_EXT_HEADERS`, `MAX_IPV6_EXT_BYTES`) that
  exist precisely because an attacker chains them to burn CPU.
- The network lease already carries `ipv6: Option<Ipv6Addr>`.
- `ForwardingCapabilities` already carries `arbitrary_ipv6`.
- smoltcp's `proto-ipv6` feature is already enabled — it was needed for the
  IPv6 arm of the userspace datapath's reset synthesis.
- The userspace datapath is barely coupled to v4: its device and limits
  modules carry no v4 references at all.

What actually blocks it is four admission guards that refuse any non-V4
destination, and the fact that relaxing them turns on two surfaces at once.

## Decision

Support IPv6 as a first-class address family: the same default-deny
posture, the same policy projection, the same audit chain, the same
capability honesty. Three decisions carry the weight.

### 1. One `embedded_v4` extraction, then the full v4 class check

IPv6 provides **four** ways to write an IPv4 address. Every one of them
reaches `169.254.169.254`:

| Form | Prefix | Example |
|---|---|---|
| v4-mapped | `::ffff:0:0/96` | `::ffff:169.254.169.254` |
| v4-compatible (deprecated) | `::/96` | `::169.254.169.254` |
| NAT64 well-known | `64:ff9b::/96` | `64:ff9b::169.254.169.254` |
| 6to4 | `2002::/16` | `2002:a9fe:a9fe::` |

v4-mapped is the famous one. NAT64 and 6to4 are the ones that get
forgotten, and a NAT64 gateway on the host network makes the third
genuinely routable.

So the v6 class check does not enumerate v6 hazards and hope the list is
complete. It **extracts first**:

```
embedded_v4(addr) -> Option<Ipv4Addr>   // ::ffff:/96, ::/96, 64:ff9b::/96, 2002::/16
```

If extraction yields a v4 address, that address goes through the **entire
existing v4 class check**, unchanged — not a special case bolted onto the
v4-mapped path. Only a genuinely native v6 address reaches the v6 rules.
One function, one place to get right, and an encoding nobody anticipated
fails closed because the surrounding posture is deny-by-default.

This preserves the property `destination_class_denial` already documents:
address-class refusals are checked before any allow-list is consulted, so
no rule shape can open them.

### 2. Native v6 address policy mirrors v4 exactly

| Range | Verdict | v4 analogue |
|---|---|---|
| `::1` | mandatory deny | `127.0.0.0/8` |
| `::` | mandatory deny | `0.0.0.0` |
| `fe80::/10` link-local | mandatory deny | `169.254.0.0/16` |
| `ff00::/8` multicast | mandatory deny | v4 multicast |
| `fc00::/7` ULA | deny unless explicitly admitted | RFC1918 |

Link-local is a **mandatory** deny, not an opt-in: `fe80::/10` is where NDP
neighbours and routers live, so a guest reaching it reaches the host's own
interfaces. ULA is the direct analogue of RFC1918 and follows the same
deny-unless-admitted path, through the same allow-list machinery.

There is deliberately no v6 broadcast row — IPv6 has no broadcast, and
`ff02::1` (all-nodes) is covered by the multicast rule.

### 3. `arbitrary_ipv6` stays false; add `ipv6_flows`

`arbitrary_ipv6` means "can put an arbitrary IPv6 packet on the wire." A
userspace socket gateway **cannot** — exactly as it cannot for v4, which is
why `USERSPACE_SOCKETS` sets `arbitrary_ipv4: false`. Setting it true would
be over-claiming, and the capability seam exists so a backend refuses what
it cannot serve rather than degrading.

The missing distinction is a different one: *can this backend carry v6
flows at all*, separate from *can it emit arbitrary v6 packets*. So:

- add `ipv6_flows: bool` — TCP and UDP over IPv6 are carried
- leave `arbitrary_ipv6` meaning what it says
- `USERSPACE_SOCKETS`: `ipv6_flows: true`, `arbitrary_ipv6: false`
- `FULL_L3_V4` becomes `FULL_L3`: both true

A plan needing arbitrary v6 packets is still refused on the userspace
backend, for the right reason, with the shortfall naming
`arbitrary_ipv6`.

## The surface this turns on, and why the ordering is not negotiable

smoltcp's `proto-ipv6` is compiled in today and is inert for exactly one
reason: `admit_outbound` refuses `version != 4`. It is **not** inert
because the interface has no IPv6 address. Reading smoltcp 0.13.1:

- `process_hopbyhop` runs **before** any address check, so a hop-by-hop
  option chain is parsed with no IPv6 address configured, and can emit an
  ICMPv6 ParamProblem.
- The no-IPv6-address drop is not total. `::1` passes via `is_loopback()`,
  and `ff02::1` and solicited-node addresses pass `has_multicast_group` —
  true even with smoltcp's `multicast` feature off. Those reach
  `process_nxt_hdr`, `process_icmpv6` (NDP, MLD, echo), and socket
  dispatch.

So relaxing the admission guard hands a hostile guest a live NDP/ICMPv6/
hop-by-hop parser. That parser must be **fuzzed before the guard relaxes**,
not after. The fuzz target belongs to the userspace datapath's ingress work
and must carry IPv6 corpus entries; this ADR's implementation may not land
its admission change until that target exists and runs.

This is one task's delay. The alternative is shipping an unexercised parser
to an attacker-controlled input path, which no amount of subsequent testing
un-ships.

## `CONFIG_IPV6` in the workload kernel

**Built and measured on a Linux 6.12.100 kernel, 2026-08-04.** IPv6 is
enabled in the workload kernel and costs no IPsec.

| | baseline | with IPv6 | delta |
|---|---|---|---|
| `bzImage` | 4,072,448 B | 4,273,152 B | **+200,704 B (+4.9%)** |
| built-in symbols | 72,523 | 75,208 | +2,685 |

That is the "few hundred kilobytes" this ADR anticipated, so IPv6 lands
unconditionally rather than becoming an image variant.

**What it took, and the false start worth recording.** The first attempt
enabled `IPV6` alone and the config guard refused the build:

```
ERROR: required kernel disables were reverted by olddefconfig: XFRM_ALGO XFRM
```

The initial reading — that IPv6 *requires* IPsec — was wrong. Core IPv6
selects only `CRYPTO_LIB_SHA1`. What `olddefconfig` enables alongside it
is the IPsec-for-v6 family, and those select XFRM:

`IPV6_MIP6`, `IPV6_VTI`, `INET6_AH`, `INET6_ESP`, `INET6_ESP_OFFLOAD`,
`INET6_ESPINTCP`, `INET6_IPCOMP`, `INET6_XFRM_TUNNEL`, `INET6_TUNNEL`

Disabling those beside enabling `IPV6` builds cleanly. The resulting config
carries `CONFIG_IPV6=y` and `# CONFIG_XFRM_USER is not set`, and the guard
passes — which is the point: `XFRM`, `XFRM_ALGO` and `XFRM_USER` stay in
the *required* disable set, so their absence is proven on every build
rather than asserted in a comment. If a later option drags XFRM back, the
build fails exactly as it did here.

Four `xfrm4_tunnel_register`/`deregister` symbols appear, from IPv4 tunnel
registration stubs rather than the transform framework. There is no XFRM
state machine and no netlink interface for a guest to reach.

## In-guest configuration: rtnetlink, not ioctl

The v4 bring-up assigns its address, netmask, peer, MTU, flags, and default
route through `SIOCSIF*` / `SIOCADDRT` ioctls on an `AF_INET` socket. The
obvious move was to mirror it on an `AF_INET6` socket. That road runs out
halfway:

- the v6 address ioctl takes `struct in6_ifreq`, a different shape from
  `ifreq`, so `ifreq_for` and `set_sockaddr_in` do not generalise; and
- the v6 route ioctl takes `struct in6_rtmsg`, whose fields `libc` declares
  private. Constructing one means hand-rolling the struct anyway.

So the ioctl path buys a partial mirror and still ends in hand-rolled
kernel structs. rtnetlink carries both halves with one mechanism, and this
crate already speaks it: the boot-time blackhole installer sends
`RTM_NEWROUTE` over a synchronous `AF_NETLINK` socket. The IPv6 bring-up
shares that socket type, its ABI constants, and its request framing rather
than forking a second copy.

Three requests, in this order:

1. `RTM_NEWADDR` — the address and its prefix, with `IFA_F_NODAD`.
   Duplicate Address Detection has no neighbour to find on a
   point-to-point link whose only other end is the gateway, and it would
   leave the address unusable while it looked.
2. `RTM_NEWROUTE` — the peer as an on-link `/128` on the device. This is
   the v6 analogue of `SIOCSIFDSTADDR`: without it the default route is
   accepted only when the peer happens to fall inside the assigned prefix.
3. `RTM_NEWROUTE` — `::/0` via the peer, naming the device explicitly.

All three are built by a pure function that returns the exact wire bytes
and the label each failure is reported under, so the order, the constants,
and every field are asserted on any host — no socket, no privilege, no
Linux. The platform-gated code only hands them to the kernel in turn. Each
runs before `drop_privileges`, in the same phase as the v4 sequence:
`CAP_NET_ADMIN` is not held one instruction longer than it already was.

`EEXIST` on any of the three is success. An address and its routes are
desired state, not write-once operations.

**A v6-only `CONFIG` is refused, not half-applied.** The MTU, the link
state, and the default route all hang off the v4 sequence, so a guest
handed a v6-only assignment would come up looking configured with no route
off its link. The allocator assigns a v4 pair with every lease, so this is
a contradiction to name rather than a case to serve. IPv6 is additive here.

## Host allocation: a unique-local /126 per machine, on request

Three questions had to be answered together: which addresses, how big a
slice, and who asks.

### The pool is unique-local, which is a security decision as much as an addressing one

Guest addresses come from `fd00::/8` — RFC 4193 unique-local — never from
global space and never from documentation space. Global space would hand a
workload a routable identity nobody asked for, that outlives the machine in
any log it touches, and that the host cannot revoke. Documentation space
(`2001:db8::/32`) is reserved for prose and would collide with the first
example an operator pastes into a rule.

The global ID is fixed (`fd6d:766d:1::/64`) rather than randomised per
host. RFC 4193 asks for randomness to make two ULA networks unlikely to
collide; here the two risks that buys off are already covered — an overlap
with a route the host already has is what `AddressAllocator::exclude` is
for, and the pool is configurable when that is not enough — while a
deterministic prefix is the difference between a packet capture an operator
can read and one they cannot. An allocator configured with a pool outside
`fc00::/7` is refused rather than accepted.

**The consequence that matters.** `fc00::/7` is deny-unless-admitted in the
v6 class rules, and the pool sits inside it. So every guest's own address
is now in the range the class check closes. That is the correct shape and
must stay: holding an address in `fc00::/7` is an identity on the
point-to-point link, **not** a permission to reach the range. A machine
cannot reach its neighbour's leased address, its neighbour's gateway, or
unrelated ULA space, under any egress policy including `unrestricted`,
unless a rule explicitly admits the destination — the same machinery, and
the same refusal code, as RFC1918 in v4. This is the property most likely
to be broken silently by adding the pool, so it is witnessed at the
admitter and again end to end through the real guest agent, and both
witnesses are mutation-proven against removing the ULA arm of the class
check.

### A /126, at the same index as the /30

The `/126` is the direct analogue of the v4 `/30`: four addresses, of which
`.1` is the gateway (peer, default route, and synthetic resolver, all the
same address) and `.2` is the guest. Nothing else is on-link.

The v6 subnet is carved at the *same index* as the v4 one, out of one index
space. That is what makes the two families share a single free-list: one
`release` frees both, no second table can fall out of step with the first,
and the "no two live machines share an address" property is identical in
each family rather than merely similar. A machine that asked for v6 and one
that did not can never be handed the same `/30` either.

### Opt-in, not always

`L3NetworkSpec.features` — already part of the signed plan — is the
request. Setting `features::IPV6` is what causes the host to allocate a v6
pair; leaving it off produces a lease, a `CONFIG`, and a guest
configuration identical in every byte to the v4-only ones.

The argument for always-on is parity: a workload that gets v4 should be
able to get v6. It *can* — the request is one bit in a spec every `l3` plan
already carries, and nothing about the path is conditional or unfinished.
The argument against handing it to everyone is that an address family the
workload does not use is still reachable surface: a second stack for a
compromised guest to originate from, a second family for anti-spoofing and
the class check to be right about, and a second address in every audit
line. mvm's posture everywhere else is that capability is declared, not
inherited. IPv6 follows it.

The bit is also what makes the capability honest. A leased v6 pair sets
`required_capabilities.ipv6_flows`, so a backend that cannot carry v6 flows
refuses the session at open with a shortfall naming `ipv6_flows`, before
the VM boots — rather than letting the guest configure an address whose
packets die somewhere it cannot see. Both backends declare it now: the
userspace gateway carries the flows without claiming it can emit an
arbitrary v6 packet, and the Linux TUN datapath declares the whole
`FULL_L3` set, because it assigns the v6 pair and pins the v6 source in
the same ruleset that pins the v4 one.

### The handshake grants what both sides can support

`features::granted(offered, assigning_v6)` is the intersection: the host
grants `IPV6` only when the guest offered it in `HELLO` **and** the host
leased a pair. `Hello::v1()` offers it, because this guest can apply one.
A guest that does not offer it and a host that leased a pair is a refusal
(`FeatureUnsupported`), not a silent downgrade to v4 — the plan asked for a
family, and a workload quietly given less than it was admitted for is the
failure this whole seam exists to prevent. `Config::decode` enforces the
same agreement on the wire: the `IPV6` bit is set exactly when a v6
assignment is present.

### What remains unwired above the plan

The request is expressible and enforced in the signed plan, and the launch
path acts on it. What no `mvmctl` surface does yet is *populate* an
`L3NetworkSpec` — not for IPv6 and not for any other field of it. Every
`SynthesisInput` construction site passes `l3_network: None`, and the boot
path's site additionally hardcodes `network_mode: Default`, so today an
`l3-vsock` plan with a spec is produced only by the plan-mode admission
path and by callers that build one directly. Giving IPv6 a CLI flag or a
workload-IR field in isolation would add a knob that is inert on the path
that actually boots a VM, which is the same defect in mirror image. The two
belong together and are not attempted here.

## What this does not do

- **No arbitrary IPv6 packet forwarding on the userspace backend.** ICMPv6
  as a workload-visible protocol, raw v6, and arbitrary v6 remain refused
  at admission. Closing that needs the privileged full-packet datapath,
  which is its own decision.
- **No IPv6 ingress mappings** beyond what the existing declared-ingress
  machinery covers once it is family-generic.
- **No dual-stack policy language.** A destination rule names an address or
  a range; it does not acquire a family selector. If a workload needs both
  families it declares both.

## Consequences

The destination-integrity assertion in the userspace datapath compares
addresses on canonical form. That is correct for an identity check, but it
means the peer assertion will **not** catch a v4-mapped bypass — it
collapses exactly the distinction the bypass exploits. The class check is
therefore the only line of defence against embedded-v4 forms, which is why
decision 1 puts extraction ahead of every other rule and why that code
needs its own tests rather than relying on the backstop.
