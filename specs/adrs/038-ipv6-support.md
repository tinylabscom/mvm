# ADR-038 — IPv6 as a first-class address family

**Status: Accepted — host side landed 2026-08-04; guest kernel still open**
**Date: 2026-08-02**

**What shipped.** The admission guard admits IPv6; `embedded_v4` extracts
all four embedded forms ahead of every other rule and hands the result to
the unchanged v4 class check; native v6 classes mirror their v4
analogues; and the capability seam carries `ipv6_flows` separately from
`arbitrary_ipv6`. The ordering constraint below — fuzz the ingress parser
*before* relaxing the guard — was honoured: the fuzz target and its IPv6
corpus landed first.

**What has not.** `CONFIG_IPV6` in the workload kernel, and the in-guest
address configuration beside it. This ADR requires that delta be measured
rather than assumed, and no measurement has been taken. Until one is, the
host admits v6 that no guest can yet originate — which is a gap in reach,
not in safety, since every refusal above is enforced regardless.
**Complements ADR-036 (L3 TUN-over-vsock) and ADR-037 (the userspace
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

The original blocker is real but small: the guest kernel needs the option
compiled in, plus in-guest address configuration alongside the existing v4
bring-up.

It carries a coordination cost. Work is in flight to shrink guest kernels
to the virtual hardware floor, and adding `CONFIG_IPV6` silently reverses
part of that if landed carelessly. So the kernel change is **measured, not
assumed**: build both, record the image-size and boot-time delta in the
implementation plan, and land it as a known accepted cost rather than an
unexplained regression. If the delta proves material rather than the few
hundred kilobytes expected, IPv6 becomes a guest-image variant instead of
an unconditional default.

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
