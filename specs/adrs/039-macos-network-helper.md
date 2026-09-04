# ADR-039 — The macOS privileged network helper

**Status: Rejected — 2026-08-03. mvm adds no root-capable component.**
**Date: proposed 2026-08-02, rejected 2026-08-03. Tracked as issue #2122.**
**Complements ADR-036 (L3 TUN-over-vsock) §"macOS (Apple Silicon)", which
enumerated the four privileged operations, and ADR-052 (the userspace
socket datapath), which deliberately avoids needing any of them.**

## Why this ADR needs a signature, not just a review

Every other component in this system runs unprivileged, or drops privilege
before touching anything a guest influences. This one cannot: a `utun`
device on macOS requires root, and no entitlement grants it otherwise.

So this proposes **adding a root-capable process to the trust boundary**.
That is a different kind of decision from the rest of this workstream, and
it should be made deliberately by a maintainer rather than absorbed as an
implementation detail of a networking feature. Nothing here should be built
until that happens.

The honest framing: mvm's threat model (ADR-001) explicitly places a
malicious *host* out of scope, so a root helper does not break a stated
guarantee. What it does is enlarge the blast radius of any bug in the
helper itself from "one VM's networking" to "root on the host". That
trade buys ICMP, traceroute, and arbitrary IP protocols for macOS
workloads — capabilities the userspace socket datapath refuses at
admission today.

## What it buys, precisely

`ForwardingCapabilities::USERSPACE_SOCKETS` sets `icmp`, `arbitrary_ipv4`,
`arbitrary_ipv6`, `raw_ip_protocols`, and `full_packet_forwarding` to
false. A plan needing any of them is refused on macOS, for the right
reason. The helper is what turns those true — nothing else.

If no workload needs them, this ADR should be rejected and the userspace
datapath left as the sole macOS backend. **That is a legitimate outcome and
the cheapest one.** The question to answer before signing is not "can we
build this safely" but "does a workload actually need raw IP on macOS".

## Decision (proposed)

A single-purpose helper, `mvm-netd-helper`, exposing **exactly four
operations plus status and cleanup**. Not a privileged shell, not a
general-purpose network daemon, not a `pfctl` wrapper.

### The four operations

1. **`CreateUtun { machine_id }`** — `socket(PF_SYSTEM, SOCK_DGRAM,
   SYSPROTO_CONTROL)` + `connect()` with `ctl_info` for
   `com.apple.net.utun_control`. Returns the interface name and passes the
   descriptor back over the control socket via `SCM_RIGHTS`. The helper
   does not keep it.
2. **`ConfigureAddress { machine_id, gateway, guest, prefix_len, mtu }`** —
   `SIOCAIFADDR` + `SIOCSIFMTU`, on that machine's interface only.
3. **`InstallRoute { machine_id, destination }`** — `PF_ROUTE` write scoped
   to that machine's utun. Never a default route, never a route through any
   other interface.
4. **`LoadAnchor { machine_id, rules }`** — load an mvm-owned PF anchor at
   `mvm/<machine_id>`, enabling PF if disabled. The **rules are generated
   by the helper** from a typed policy struct — the caller never supplies
   PF syntax.

Plus `Status { machine_id }` and `Cleanup { machine_id }`, where cleanup is
idempotent and total for that machine.

### What it must refuse, structurally rather than by validation

- **No arbitrary command execution.** No `sh`, no `pfctl` with
  caller-supplied arguments, no `exec` of anything.
- **No caller-supplied PF syntax.** Rules are generated from a typed
  struct. A caller cannot express a rule the type system does not permit.
- **No operations outside the anchor `mvm/<machine_id>`.** The helper
  cannot flush another anchor, cannot disable PF wholesale, cannot touch
  the main ruleset.
- **No interface outside the one it created for that machine.**
- **No filesystem access** beyond its own socket and the anchor it owns.
- **No route not scoped to that machine's utun.**

The distinction that matters: these are properties of the *wire format*,
not of a validation layer. A validation layer can be bypassed by a bug in
the validator. If the protocol has no way to express "run this command",
no bug can produce one.

### Authentication and ownership

The helper must authenticate the calling supervisor and refuse machines
that supervisor does not own. Concretely: the control socket is per-user
and mode 0700, the caller's identity comes from `SO_PEERCRED`-equivalent
(`LOCAL_PEERCRED` on macOS) rather than anything in the message, and each
machine is bound to the first caller that created it. A second caller
asking about someone else's machine gets a refusal, not a status.

This is the property that stops the helper from being a
privilege-escalation primitive for any local process that can reach its
socket.

## Alternatives considered

**Do nothing — keep the userspace socket datapath as the sole macOS
backend.** Costs: no ICMP, no raw IP, no arbitrary protocols on macOS.
Benefit: no root component, ever. **This is the recommended default unless
a real workload need is identified.**

**Ship the helper as an optional, separately-installed component.** Users
who need raw IP install it; everyone else never has a root process. This
narrows exposure to those who opted in, at the cost of a second
installation path and a capability that varies by host — which the
capability seam already handles honestly, since admission refuses what the
backend cannot serve.

**Use an existing privileged mechanism.** There is none that fits: the
`jailer` in this repo is a Linux confinement tool, not a macOS privilege
broker, and reusing it would mean giving it a second unrelated purpose.

## Consequences

- A bug in the helper is a root bug. Its surface must stay small enough to
  audit in one reading, and it should be the most heavily fuzzed component
  in the repo relative to its size.
- It needs its own claim in the security ledger, or an explicit statement
  in ADR-001 that it is out of scope. Adding a root process without saying
  so in the posture document would make that document wrong.
- `USERSPACE_SOCKETS` and the full-packet capabilities must remain
  distinguishable, so a host with the helper and a host without refuse
  different plans — honestly, and for stated reasons.

## Status

**Rejected, 2026-08-03.** mvm adds no root-capable component. The
recommended default in "Alternatives considered" is the decision: keep the
userspace socket datapath as the sole macOS backend, and leave ICMP, raw
IP, and arbitrary IPv4/IPv6 refused at admission.

The question this ADR asked was not "can we build this safely" but "does a
workload actually need raw IP on macOS." Nothing does. Paying a permanent
root process — and the blast radius that any bug in it would carry, from
one VM's networking to root on the host — for capabilities nothing asks
for is a bad trade. The capability seam already refuses those plans with
the shortfall named, rather than degrading silently.

Reopening requires a workload with a demonstrated need, not a hypothetical
one. Everything above stays as the design of record for that case: the
four operations, the structural refusals, and the `LOCAL_PEERCRED`
ownership binding remain what a helper would have to look like. The
requirement that those be properties of the wire format rather than of a
validation layer is the part most worth preserving — a validator can be
bypassed by a bug in the validator; a protocol that cannot express "run
this command" cannot be talked into one.
