# ADR-110: Uniform userspace vsock egress (one smoltcp forwarder + host-originated secret substitution)

**Status:** Proposed — 2026-07-11
**Summary:** Collapse host-side workload egress onto a single userspace model on every
backend (libkrun, Firecracker, HVF, future WHP): a `smoltcp` forwarder for direct
flows and a host-originated vsock substitution endpoint for secret-bearing flows.
Retire the Linux host-TUN + kernel-NAT path. No NAT device, no privilege, no guest
networking stack beyond vsock.

## Context

The Phase 2A raw-L3 egress data plane landed across five PRs: Linux host-`/dev/net/tun`
+ kernel masquerade NAT (#1634), and a macOS userspace `smoltcp` forwarder for TCP
(#1639), UDP (#1647), and ICMP echo (#1650), plus a fuzz target for the packet gate
(#1643). That left **two different host-side forwarding mechanisms** for what is one
job.

The invariant this ADR is written against (reaffirmed by the maintainer):

- The microVM's **only** I/O channel is vsock. There is no networking stack *beyond*
  vsock from the guest's perspective, and **no NAT device** in the egress path.
- **Zero secrets or sensitive data land in the microVM.** Secrets are replaced
  host-side and the substituted request + its response ride the **vsock** channel.

The Linux host-TUN + kernel-NAT path conflicts with the spirit of that invariant: it
needs `CAP_NET_ADMIN`, installs a NAT device, is Linux-specific, and has no
unprivileged equivalent on macOS (`pf` needs root) or Windows.

## The requirement

One host-side egress model that is: **uniform** across libkrun / Firecracker / HVF /
WHP, **unprivileged**, uses **no NAT device**, keeps the microVM **vsock-only**, keeps
the guest with **no networking stack beyond vsock**, and lets **zero secrets** reach
the guest.

## Options considered

**A. Kernel NAT everywhere** (host TUN + kernel NAT on each OS). Fastest, but needs
`CAP_NET_ADMIN`/root and a NAT device, and has no unprivileged form on macOS/Windows.
Rejected — violates the no-NAT / unprivileged / uniform requirement.

**B. One userspace `smoltcp` forwarder everywhere.** `smoltcp` runs entirely
host-side and is **VMM-agnostic**: the guest pumps raw-L3 packets over vsock and the
host worker feeds them into a `smoltcp::Interface` that terminates TCP/UDP and splices
the byte stream to ordinary host `std::net` sockets. The VMM only supplies the vsock
transport — which libkrun (in-process vsock) and Firecracker (host AF_VSOCK) already
do, which is why the worker was built backend-neutral. Uniform, unprivileged, no NAT,
vsock-only. **Chosen.**

**C. Host kernel sockets via a socket-level vsock proxy (TSI-style).** The guest
relays socket operations over vsock instead of running a TCP/IP stack; the host opens
**kernel** sockets and splices. No userspace TCP anywhere — the performance end-state,
and an even tighter fit for "no networking stack beyond vsock" (the guest has no IP
stack at all). Deferred (see Performance).

## Recommendation

1. **Unify host forwarding on `smoltcp` (option B) across all backends.** Promote the
   `smoltcp` forwarder from `#[cfg(target_os = "macos")]` to the universal host
   forwarder; **retire** `host_tun` + the nft NAT + the `host_tun_nat_live` witness.
2. **One codebase, one thin trait.** TCP/UDP termination + packet framing + the socket
   bridge are pure `smoltcp` + `std::net` — identical on every OS. The *only*
   platform-specific piece is the unprivileged ICMP-echo socket (Linux ping socket /
   macOS `SOCK_DGRAM`+`IPPROTO_ICMP` / Windows raw), which lives behind a thin
   `HostIcmpEcho` trait with per-OS impls. Nothing else forks by platform.
3. **End-to-end TLS is preserved, no MITM.** `smoltcp` terminates the *TCP transport*
   and byte-splices the encrypted stream to the host socket; the TLS handshake stays
   end-to-end between guest and real server. The host relays ciphertext only. The
   existing CI guard that bans TLS/transform symbols from the data-plane files stays.
4. **Secret egress is host-originated vsock substitution, never a NAT/terminator.**
   Per the substitution mechanism the codebase already implements: the guest sends a
   request carrying an opaque placeholder over vsock; the host resolves the
   placeholder to the real secret, verifies the destination is bound to that secret,
   **originates the real egress itself**, and returns the response over vsock. The raw
   secret only ever exists in the one confined host process; it never lands in the
   microVM. This is *not* the transparent nft-REDIRECT terminator — no host network
   device the guest routes through.
5. **All egress is one uniform host-side model:** the `smoltcp` forwarder for direct /
   non-secret flows (guest does its own end-to-end TLS) and the vsock substitution
   endpoint for secret flows (host originates). Both unprivileged, both vsock-only,
   both audited, no NAT.

## Performance

Measured, not asserted. Benchmark on a Linux box (Intel i7-7700 @ 3.6 GHz; `smoltcp`
0.13.1 over a real 1500-MTU TUN driven by a kernel-TCP sender), 2 GB bulk transfer +
20k×64 B ping-pong.

Single flow, single core:

| path | throughput (1 flow) | ping-pong RPS | p50 / p99 |
|---|---|---|---|
| kernel TCP (loopback ceiling*) | ~9.8 GB/s | 71.9k | 11 µs / 45 µs |
| smoltcp / TUN, 64 KiB buffer | 0.81 GB/s (6.5 Gbit/s) | 65.7k | 13 µs / 52 µs |
| smoltcp / TUN, 256 KiB buffer | 0.91 GB/s (7.3 Gbit/s) | — | — |

Eight concurrent flows through **one** worker (the builder-egress shape — parallel nix
fetches all funnel through a single per-VM worker):

| path | aggregate throughput (8 flows) |
|---|---|
| kernel TCP (loopback, multi-core*) | ~95 Gbit/s |
| smoltcp / TUN, 64 KiB, one worker thread | 6.4 Gbit/s |
| smoltcp / TUN, 256 KiB, one worker thread | 6.9 Gbit/s |

*Loopback ceilings are inflated by large-segment offload (64 KB segments, no 1500-MTU
segmentation) and, for the multi-core row, by using every core; they bound, they do
not represent a real 1500-MTU kernel-NAT path. The decisive figures are the
**absolute** smoltcp numbers.

Conclusion: the userspace-TCP tax is **negligible for every consumer at this tier**.
Single-flow, smoltcp delivers 6.5–7.3 Gbit/s and lands within ~9 % of kernel RPS on
request/response latency (+2 µs p50). Under eight concurrent flows the single-threaded
worker holds a **steady ~6.5 Gbit/s aggregate** — it does not degrade or thrash, it
simply caps at one core, and eight flows share that ceiling. That cap is the number
that matters for the highest-demand consumer, the builder VM's parallel nix fetches:
those are internet-bound (10s–100s of Mbps per connection), so aggregate builder egress
sits far below the ~6.5 Gbit/s single-worker ceiling. dev/agent workloads clear it by
a wider margin still — all of this on 2017-era silicon. A 256 KiB buffer buys ~12 %
over the 64 KiB default.

The one scenario where the single-worker cap bites is sustained aggregate egress above
~6.5 Gbit/s per VM — e.g. a LAN-local binary cache at 10–25 GbE feeding a massive
parallel closure, not a realistic internet-bound builder or workload. If that ever
materializes, the escape hatch is **option C** (host
kernel sockets via a socket-level vsock proxy / TSI): faster, still
unprivileged/uniform/no-NAT, and a tighter fit for the invariant. Two constraints on
that future path: it needs guest-side socket interception (feasible in the in-house
HVF VMM and already present in libkrun; a shim elsewhere), and it **must be the
egress-enforcement gate** — every `connect` policy-checked and audited host-side. The
earlier libkrun TSI mode was removed precisely because it *bypassed* the egress
gateway; a socket proxy that *is* the gate is the opposite and is acceptable. Build it
only if the numbers force it.

## Consequences

- Delete `crates/mvm-hostd/src/host_tun.rs`, its nft NAT setup/teardown, and the
  `host_tun_nat_live` witness; generalize `smoltcp_egress`; add `HostIcmpEcho`.
- **Drops the `CAP_NET_ADMIN` requirement on Linux** — workload egress becomes
  uniformly unprivileged.
- Correct the **stale claim-12/13 prose in ADR-002**: it still describes a removed
  signed-credential broker (`host.secrets.v1`); the real, shipped mechanism is
  host-side egress substitution. Reconcile the numbered claims with the substitution
  path.
- The implementation **must rebase onto the active tunnel-hardening work**, not open a
  competing branch. The primary base is `feat/plan-236-2a-l3-forward`, which is
  actively expanding `network_tunnel.rs` / `network_tunnel_spawn.rs` / `net_l3.rs`
  (adds a no-guest-NIC claim + a legacy-workload-transport gate) — the exact
  orchestration this unification reworks. It composes with that work (it locks in
  vsock-only/no-NIC; this ADR unifies the host forwarder behind it), but the
  unification lands only after it settles. The substitution/vsock edges also overlap
  `fix/host-http-forward-proxy`, `feat/guest-vsock-session-refactor`, and the
  vsock-egress-cutover line.

## Out of scope (for this ADR)

- The option-C kernel-socket vsock proxy / TSI implementation (documented escape hatch
  only, not built here).
- IPv6 forwarding and per-flow credit backpressure (tracked separately).
- The live booted-workload egress witness (needs a Linux + libkrun host; the host
  TUN/NAT *mechanism* was live-proven on Linux 2026-07-11, but that path is being
  retired — a `smoltcp` live witness replaces it).
