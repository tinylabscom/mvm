# ADR-032: Admitted egress must complete; DNS becomes a first-class part of the egress seam

## Status

Accepted

## Context

The vsock-only auditable data plane is an invariant (ADR-001; the
`vsock-only-auditable-data-plane` posture): the guest has no routable NIC, every
outbound flow crosses the host over vsock, the host mediates and audits it, and
egress is admitted only by the workload's signed `NetworkPolicy` allow-list
(claim 10 — no untrusted workload reaches the network unless explicitly
admitted).

Two live defects break that story for admitted workloads on the vsock-proxy
backends (libkrun / HVF):

1. **Admitted egress times out.** With `--allow-host example.com`, `wget
   https://example.com` hangs and exits 124, even though the destination is
   admitted. A *disallowed* destination is refused fast (a synthesized
   `403`), so enforcement looks instant while an admitted connect never
   completes.
2. **The guest has no DNS resolver.** `/etc/resolv.conf` is empty. Any app that
   resolves names itself (`ping`, and many TCP clients) fails with `bad
   address`; only proxy-aware apps work, because the host resolves the name the
   proxy is handed. DNS today is *implicit* — it only happens as a side effect
   of an admitted CONNECT.

Both defects live on the same host egress path, so this ADR addresses them
together. Making the vsock proxy the sole egress plane (recent work that dropped
the parallel L3 tunnel on host-vsock-proxy backends and fixed the guest
egress-client spawn for OCI images) is what *exposed* defect 1 — the L3 tunnel
had masked it.

## Decision

### Part 1 — Make admitted egress actually connect

**Root cause** (two compounding defects):

- **Optimistic CONNECT handshake.** The guest egress client
  (`crates/mvm-agentd/src/egress_client.rs`, `serve_http_connect` ~332-342,
  `serve_socks` ~320-330) writes `HTTP/1.1 200 Connection established` (or SOCKS
  `REP_SUCCESS`) *before* the host confirms the outbound connect — it only opens
  the vsock and writes the target line, then replies OK and splices. A failed
  admitted connect therefore cannot surface as an error: the client has already
  been told the tunnel is up, sends its TLS ClientHello into a tunnel that never
  delivers a response, and blocks until timeout.
- **Single-IP connect, no fallback.** Pins collect *all* resolved addresses
  (A + AAAA) via `to_socket_addrs()`
  (`crates/mvm-core/src/policy/dns_pin.rs`, `resolve_network_policy_pins`
  ~47-67), but `EgressGate::decide_hostname_request`
  (`crates/mvm-runtime/src/vsock_egress_bridge/egress_gate.rs` ~122-151) returns
  only the *first* admitted IP, and `raw_egress::splice`
  (`crates/mvm-hostd/src/supervisor/raw_egress.rs` ~143-155) does a single
  `TcpStream::connect` with no iteration. On a dual-stack host whose first
  pinned IP (typically IPv6) has no working egress — the common dev-Mac case —
  the connect stalls the full 30s timeout.
- **Why enforcement stays fast:** a disallowed `http://` request is classified
  `HttpForward` and answered inline by a *different* host component
  (`crates/mvm-hostd/src/supervisor/http_forward.rs`), which synthesizes the
  `403` with no outbound socket. The admitted-CONNECT path is the raw TCP splice
  above. That asymmetry — plus the optimistic `200` — is exactly why enforcement
  looks instant while an admitted connect hangs. Byte-pumping is correct in both
  directions (the `403` round-trip proves it), and the host endpoint is spawned
  and policy is threaded (the `403` proves the pin exists).

**Decision 1a — honest CONNECT handshake.** Add a connect-result ack to the
raw-egress protocol: after `TcpStream::connect` returns on the host, send a
one-line `OK` / `FAIL` back to the guest before splicing; the guest relays `200
Connection established` (or SOCKS `REP_SUCCESS`) only on `OK`, and otherwise
returns `502` / `REP_GENERAL_FAILURE`. A failed admitted connect becomes a fast,
correct client error instead of a hang.

**Decision 1b — try every admitted pinned IP.**
`EgressGate::decide_hostname_request` returns all admitted IPs (not just the
first); `raw_egress::splice` iterates them happy-eyeballs style — prefer IPv4, a
short per-IP connect budget, first success wins. An unreachable AAAA pin no
longer stalls the request. 1b is what makes an admitted connection actually
*succeed* on a dual-stack host; 1a makes any residual failure fail fast instead
of hanging.

### Part 2 — DNS as a first-class, policy-gated, audited part of the egress seam

**Principle:** "can this workload reach destination D?" is *one* policy
decision, applied to name resolution and to connection alike. A resolver bolted
on beside the seam would be a second door with weaker policy — the classic way
allow-listed egress is bypassed. So DNS is folded into the seam that already
owns the gate, not added next to it.

**Architecture.**

- *Guest:* `mvm-netd` gains a DNS stub listener on `127.0.0.1:53` (UDP + TCP);
  the guest's `/etc/resolv.conf` becomes `nameserver 127.0.0.1`. Queries are
  forwarded over the *same* vsock plane already used for the proxy — no new
  transport, no NIC.
- *Host:* the egress endpoint gains a DNS handler that, per query: checks the
  QNAME against the workload's admitted `NetworkPolicy` allow-list, resolves
  upstream **only if admitted**, validates the answer IPs against IP-egress
  policy, audits the query, and returns.

**The five guards** (each closes one attack-surface item):

1. **No covert exfil / DNS tunneling.** Resolve only allow-listed names;
   everything else → `REFUSED`, no upstream lookup. Chain-audit every query
   (qname, qtype, verdict, resolved IPs) so DNS is not a claim-10 blind spot.
   (Wildcard / parent-domain allow-listing widens the channel to subdomains of
   an admitted domain; it stays audited and rate-limited, and exact-name
   allow-listing is preferred.)
2. **No SSRF / DNS rebinding.** Reject A/AAAA answers in RFC1918, link-local,
   loopback, ULA, and the metadata address `169.254.169.254` unless explicitly
   allowed; re-check the IP at connect time (Part 1b already dials by admitted
   IP), so a short-TTL rebind to a private IP is caught before dialing.
3. **Parser safety across the vsock trust boundary.** A minimal, in-house
   `forbid(unsafe)` DNS codec (question section + A/AAAA answers only — the wire
   format we need is small), bounded message size, fail-closed on malformed,
   plus a `cargo-fuzz` target sibling to the existing vsock-framing fuzzers
   (claim 5). We do **not** pull `hickory-proto`: the surface we need is tiny
   and a large parser dep works against the limit-dependencies norm (ADR-002).
4. **Resource bounds.** Per-workload token-bucket on queries, a concurrency cap
   on in-flight upstream lookups, and a response-size bound.
5. **No confused deputy.** The handler is scoped to the *workload's* admitted
   policy (threaded from the signed `ExecutionPlan`, exactly like TCP egress),
   never a host-global resolver.

The result: one `NetworkPolicy` drives both the DNS name gate and the TCP
connect gate; one host component enforces both; one audit stream records both.

### Test & fuzz matrix

- **Unit (hermetic, no VM):** the name-gate + IP-policy filter; the
  pinned-IP happy-eyeballs selection; the CONNECT ack state machine
  (`OK` → `200`, `FAIL` → `502`).
- **`@live` BDD** (`MVM_BDD_LIVE=1`, the lane added in this branch): an admitted
  host is reachable (Part 1); an admitted *name* resolves and connects; a
  non-admitted name is `REFUSED`; a name resolving to an internal/metadata IP is
  blocked; the audit chain carries the query entries.
- **Fuzz:** the DNS codec.

### Sequencing

1. **Part 1** (data-path fix) first — independently shippable, unblocks
   everything, and makes the `@live` admitted-reachability scenario pass.
2. **Part 2** (DNS resolver) rides the fixed path.

## Consequences

**Positive.** Admitted egress completes (fast failure when it can't); workloads
that resolve names work without a NIC; DNS becomes auditable, so claim 10 stays
honest with DNS in the picture; enforcement *and* reachability are both covered
by `@live` tests.

**Trade-offs / non-goals.** This does **not** make `ping` / ICMP work, and does
**not** give non-proxy-aware raw TCP a transparent path — that is the L3-tunnel
"full transparency" option, explicitly out of scope here. Wildcard / parent-domain
allow-listing remains a wider (audited) DNS channel than exact-name matching. A
workload that resolves a name it is not admitted to reach gets `REFUSED` by
design.

**Alternatives rejected.**
- *A plain forwarding resolver* (forward all guest DNS to the host): reopens the
  covert-egress hole — DNS would bypass the TCP allow-list. Rejected.
- *Full L3 transparency* (guest TUN + L3 tunnel over vsock): makes arbitrary
  TCP/UDP and `ping` work transparently, but is a much larger change and is the
  currently-unstable area. Deferred; not this ADR.
- *UX-only error* (replace `bad address` with a helpful message, no DNS
  behavior change): doesn't fix the actual DNS need. Rejected.

## References

- ADR-001 — microVM security posture, threat model, claim 10.
- ADR-023 — secrets subsystem / egress substitution (the other half of the
  host-mediated egress boundary).
- The admitted-egress-timeout root cause was confirmed by end-to-end static
  analysis of the guest→vsock→host egress path on this branch; the file
  references above are the anchor points a plan will change.
