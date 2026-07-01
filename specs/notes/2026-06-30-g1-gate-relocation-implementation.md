# G1 gate-relocation — implementation notes (Plan 214 S1b)

Companion to the "S1b — G1 gate-relocation design (implementation-ready)" section
of `specs/plans/214-clean-replacement-architecture.md`. Records the facts verified
in code and the one routing decision the design left implicit, so the additive
increments and the live-verify are unambiguous.

## Verified facts

- **Two guest egress protocols share `EGRESS_PORT` (5253).**
  - Raw TCP egress: `mvm-guest-helpers::egress_client` (a loopback SOCKS5 proxy).
    First frame on the vsock stream is `"host:port\n"`, then a raw byte pump. The
    host side is `vsock_egress_bridge::egress_proxy::EgressProxy` (gate + TCP dial
    + splice), run **in the guest run loop**.
  - WireRequest substitution: `mvm-guest::substitution_client`. A framed JSON
    `WireRequest` (4-byte BE length + JSON), one request/response per connection.
    The host side is `substitution_bridge::SubstitutionBridge` (peek first frame →
    gate on the URL → relay to the per-VM `mvm-substitution-endpoint`), also **in
    the run loop**.
- **The run loop picks the host handler by config, not by sniffing bytes.**
  `vmm::vsock` routes `EGRESS_PORT` to `SubstitutionBridge` iff a substitution
  endpoint socket is configured, else to `EgressProxy`. A given VM therefore uses
  exactly one protocol: WireRequest when its admitted plan carries egress secrets
  (endpoint spawned), raw otherwise.
- **The claim-10 gate is `vsock_egress_bridge::egress_gate::EgressGate`** — the one
  shared decision (`decide_request("host:port")`), default-deny, SSH/mandatory-deny
  enforced. Both in-loop paths call it today.
- **The endpoint already supports a plain (no-secret) forward.** `SubstitutionService::process`
  (substitution_proxy.rs) reads a `WireRequest`, computes `destination_host(url)`,
  runs redaction + `prepare_request` (substitution; refuses on a placeholder whose
  binding disallows the destination — claim 12), then `forwarder.forward` (hardened
  reqwest). A request with no placeholder forwards as-is. So the destination is
  known at one point (right after the `destination` binding) — the exact insertion
  point for a claim-10 gate, before any forward.
- **`mvm-hostd` already depends on `mvm-backend`** (`EndpointTransport` is
  re-exported from it), so the endpoint can reuse `EgressGate` directly — no new
  crate edge, no reimplementation.
- **The live claim-10 witness today is the raw echo path.** `examples/hvf-backend-egress`
  boots a no-secret allow-list VM; the guest raw-egresses to a discovered LAN
  destination via `EgressProxy`. Commit `5b7b4325`: claim-10 live-proven on HVF via
  this path; claims 12/13 unit-tested + substrate-live-proven.

## Decision: the endpoint is the unified bridge for BOTH protocols

The design says the endpoint "refuses a non-admitted destination before
**connecting/substituting**" and the run loop relays "**all** egress, not just
bound-secret flows." Raw TCP egress is not dead (it is how a workload does
arbitrary non-secret TCP), so the endpoint must gate + carry it too — not just the
WireRequest path. The end state:

- Run loop: pure relay of `EGRESS_PORT` ↔ endpoint UDS. No gate. No protocol
  knowledge.
- Endpoint (`mvm-substitution-endpoint`) = the one `vsock_egress_bridge` process:
  gates every destination (claim 10), then either substitutes+forwards a
  WireRequest (claims 12/13) or connects+splices a raw stream.

**Protocol routing at the endpoint.** The VM's protocol is fixed at config time
(secrets ⇒ WireRequest, else raw), exactly as the run loop already decides. The
endpoint learns the same bit from its config rather than sniffing untrusted guest
bytes (sniffing a length-prefix vs an ASCII `host:port\n` is fragile and a parser
attack surface). So `EndpointConfig` carries an egress mode alongside the policy.

## Additive migration (no flag day) — increment map

1. **P1.1 — endpoint WireRequest gate.** `EndpointConfig.network_policy:
   Option<NetworkPolicy>` (`#[serde(default)]`). `None` ⇒ endpoint does not gate
   (legacy: the run loop still gates) — backward compatible. `Some(policy)` ⇒
   `assemble` resolves DNS pins + builds an `EgressGate`; `process` refuses a
   non-admitted destination before forward. Unit-tested.
2. **P1.2 — endpoint raw egress.** Endpoint gains a raw-egress accept path (first
   line `host:port` → gate → connect → `copy_bidirectional`), selected by an
   `EndpointConfig` egress mode. Absorbs `EgressProxy`.
3. **P1.3 — run-loop relay mode.** `HostChannels` gains an egress-relay UDS; when
   set, `EGRESS_PORT` relays to it with no in-loop gate. Selected on config
   (relay socket present) — legacy in-loop gate path kept alongside.
4. **P1.4 — wire `InHouseDriver::boot` + `WorkloadRunner`** to the relay path
   (endpoint spawned with the resolved policy; its UDS threaded into the
   `EGRESS_PORT` `VsockPort.host_uds`). Prove vs `MockDriver`.
5. **P1.5 — live-verify** `examples/hvf-backend-egress` through relay+endpoint on
   macOS-26: admitted reachable AND non-admitted refused. Only then delete the
   legacy in-loop gate + `network_policy` from the supervisor config.

**Invariant:** the relay has no upstream path except through the gating endpoint,
so there is no window where guest egress reaches the network ungated. The live
verdict confirms it adversarially (a non-admitted destination stays blocked).
