---
title: "ADR-004: hypervisor-level egress policy with domain-pinning"
status: Proposed (v1 = L3 only; L7 + DNS-pinning deferred)
date: 2026-04-30
related: ADR-002 (microVM security posture); ADR-003 (local MCP server); plan 32 (MCP + LLM-agent adoption); plan 25 (microVM hardening)
---

## Status

Proposed. v1 implementation tracked in
`specs/plans/32-mcp-agent-adoption.md` Proposal D. ADR-002 named
hypervisor-level egress policy as an explicit non-goal for Sprint 42's
hardening; this ADR moves it on-roadmap for the next sprint with a
deliberately smaller v1 scope than the full three-layer model.

## Context

When mvm runs an LLM agent (or any other workload that the user wants
to constrain), the hypervisor sits in the only place that can enforce
egress destinations — between the guest's TAP interface and the
host's wider network. The guest agent inside the microVM is untrusted
in this threat model; an agent that decides to exfiltrate to
`evil.example.com` cannot be stopped by the guest's own firewall.

mvm has had `NetworkPolicy` in `mvm-core` since W7, and `mvmctl up
--network-preset` / `--network-allow` since the same sprint. Those
flags wire up an iptables-based L3 allowlist on the bridge. What was
missing:

1. A clear ADR specifying what egress enforcement does and does not
   guarantee.
2. A curated preset for the LLM-agent use case (plan 32 / Proposal B
   wants `api.anthropic.com` + GitHub + nothing else).
3. A roadmap for the layers above L3 — namely L7 SNI/Host-header
   filtering and DNS-answer pinning — which are needed to defeat
   DNS-rotation attacks and SNI-hopping that pure L3 can't see.

This ADR captures both decisions and limits.

## Threat model (additive over ADR-002)

The adversary is **a malicious guest workload** (per ADR-002 §1):
code running inside a microVM trying to talk to a host the operator
did not authorize. Specifically:

1. The guest may attempt direct TCP/UDP connections to arbitrary
   IPs.
2. The guest may abuse DNS — query a benign hostname, observe the
   answer, then connect to a different IP than the one a stub
   resolver would have authorized.
3. The guest may reuse a TLS connection to a permitted SNI by
   sending a different `Host` header (HTTP/1.1 vhosting).
4. The guest may attempt SNI to a permitted name then perform
   ALPN-protocol smuggling.

A **malicious host** is out of scope (per ADR-002). A **malicious
DNS resolver upstream of the host** is also out of scope.

## The three-layer model

A complete egress enforcer for the LLM-agent use case has three
tiers, each catching a class of attack the lower one can't:

### L3 — iptables allowlist (v1 — shipped)

Already in `mvm-runtime/src/vm/network.rs::apply_network_policy`.
At TAP attach time, install `FORWARD` rules in the bridge chain that:

- `DROP` all packets from the guest IP by default.
- Allow ESTABLISHED/RELATED return traffic.
- Allow DNS (UDP+TCP :53) so name resolution works.
- Allow each `<host>:<port>` in the policy by IP — iptables resolves
  the host once, at rule-install time.

**Catches:** raw IP-targeted exfil to non-allowlisted hosts.
**Doesn't catch:** DNS rotation (CDN-fronted hosts where the
authorized answer changes between rule-install and connect),
SNI-hopping (TLS to authorized IP, different SNI), Host-header
abuse.

### L7 — HTTPS proxy with SNI/Host filtering (deferred)

Egress proxy on the host bound to a private CIDR the guest can reach.
Guest gets `HTTPS_PROXY` / `HTTP_PROXY` env vars and the proxy's CA
cert in `/etc/ssl/certs/mvm-egress.crt`. Proxy enforces the allowlist
by SNI for HTTPS (CONNECT) and Host header for HTTP. CONNECT to a
disallowed domain returns 403.

**Implementation cost:** wraps `mitmdump` from nixpkgs (~50 LoC of
process supervision in mvm-runtime); needs CA injection at boot
inside the rootfs; needs per-VM port allocation; needs cleanup on
crash.

**Why deferred:** mitmdump is a substantial runtime dep (Python +
mitmproxy + cryptography), and the dev image's closure grows by
~80 MiB. We want the L3 tier shipped and adopted before pulling in
that closure. Operator opt-in via a separate command flag once the
implementation lands.

### L7+ — DNS-answer pinning (deferred)

Stub resolver on the host (`dnsmasq` configured with
`server=/<allowlisted-domain>/<upstream>` and a 0-TTL pin per
recursion result). Guest DNS goes through the stub; the stub
publishes resolved A records into the iptables allowlist for the
TTL of the answer. Catches DNS rotation. **Why deferred:** dnsmasq
is small but the IP-pin/iptables-update plumbing has corner cases
(IPv6, A-vs-CNAME chains, NX caching) that need careful design.

## Decisions

1. **v1 ships L3 only.** The infrastructure is already there
   (`NetworkPolicy::AllowList` + `iptables_script`); v1's only
   addition is the new `NetworkPreset::Agent` curated bundle for
   plan 32 / Proposal B. Operators who need L7 wait for the
   follow-up.

2. **`NetworkPreset::Agent` is the LLM-agent default.** It contains:
   - `api.anthropic.com:443`
   - `api.openai.com:443`
   - `github.com:443` + `:22`
   - `api.github.com:443`

   Strictly smaller than `dev` (no npm/PyPI/crates.io). Documented
   in `nix/images/examples/llm-agent/README.md` as the recommended
   `mvmctl up --network-preset agent`.

3. **No L7 today; ADR documents it.** When L7 lands, it composes
   on top of L3 (defense in depth, per ADR-002 §"Decisions" 2).
   Operator chooses the layer per `--network-mode` (future flag),
   not by separate commands.

4. **DNS pinning is paired with L7.** Doing DNS pinning without
   the L7 proxy is a partial solution that defeats CDN-fronted
   destinations; doing L7 without DNS pinning leaves SNI-equal-IP
   gaps. Land them together.

5. **Cross-platform discipline (cross-cutting "D: iptables/proxy
   dispatch lives in Lima on macOS").** L3 already follows this:
   `apply_network_policy` calls `run_in_vm_visible` which dispatches
   through `shell::run_in_vm` on macOS and runs natively on Linux.
   L7 + DNS-pinning when added must follow the same pattern.

6. **Per-template default policy is an ergonomic follow-up.**
   Today policies are passed per-invocation. Baking a default into
   `TemplateSpec` so `claude-code-vm` ships with `agent` preset
   automatically is a separate (small) refactor, tracked but not
   blocking this ADR.

## Consequences

### Positive

- Operators get an explicit ADR explaining what egress filtering
  does and doesn't catch, instead of inferring from the existing
  CLI flags.
- The `agent` preset gives the LLM-agent showcase (Proposal B) a
  one-flag answer to "how do I lock this down to Anthropic?":
  `mvmctl up --network-preset agent`.
- L3 enforcement is real and ships today. DNS-rotation gaps are
  documented, not pretended-away.

### Negative / accepted costs

- L3 by itself does not stop a determined adversary that controls
  the resolver path (or a CDN-fronted destination). This is
  documented honestly. Operators wanting stronger guarantees wait
  for L7 + DNS-pinning.
- Adding `NetworkPreset::Agent` means a new variant downstream
  consumers must match on. Existing match-arms in the workspace
  are exhaustive (no wildcards) so the compiler will catch any
  miss.

### Explicit non-goals

- **Application-layer protocol filtering.** Beyond SNI + Host, we
  don't do payload inspection.
- **Egress for IPv6.** Today's `iptables` script is IPv4-only.
  IPv6 follow-up tracked.
- **Multi-tenant fairness.** Per-tenant egress quotas are mvmd's
  domain (plan 33).

## Reversal cost

- v1 changes (the `Agent` preset variant + tests + README) are a
  one-line per-call-site removal — trivially reversible.
- L7 + DNS pinning would, when implemented, cost a runtime-dep
  rollback (mitmdump + dnsmasq removal) plus an `ops/egress-proxy/`
  cleanup. Documented as part of those follow-up plans.

## References

- Plan: `specs/plans/32-mcp-agent-adoption.md` Proposal D
- Related ADRs: ADR-002 (microVM security posture), ADR-003 (local
  MCP server)
- Existing infrastructure: `mvm-core::policy::network_policy`,
  `mvm-runtime::vm::network::{apply,cleanup}_network_policy`
- L7 inspiration: archie-judd/agent-sandbox.nix's domain allowlist
  proxy pattern
