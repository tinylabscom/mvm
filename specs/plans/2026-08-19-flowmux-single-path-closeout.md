# FlowMux single-path closeout

Backing: preview
Validation: none

**Issue:** [#2751](https://github.com/tinylabscom/mvm/issues/2751)
**Predecessors:** Plan 316, ADR-042, and the FlowMux transport cutover in
`2026-08-15-flowmux-single-transport-cutover.md`

## Status

PR #2741 merged on 2026-08-19. The guest and host can now complete the
host-first FlowMux handshake on relayed-vsock backends as well as direct-vsock
backends. The outbound cutover is complete: guest TCP, UDP, DNS, mediated ICMP,
and typed HTTP all use the authenticated protocol on `NetworkFlow`.

Workstreams W1–W4 are now implemented. Admitted `NetworkLimits` are shared
per-VM endpoint budgets; typed HTTP and connectors use bounded endpoint-owned
streaming transforms; and signed TCP/UDP/HTTP/TLS ingress binds only admitted
listeners, crosses the authenticated FlowMux session, and terminates at the
declared guest-loopback target. The performance harness, rejected
`raw_ip_stack` removal, frozen L3 deletion, permanent single-path gates, and
final performance/backend matrix remain. This plan owns that remainder. The
closed Plan 316 phase issues are historical; issue #2751 is the active
umbrella.

## Outcome

An admitted workload has either no network capability or one authenticated
FlowMux endpoint. Every guest-visible TCP, UDP, DNS, typed HTTP/connector, and
declared-ingress flow shares the endpoint's plan projection, per-VM resource
budget, identity, audit sink, and lifecycle. No production L3/raw-packet
implementation, compatibility flag, alternate socket owner, or second guest
protocol remains.

## Ordering and pull-request boundaries

Workstreams run in order unless a dependency note explicitly permits overlap.
Each implementation pull request updates this plan, its delivery record, and
`specs/REFACTOR-STATUS.md` only after its tests are green.

### W0 — Re-establish one truthful tracker

- [x] Make issue #2751 the active umbrella for every remaining FlowMux item.
- [x] Replace Plan 316's pre-cutover status with the current source inventory
      and point its remaining phases here.
- [x] Reconcile the sprint delivery archive and refactor rollup with the same
      status and dependency order.

### W1 — Enforce admitted limits as shared per-VM budgets

- [x] Thread signed `NetworkLimits` from the admitted plan through
      `EndpointSpawnRequest`, `EndpointConfig`, and endpoint startup without a
      fallback to `RegistryLimits::default()` on an admitted workload.
- [x] Introduce one per-VM budget owner shared by all authenticated sessions;
      session churn or multiple guest processes must not multiply stream,
      association, byte-credit, listener, peer, or rate ceilings.
- [x] Bound concurrent authenticated sessions and ensure every reservation is
      released on refusal, cancellation, EOF, and endpoint teardown.
- [x] Add serde/default/validation tests, cross-session exhaustion tests,
      reconnect tests, and endpoint subprocess coverage for malformed or
      missing limits.

### W2 — Add the performance harness before deleting the baseline path

- [ ] Add `xtask network-perf` with machine-readable reports for opaque TCP,
      UDP, DNS, and transformed HTTP latency, throughput, CPU, copies where
      measurable, and peak RSS.
- [ ] Record host-, backend-, storage-, build-, and sample-labelled legacy L3
      and current FlowMux baselines under `specs/benchmarks/network/`.
- [ ] Make comparison thresholds explicit: opaque latency at most 5% slower,
      throughput at least 95%, RSS growth at most 10%, and transformed HTTP
      latency at most 10% slower unless an owner-approved measured exception is
      recorded here.
- [ ] Keep the harness hermetic by default and isolate live KVM/HVF/libkrun
      runners behind explicit environment checks.

### W3 — Make typed transformations bounded and endpoint-owned

- [x] Replace whole-message `WireRequest`/`WireResponse` buffering with bounded
      incremental head/body handling from `OpenHttp` through completion.
- [x] Preserve transformation matches across frame boundaries with a bounded
      overlap window, enforce head/body/idle/credit ceilings, and zeroize
      secret-bearing buffers on completion and cancellation.
- [x] Apply destination-bound substitution only after final DNS and redirect
      admission; redact each response chunk before it crosses to the guest.
- [x] Route typed connector network execution through the endpoint. Brokers
      retain binding authorization but do not connect, resolve, or create an
      independent HTTP client for workload traffic.
- [x] Add positive, refusal, split-token, redirect, oversized-head/body,
      timeout, cancellation, audit-leak, and long-stream tests.

### W4 — Implement declared ingress on FlowMux

- [x] Replace `L3IngressMapping` with a transport-neutral signed-plan/IR type
      carrying mapping ID, protocol, exact host bind, guest loopback target,
      and transformation class; update Rust, Python, TypeScript, schemas, and
      fixtures together.
- [x] Bind only admitted listeners before endpoint readiness. Refuse duplicate
      or unavailable binds, undeclared wildcards, unsupported protocols, and
      unavailable transformation material.
- [x] Implement TCP ingress with even stream IDs and the existing
      `InboundOpen`/`InboundReady`/`InboundRefused` contract before relaying
      bytes to a declared guest-loopback target.
- [x] Implement UDP ingress with bounded per-mapping peer tables; replies may
      target only a peer that previously sent to that mapping.
- [x] Keep TLS keys and transformation material host-side, support explicitly
      opaque TCP without transformation, and delete the unused second ingress
      broker/handler model.
- [x] Add exact/wildcard bind, undeclared port, TCP/UDP delivery, guest refusal,
      exhaustion, TLS-key non-disclosure, streaming transform, audit, and
      teardown tests plus BDD coverage.

### W5 — Remove the rejected public compatibility surface

- [ ] Remove `raw_ip_stack` and `NetworkMode::L3Vsock` from the Rust IR,
      Python and TypeScript SDKs, generated schemas, fixtures, examples, CLI
      help, and public documentation.
- [ ] Preserve an explicit migration error for stale serialized input at the
      outer compatibility boundary without representing the rejected mode in
      admitted domain types.
- [ ] Document the supported loopback proxy, SOCKS5h/UDP, controlled DNS,
      mediated ping, and typed connector surfaces, and the fail-closed result
      for applications that bypass them.
- [ ] Add schema parity, stale-input refusal, supported-adapter, typed-
      connector, and non-cooperative direct-socket BDD tests.

### W6 — Delete the superseded L3 implementation

- [ ] Delete contract and policy L3 modules, L3-only channel identities,
      leases, fuzz targets, synthesis/admission branches, and live product
      scenarios.
- [ ] Delete `mvm-net` and `mvm-agentd` L3 modules, `mvm-net-agent`, guest TUN
      setup/cmdline/runtime-overlay code, and the workload-kernel TUN
      requirement where no non-network consumer remains.
- [ ] Delete hostd netd modules and binary, host TUN/netns/nftables and smoltcp
      datapaths, privileged L3 tests, VMM spawn/reap/teardown hooks, and
      control/data service sockets.
- [ ] Remove resulting dependencies and packaging/Nix/CI/kernel residue; update
      lockfiles and closure budgets.
- [ ] Rewrite protocol-independent security scenarios against FlowMux and
      delete scenarios for intentionally unsupported raw networking.
- [ ] Run dependency, advisory, license, duplicate-major, and closure-budget
      checks with no L3-only binary or dependency left.

### W7 — Replace migration ratchets with permanent invariants

- [ ] Add `check-single-network-path`: exactly one production endpoint binary
      and spawn implementation, every networked backend binds `NetworkFlow`,
      and forbidden packet/NIC/gateway symbols occur only in historical specs.
- [ ] Add a socket-owner gate permitting workload outbound connects and
      ingress listener binds only inside the endpoint, with narrow enumerated
      exemptions for unrelated host infrastructure.
- [ ] Test each gate with forbidden synthetic fixtures and its exact allowed
      cases, then retire temporary L3 freeze/uniform-vsock gates that no longer
      describe the tree.
- [ ] Add a signed-plan projection test showing TCP, UDP, DNS, typed connectors,
      and ingress share one policy object, budget owner, identity, and audit
      sink.

### W8 — Run the final evidence matrix and close the umbrella

- [ ] Run `xtask network-perf` against the recorded baseline and record the
      final report and any approved exception.
- [ ] Live-witness Firecracker on Linux/KVM, HVF on macOS, and libkrun on every
      supported host OS. Cover deny-all, TCP, UDP, DNS, typed substitution,
      ingress, endpoint crash, no guest NIC, and no L3 services.
- [ ] Run workspace test/check/doc-test/formatting on the macOS host; run Linux
      all-target/all-feature Clippy, gated tests, Nix checks, and live KVM work
      inside the project builder VM.
- [ ] Run BDD, dependency, supply-chain, schema, product, claim, and permanent
      networking gates.
- [ ] Update ADR/claim witnesses, public networking docs, release notes, this
      plan, the sprint delivery archive, and the refactor rollup; close #2751
      only after every acceptance item is backed by recorded output.

## Definition of done

- [ ] The production source tree contains no L3/raw-packet workload networking
      code, public raw-network mode, or second ingress/egress socket owner.
- [ ] Every admitted network flow shares one endpoint, authenticated protocol,
      signed-plan projection, per-VM budget owner, and payload-free audit sink.
- [ ] Typed transformation and declared ingress are bounded, streaming, and
      covered across positive, negative, cancellation, and boundary cases.
- [ ] Permanent gates reject a second path or socket owner.
- [ ] Performance budgets and the required cross-backend live matrix pass, and
      all repository validation is green.

## Non-goals

- No guest NIC, host bridge, TAP, slirp, passt, vpnkit, or raw-packet fallback.
- No universal TLS interception CA or attempt to bypass certificate pinning,
  QUIC, or ECH.
- No weakening of ptrace, seccomp, capability, Landlock, read-only-root, or
  secret-handling boundaries for application compatibility.
- No alternate production endpoint retained as a development escape hatch.
