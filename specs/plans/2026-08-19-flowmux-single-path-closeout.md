# FlowMux single-path closeout

Backing: shipped-source
Validation: check-single-network-path

**Issue:** [#2751](https://github.com/tinylabscom/mvm/issues/2751)
**Predecessors:** Plan 316, ADR-042, and the FlowMux transport cutover in
`2026-08-15-flowmux-single-transport-cutover.md`

## Status

PR #2741 merged on 2026-08-19. The guest and host can now complete the
host-first FlowMux handshake on relayed-vsock backends as well as direct-vsock
backends. The outbound cutover is complete: guest TCP, UDP, DNS, mediated ICMP,
and typed HTTP all use the authenticated protocol on `NetworkFlow`.

Workstreams W1–W7 are now implemented in the dependency-ordered PR stack.
Admitted `NetworkLimits` are shared
per-VM endpoint budgets; typed HTTP and connectors use bounded endpoint-owned
streaming transforms; and signed TCP/UDP/HTTP/TLS ingress binds only admitted
listeners, crosses the authenticated FlowMux session, and terminates at the
declared guest-loopback target. The performance harness and labelled legacy
baselines are recorded, and the rejected `raw_ip_stack`/`L3Vsock` public
surface is gone with explicit stale-input migration errors. The frozen L3
implementation, packaging, kernel requirement, dependencies, and live product
tests are deleted. Permanent single-path and socket-owner gates now enforce the
result; the final performance decision and backend matrix remain. This plan
owns that remainder. The closed Plan 316 phase issues are
historical; issue #2751 is the active umbrella.

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

- [x] Add `xtask network-perf` with machine-readable reports for opaque TCP,
      UDP, DNS, and transformed HTTP latency, throughput, CPU, copies where
      measurable, and peak RSS.
- [x] Record host-, backend-, storage-, build-, and sample-labelled legacy L3
      and current FlowMux baselines under `specs/benchmarks/network/`.
- [x] Make comparison thresholds explicit: opaque latency at most 5% slower,
      throughput at least 95%, RSS growth at most 10%, and transformed HTTP
      latency at most 10% slower unless an owner-approved measured exception is
      recorded here.
- [x] Keep the harness hermetic by default and isolate live KVM/HVF/libkrun
      runners behind explicit environment checks.

The pre-deletion comparisons are deliberately retained as failing evidence:
21 checks miss on the labelled macOS arm64 host and 28 miss on the labelled
Linux x86_64 host. No owner exception is approved. W8 must produce a passing
final report or record an explicit owner-approved measured exception.

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

The host-side performance probe enables the narrow `flowmux-client` feature,
not the guest addon bundle. This keeps guest-only vsock dependencies out of
host test graphs and preserves the duplicate-major dependency invariant.
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
- [x] Retire post-admission SDK forwarding without regressing typed manifest or
      OCI sources, boot-command overrides, literal environment and egress
      lowering, or the pinned browser provider and readiness surfaces.
- [x] Regenerate SDK protocol bindings after removing the guest port-forward
      request so the committed Python types match the canonical schema.

The public-surface CI rerun exposed a stack-order defect in the completed UDP
ingress work: replies to peers already observed by an ingress mapping were
still evaluated as guest-introduced outbound destinations. The session now
applies outbound transform and egress admission only when the guest introduces
a new peer; the relay's observed-peer table remains the authority for ingress
replies and rejects unseen destinations. The focused regression passes five
consecutive runs.

### W5 — Remove the rejected public compatibility surface

- [x] Remove `raw_ip_stack` and `NetworkMode::L3Vsock` from the Rust IR,
      Python and TypeScript SDKs, generated schemas, fixtures, examples, CLI
      help, and public documentation.
- [x] Preserve an explicit migration error for stale serialized input at the
      outer compatibility boundary without representing the rejected mode in
      admitted domain types.
- [x] Document the supported loopback proxy, SOCKS5h/UDP, controlled DNS,
      mediated ping, and typed connector surfaces, and the fail-closed result
      for applications that bypass them.
- [x] Add schema parity, stale-input refusal, supported-adapter, typed-
      connector, and non-cooperative direct-socket BDD tests.

### W6 — Delete the superseded L3 implementation

- [x] Delete contract and policy L3 modules, L3-only channel identities,
      leases, fuzz targets, synthesis/admission branches, and live product
      scenarios.
- [x] Delete `mvm-net` and `mvm-agentd` L3 modules, `mvm-net-agent`, guest TUN
      setup/cmdline/runtime-overlay code, and the workload-kernel TUN
      requirement where no non-network consumer remains.
- [x] Delete hostd netd modules and binary, host TUN/netns/nftables and smoltcp
      datapaths, privileged L3 tests, VMM spawn/reap/teardown hooks, and
      control/data service sockets.
- [x] Remove resulting dependencies and packaging/Nix/CI/kernel residue; update
      lockfiles and closure budgets.
- [x] Rewrite protocol-independent security scenarios against FlowMux and
      delete scenarios for intentionally unsupported raw networking.
- [x] Run dependency, advisory, license, duplicate-major, and closure-budget
      checks with no L3-only binary or dependency left.
- [x] Refresh the standalone `mvm-agentd` fuzz lock to the reviewed `blake3`
      1.8.6 graph so the vendored `arrayref` patch remains active under
      `--locked` validation.

**Validation.** W6 removes more than 41,000 lines across the raw-packet
contract, guest agent, host gateway, VMM lifecycle, packaging, Nix, kernel, CI,
fuzz, and live-product slices. `cargo machete` reports no unused dependencies;
advisory, license, source, ban, duplicate-major, default-closure, and
all-feature closure checks pass. The standalone agent fuzz graph also passes
its locked all-target check with the reviewed `arrayref` patch active. The
all-feature closure is 468 crates, with
default Linux and macOS closures at 235 and 226. Host all-target Clippy,
all-feature gated compilation, formatting, the complete workspace test and
doctest suite, and all 56 BDD features pass (194 scenarios: 193 passed and one
capability-gated skip).

### W7 — Replace migration ratchets with permanent invariants

- [x] Add `check-single-network-path`: exactly one production endpoint binary
      and spawn implementation, every networked backend binds `NetworkFlow`,
      and forbidden packet/NIC/gateway symbols occur only in historical specs.
- [x] Add a socket-owner gate permitting workload outbound connects and
      ingress listener binds only inside the endpoint, with narrow enumerated
      exemptions for unrelated host infrastructure.
- [x] Test each gate with forbidden synthetic fixtures and its exact allowed
      cases, then retire temporary L3 freeze/uniform-vsock gates that no longer
      describe the tree.
- [x] Add a signed-plan projection test showing TCP, UDP, DNS, typed connectors,
      and ingress share one policy object, budget owner, identity, and audit
      sink.

**Validation.** The permanent gate rejects synthetic second endpoint spawns,
runner/channel divergence, retired L3 and guest-NIC symbols, stale public mode
spellings, and unauthorized outbound-connect or listener-bind sites while
preserving exact endpoint and unrelated-infrastructure cases. Endpoint
projection tests exercise TCP, UDP, DNS, typed connectors, and ingress against
the same policy, budget, identity, VM resource, and audit allocations. A
connector service test additionally asserts pointer identity for the shared
gate and recorder. Host all-target/all-feature Clippy, the complete `mvm-hostd` suite,
the complete workspace test and doctest suite, Linux all-target and BDD-feature
gated compilation, and all 56 BDD features pass (194 scenarios: 193 passed and
one capability-gated skip). Formatting, dependency, advisory, license, source,
ban, duplicate-major, closure-budget, conformance, claim, workflow-path,
process-citation, sprint-append, one-guest-protocol, and single-network-path
checks also pass.

### W8 — Run the final evidence matrix and close the umbrella

- [ ] Run `xtask network-perf` against the recorded baseline and record the
      final report and any approved exception. A fresh release run is recorded
      at `specs/benchmarks/network/flow-mux-macos-arm64-host-loopback-642140ec38.json`
      with comparison
      `specs/benchmarks/network/comparison-macos-arm64-host-loopback-642140ec38.json`.
      It remains truthfully `passed: false` (12/32 checks pass; maximum
      latency ratio 14.5x; minimum throughput ratio 0.325x), so this item is
      still a performance blocker. The raw evidence and thresholds were not
      edited. The failures are concentrated in short-flow authenticated
      framing/session setup and endpoint-relay paths versus the deleted direct
      L3 baseline; this is a measured diagnosis, not an acceptance exception.
- [ ] Live-witness Firecracker on Linux/KVM, HVF on macOS, and libkrun on every
      supported host OS. Cover deny-all, TCP, UDP, DNS, typed substitution,
      ingress, endpoint crash, no guest NIC, and no L3 services.
      The approved Lima-KVM Firecracker lane now passes an admitted TCP/DNS
      witness: Alpine fetched `http://example.com` under the exact
      `example.com:80` rule and exited zero. The wider behavior matrix and
      libkrun closeout remain open.
- [ ] Run workspace test/check/doc-test/formatting on the macOS host; run Linux
      all-target/all-feature Clippy, gated tests, Nix checks, and live KVM work
      inside the project builder VM.
- [x] Run BDD, dependency, supply-chain, schema, product, claim, and permanent
      networking gates.
- [x] Isolate pinned nested cross-compiles from the outer Cargo toolchain,
      compiler wrappers, and nightly-only Rust flags; cover the scrubbed
      command environment with a regression test.
- [ ] Update ADR/claim witnesses, public networking docs, release notes, this
      plan, the sprint delivery archive, and the refactor rollup; close #2751
      only after every acceptance item is backed by recorded output.

The post-stack validation rerun also found and fixed six closeout defects:
the standalone `mvm-sdk` fuzz lockfile had drifted; ingress UDP replies were
incorrectly rechecked against outbound egress admission after the relay had
already observed the external peer; an old evidence-tree snapshot overwrote
newer Python and TypeScript SDK boot-source, command, egress, and browser
surfaces while retiring dynamic forwarding; the generated Python protocol
binding still contained the deleted guest port-forward request; outer nightly-only Cargo flags
leaked into the pinned stable nested cross-compiler; and the refreshed fuzz resolver selected
`blake3` 1.8.7, bypassing the workspace-reviewed vendored `arrayref`. The
SDKs now declare ingress before boot while preserving those public surfaces,
and their generated protocol bindings match the canonical schema;
nested cross-compiles clear outer toolchain, wrapper, and Rust flag variables,
and the fuzz lock pins `blake3`
1.8.6 so the reviewed patch remains active. The full host workspace test,
check, doc-test, and formatting chain passes; the locked fuzz build passes on
Rust 1.91.1; the focused observed-peer test passes five consecutive runs; and
hostd all-target Clippy passes with warnings denied.

The first post-deletion macOS arm64 host-loopback candidate is recorded at
`c22db543f1`. It passes 12 of 32 comparisons and misses 20: ten opaque-TCP,
six UDP, and four transformed-HTTP connect checks. The raw candidate and
comparison reports are retained under `specs/benchmarks/network/`; no
performance exception is approved or implied. W8 remains open until the
published ceilings pass or the owner explicitly accepts the measured delta.

## Definition of done

- [x] The production source tree contains no L3/raw-packet workload networking
      code, public raw-network mode, or second ingress/egress socket owner.
- [x] Every admitted network flow shares one endpoint, authenticated protocol,
      signed-plan projection, per-VM budget owner, and payload-free audit sink.
- [x] Typed transformation and declared ingress are bounded, streaming, and
      covered across positive, negative, cancellation, and boundary cases.
- [x] Permanent gates reject a second path or socket owner.
- [ ] Performance budgets and the required cross-backend live matrix pass, and
      all repository validation is green.

## Non-goals

- No guest NIC, host bridge, TAP, slirp, passt, vpnkit, or raw-packet fallback.
- No universal TLS interception CA or attempt to bypass certificate pinning,
  QUIC, or ECH.
- No weakening of ptrace, seccomp, capability, Landlock, read-only-root, or
  secret-handling boundaries for application compatibility.
- No alternate production endpoint retained as a development escape hatch.
