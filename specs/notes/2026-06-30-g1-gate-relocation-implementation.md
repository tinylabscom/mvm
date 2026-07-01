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

## Status (as of 2026-06-30)

Done, committed, unit-tested (fmt / clippy / `check-vsock-only-egress` all clean;
no backend flipped, no legacy path deleted — all additive):

- **P1.1** `feat(hostd): substitution endpoint gains the claim-10 egress gate` —
  `EndpointConfig.network_policy: Option<NetworkPolicy>`; `assemble` builds the
  shared `EgressGate`; `SubstitutionService::process` refuses an unadmitted
  destination before substitute/forward. `None` ⇒ ungated (legacy). Tests prove
  no secret crosses on a denial.
- **P1.2** `feat(hostd): endpoint gains a raw-TCP egress serve mode` —
  `EndpointConfig.egress_mode: {Wire(default), Raw}`; `raw_egress::serve_raw_egress`
  reads `host:port\n`, gates via the same `EgressGate`, connects + splices. The
  endpoint is now the unified bridge for BOTH protocols.
- **P1.3** `feat(backend): in-house VMM run loop gains a pure-relay egress mode` —
  `HostChannels.egress_relay` / `HvfSupervisorConfig.egress_relay_socket`;
  `SubstitutionBridge::set_relay_only` skips the in-loop gate + parse and pipes
  bytes to the endpoint. Relay mode drops the in-loop `EgressGate` entirely.

### P1.4 + P1.5 — DONE, live verdict GREEN (2026-06-30)

- **P1.4** `feat(backend): wire InHouseDriver::boot to the relay supervisor path` —
  `VmmSpec` gained `initramfs`; `boot` maps the policy-free spec → a relay
  `HvfSupervisorConfig` (`egress_relay_socket` = the `EGRESS_PORT` `VsockPort.host_uds`,
  no in-loop policy) and returns a `RunningVm`. Fails closed with no `EGRESS_PORT`
  socket or a bundled kernel.
- **Corrected echo init** — `crates/mvm-backend/examples/hvf-egress-guest/{init.c,build.sh}`:
  freestanding aarch64, mounts procfs, reads `mvm.egress_target` from `/proc/cmdline`
  (no hardcoded IP), sends `target\n` then `ping`. Reproducible cpio build.
- **P1.5 live proof** `test(hvf): live proof — claim-10 egress enforced by the host
  endpoint` (`examples/hvf-relay-egress`). Runs the echo guest through `InHouseDriver`
  with `EGRESS_PORT` relayed to a per-VM endpoint (`egress_mode: Raw`,
  `network_policy: Some(allow_list)`). **Verified on macOS-26 Apple silicon:**
  `admitted destination reachable: true`, `non-admitted destination reachable: false`
  — claim-10 preserved with the gate in the endpoint, the run loop a pure relay.

**Environment gotcha that cost time (record it):** `/tmp/mvm-hvf-kernel/Image` (the
example default) is a broken kernel — it produces **zero** earlycon bytes. The
working kernel on this box is `/tmp/mvm-hvf-kernel/Image-builder`. A broken kernel
file masquerading as a console/code bug is the same class of trap as a stale dev IP.
Use `Image-builder` (or rebuild `Image`).

### Legacy-gate deletion — DEFERRED to the HvfBackend→relay migration (Phase 2)

The G1 "delete the legacy in-loop gate + `network_policy`" step is **not** safe yet:
`HvfBackend::start` (the current production HVF workload path) still sets
`network_policy` and relies on the in-loop `EgressGate` / `EgressProxy` /
`SubstitutionBridge` gate. Deleting them now would leave HvfBackend with **no**
claim-10 enforcement — a regression, and exactly the "window with no gate" the
invariant forbids. The relay path is proven and available (via `InHouseDriver`), but
HvfBackend hasn't been routed onto it, and the WireRequest (secret-bearing) relay
path is not yet live-verified (only the Raw path is). So the legacy gate stays until
Phase 2 routes `HvfBackend` (or `WorkloadRunner<InHouseDriver>`) through the relay and
re-verifies BOTH the Raw and Wire paths live; then `EgressProxy` + the in-loop gate +
`HvfSupervisorConfig.network_policy` become dead and are deleted together.

### (superseded) original remaining plan

- **P1.4 — wire `InHouseDriver::boot` + a live harness.** `boot` maps the
  policy-free `VmmSpec` → a relay `HvfSupervisorConfig` (`egress_relay_socket` =
  the `EGRESS_PORT` `VsockPort.host_uds`; no `network_policy`), spawns
  `mvm-hvf-supervisor`, and returns a `RunningVm` wrapping the supervisor child +
  `workload.exit` + pid file (extract the mechanics from `HvfBackend::start`). The
  NetworkPolicy stays with the caller, which spawns the endpoint bound to that UDS
  with `network_policy: Some(policy)` + `egress_mode: Raw`. (Full `WorkloadRunner`
  is Phase 2; the Phase-1 live proof can use a thin harness / the example.)
- **P1.5 — live-verify on HVF, then delete the legacy gate.** The example's echo
  guest speaks the raw SOCKS→`host:port` protocol, so the endpoint runs
  `egress_mode: Raw`. Rebuild the aux bins explicitly
  (`cargo build -p mvm-vm-host --bin mvm-hvf-supervisor`,
  `cargo build -p mvm-hostd --bin mvm-substitution-endpoint`) — `cargo run/test`
  won't. The proof must show: admitted LAN destination reachable AND a non-admitted
  one refused, with the gate now in the endpoint. Only after GREEN: delete the
  in-loop `EgressGate` from `HostChannels`/the run loop and `network_policy` from
  `HvfSupervisorConfig` (and the now-dead `EgressProxy`, once nothing routes to it).

### P1.5 blocker found — the on-disk echo init is stale and protocol-incompatible

`/tmp/hvf-init-echo/init.c` (the initramfs the `hvf-backend-egress` example boots)
is stale in two ways that break the relay live-verify:

1. It **hardcodes** `192.168.4.23:19099` and does NOT read `mvm.egress_target`
   from `/proc/cmdline` — despite the example already injecting the discovered LAN
   address via `MVM_HVF_BOOTARGS_EXTRA`. A hardcoded dev IP is exactly the
   masquerade-as-egress-bug trap; the init must read the cmdline.
2. It sends the target with **no trailing `\n`** (it relied on the old in-loop
   `EgressProxy` consuming the first *vsock frame* as the target). In the relay
   model the run loop pipes the guest stream byte-for-byte to the endpoint UDS, so
   vsock frame boundaries are lost — the endpoint's `raw_egress::read_target_line`
   needs a `\n` delimiter (which the real `mvm-guest-helpers::egress_client`
   already sends). So the echo init MUST send `mvm.egress_target` + `\n`, then the
   request bytes.

**P1.5 therefore includes authoring a correct minimal echo init** (arm64 freestanding
C or a small Rust `no_std`/musl static bin): parse `mvm.egress_target=<host:port>`
from `/proc/cmdline`, connect vsock `EGRESS_PORT`, write `target\n`, write `ping`,
read the reply, print `egress reply over vsock: <reply>`, then write the exit port.
Rebuild the cpio. Prove BOTH the admitted destination (reply received) and a
non-admitted one (no reply — refused at the endpoint gate). There is no in-repo
build script for this initramfs today; add one under the example's tooling so the
proof is reproducible rather than a `/tmp` artifact.

## Phase 2 frontier (verified against code, 2026-06-30 — start here)

G1 (P1.1–P1.5) is DONE + live-verified. Phase 2 is genuinely NOT STARTED — confirmed:
- `WorkloadRunner` does not exist yet (P2.1 open).
- No Wire/secret-bearing relay live proof (P2.2 open).
- `HvfBackend::start` still sets `network_policy` + `egress_relay_socket: None`
  (`hvf_backend.rs:215,219`) — the production HVF path still uses the LEGACY in-loop
  gate; not routed through the relay (P2.3 open).
- `vsock_egress_bridge::egress_proxy::EgressProxy` still present + used by
  `vmm/vsock.rs` — legacy gate NOT deleted (P2.4 open).

Tools already in place for P2.1: `workload_spec` (VmStartConfig→VmmSpec),
`InHouseDriver::boot` (relay path, live-proven), and `spawn_substitution_endpoint` +
`build_endpoint_config_json` now carry `network_policy` + `raw_egress` (the gating
endpoint spawn). So `WorkloadRunner` spawns a gating endpoint with
`network_policy: Some(resolved)` + `raw_egress` (Raw if no secrets, else Wire), threads
its UDS into the `EGRESS_PORT` `VsockPort.host_uds`, and boots via `InHouseDriver`.

Execution order unchanged: P2.1 WorkloadRunner (test vs MockDriver) → P2.2 Wire live
proof → P2.3 route HvfBackend/machine-run through WorkloadRunner<InHouseDriver> +
re-verify → P2.4 delete the in-loop gate + EgressProxy + network_policy. Legacy stays
until BOTH Raw and Wire relay paths are live-green.
