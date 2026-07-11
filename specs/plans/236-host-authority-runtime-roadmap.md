# Plan 236 — Host-authority runtime roadmap

**Status:** IN PROGRESS (GO; macOS verb-grant witness remains)  
**Created:** 2026-07-09  
**Goal:** turn `mvm`'s current security and architecture lead into a simpler,
more competitive product by finishing the host-authority model, removing
remaining guest-NIC and guest-directed escape hatches, narrowing the secrets
story to explicit host-owned authorities, and shipping a developer-grade
lifecycle on top of that runtime.

**Execution note (2026-07-10):** the prerequisite picture changed after synced
`origin/main` advanced on July 10, 2026. The merged Plan 219 refresh
(`Refresh Plan 219 grant-delivery branch on main`, PR `#1605`) and the merged
Phase 2A registry closeout (`Finish vsock port-handler registry production
closeout`, PR `#1599`) are now satisfied directly on `origin/main`. The three
remaining stale prerequisite branches were then refreshed into dedicated Codex
worktrees:
`codex/plan-236-plan202-refresh`,
`codex/plan-236-vsock-egress-refresh`, and
`codex/plan-236-plan216-refresh`. All three currently rebase cleanly and
collapse to `origin/main`, so the checker now treats "clean + aligned with
main after refresh" as GO rather than forcing an artificial ahead-of-main
delta. That means the broad branch-staleness blocker is cleared; the remaining
honest production-readiness blockers for Plan 236 are live-proof and closeout
evidence, not stale prerequisite worktrees.

**Execution progress (2026-07-10 / 2026-07-11):** the gate turned `GO` and the Phase 1 →
Phase 2A pivot largely landed on `main`. Shipped: §1 delivers the host-signer
verb-grant anchor over the kernel cmdline to the vsock-only backends
(libkrun/HVF), so sealed guests pin and *selectively* enforce plan-bound grants
instead of failing to deny-all (PR `#1615`); §3.1 renames `no_guest_nic` →
`no_routable_guest_nic` with honest reachability semantics (PR `#1616`); the
Phase 2A workload delta gates the HVF egress endpoint on admitted policy so a
deny-all workload spawns no endpoint and fails closed, matching libkrun
(PR `#1619`); and the dead `HostBoundRequest` surface is removed. The §4
negative-path matrix surfaced a real bypass — `re_pin_verb_grant` verified the
resume envelope against its own embedded key — fixed by verifying against the
boot-pinned host-signer anchor with a shared verification core (closes the
self-forgery bypass). The restore/fork follow-up now also binds host-signed
re-pin envelopes to the currently pinned VM lineage (`predecessor_session_id` +
`predecessor_plan_nonce_hex`), so a genuinely host-signed sibling grant cannot
replace the current VM's grant during `PostRestore`; focused guest/core/CLI
tests plus green `cargo clippy --workspace --all-targets -- -D warnings` and
host `cargo test --workspace` validation closed the cross-VM replay residual.
Remaining honest blockers: the separate macOS live-proof of vsock-only
verb-grant enforcement still needs to be captured. The earlier
production/verity OCI seal-path blocker is now closed on
`feat/plan-236-oci-seal-closeout`, including a signed BusyBox prod witness, so
this replay-binding slice no longer carries that as an open dependency.

## Thesis

`mvm` already has the right base posture:

- signed admission
- chain-signed audit
- vsock-first direction
- host-services model
- builder/runtime split
- rootfs integrity work

The remaining gap is not core security architecture. It is **execution
consistency**:

1. the host-authority boundary is not yet the only production shape on every
   path;
2. the vsock-only no-guest-NIC path is not yet universal across workloads and
   builders;
3. the secret-egress story is promising but still broader and rougher than it
   should be;
4. the local client/runtime lifecycle is still more operator-shaped than
   developer-shaped.

This plan closes those gaps without turning `mvm` into a transparent network
appliance. The winning line is: **explicit host authorities, audited vsock/UDS
transport, no guest-directed upstream sockets, and a cleaner runtime UX than
the field.**

## Non-goals

- Do not make transparent TLS interception the primary runtime primitive.
- Do not add any new production path where the guest opens arbitrary upstream
  sockets directly.
- Do not reintroduce gvproxy-era or guest-NIC compatibility fallbacks to make
  a benchmark pass.
- Do not split security authority across multiple overlapping control planes.
- Do not let SDK convenience bypass signed admission, audit, or host policy.

## Priority order

### P0 — Must land first

- [ ] Finish the host-authority transport boundary.
- [ ] Finish the vsock-only, no-guest-NIC workload path.
- [ ] Finish the builder path's no-guest-NIC cutover with live evidence.

### P1 — High leverage, competitive

- [ ] Ship a narrow, explicit destination-bound secret-egress path.
- [ ] Ship caller-owned runtime lifecycle through the `MvmClient` facade.
- [ ] Add a host-only mutable runtime control socket.

### P2 — Hardening and scale-up

- [ ] Tighten runtime-share/filesystem semantics.
- [ ] Complete lifecycle parity features such as reconfigure/health/warm paths.
- [ ] Publish stronger operational evidence and benchmark claims.

## Start trigger

This plan starts when leadership makes one explicit call:

- [ ] `mvm` is standardizing on the host-authority, no-guest-NIC, vsock-only
      runtime line as the default architecture path.

That decision is usually justified by one or more concrete triggers:

- [ ] The active vsock-only transport branches need integration rather than more
      isolated branch work.
- [ ] Linux builder smoke is still blocking the claim that the runtime is
      honestly vsock-only end to end.
- [ ] Secret-egress work needs a product-scope decision before more
      implementation lands.
- [ ] SDK/runtime lifecycle work is expanding again and needs one owning
      integration roadmap.

## Go / No-go checklist

Start execution on this plan only when the following are true:

- [ ] The current top-level product priority is to finish the host-authority
      transport line rather than open a competing runtime direction.
- [ ] We are ready to treat the current no-guest-NIC / vsock-only branches as
      the mainline architecture path.
- [ ] We are willing to treat transparent-network work as exploratory unless it
      proves value inside the host-authority model.
- [ ] The next integration work will begin with Phase 1 and Phase 2 inputs:
      `fix/agent-verb-grant-delivery`,
      `feat/vsock-port-handler-registry`, and
      `worktree-vsock-only-egress-cutover`.

Do not start execution on this plan when any of the following are true:

- [ ] The team still wants to compare multiple competing transport end states in
      parallel.
- [ ] The active no-guest-NIC branches are still too early to integrate and
      need more isolated prototyping first.
- [ ] The current quarter's priority is elsewhere and this plan would only add
      coordination overhead without implementation follow-through.

## Existing work that already shrinks this plan

These branches and plans should be treated as direct inputs, not parallel
competing epics:

- `feat/plan-202-native-host-services`
  - Residual cleanup only.
  - Reuse as the host-only daemon/control-plane proof point.
  - Do not reopen the process-moat question.
- `feat/plan-216-s0-mvm-client`
  - Keep as the seed for the local/remote facade.
  - Shrinks Phase 4 materially; do not redesign the crate from scratch.
- `fix/agent-verb-grant-delivery`
  - Directly contributes to the host-authority boundary.
  - Fold into Phase 1; it is not optional polish.
- `feat/vsock-port-handler-registry`
  - Direct input to readiness-driven host I/O and libkrun runtime proof.
  - Fold into Phase 2 instead of leaving it a refactor-only branch.
- `worktree-vsock-only-egress-cutover`
  - Direct input to workload no-NIC cutover.
  - Reuse its host-vsock proxy and builder-vsock egress lessons.
- `feat/vsock-transparent-net`
  - Treat as exploratory, not as the architecture baseline.
  - Salvage only the useful pieces: tests, bounded pump/handler abstractions,
    and evidence about denied paths.
  - The branch's return-path complexity is itself a design signal: semantic
    DNS/TCP/UDP message translation forces the guest and host to synthesize
    TCP/ICMP/DNS packets back toward the workload, which is precisely the
    stateful return-path complexity this roadmap avoids by standardizing on a
    raw L3 packet tunnel over vsock.
  - Do not import the `mvm-net` semantic protocol, synthetic DNS/IP mapping, or
    TLS/plugin pipeline into the Phase 2 packet tunnel baseline.

Related landed or in-flight plans that should be reused instead of duplicated:

- Plan 202 — host services daemon
- Plan 204 — resident builder control plane
- Plan 211 — VM host process convergence
- Plan 216 — `MvmClient` facade
- Plan 219 — out-of-band agent verb grant delivery
- Plan 221 — in-process rootfs materialize
- Plan 223 — virtiofs root
- Plan 224 / 225 — machine reconfigure
- Plan 227 — instant-resume vsock-only sandboxes
- Plan 230 — two-surface consolidation
- Plan 232 / 233 — workload healthcheck lifecycle
- Plan 237 — HVF density memory footprint reduction

## Source lessons reflected here

This roadmap is grounded in a full-codebase analysis of a peer sandbox runtime,
not only its networking path. The emphasis on transport and egress exists
because that is where `mvm` still has the largest integration gap, but the
phases below reflect lessons from the whole system:

- **Runtime and launch model**
  - Reflected in Phases 4 and 5.
  - Why: the child-runtime ownership model, launch-config hygiene, and
    host-only mutable controls were among the strongest ideas in the review.
- **Protocol and relay structure**
  - Reflected in Phases 1 and 5.
  - Why: the review reinforced that `mvm` should keep one explicit guest
    request surface and avoid smearing host-only controls across the guest
    protocol.
- **Guest agent scope**
  - Reflected in Phases 1 and 2.
  - Why: the analysis supported a narrower guest role: guest requests host
    services, but does not become a general network actor with its own
    upstream authority.
- **Networking and policy enforcement**
  - Reflected most strongly in Phases 2 and 3.
  - Why: this is the area where `mvm` most needs convergence around the
    no-guest-NIC, vsock-only, host-authority direction.
- **Filesystem and rootfs model**
  - Reflected in Phase 6.
  - Why: the review reinforced the value of a narrow runtime share, explicit
    rootfs layering semantics, and keeping host/guest file exchange bounded.
- **Observability, audit, and evidence**
  - Reflected in Phase 7.
  - Why: the review confirmed that strong runtime evidence should remain a
    differentiator, but separated from policy and transport authority.
- **Runtime density and helper-count discipline**
  - Reflected in Phases 2, 4, and 7.
  - Why: the review supported fewer long-lived helpers, tighter host-owned
    runtime roles, and honest capacity claims rather than invisible process
    sprawl.

## Guardrails

- Host-owned authorities remain the only source of network, secret, audit, and
  mutable-runtime power.
- Domain/SNI/hostname inference may inform policy, but it must not become the
  primary authorization model.
- The guest may request work; it may not define the trust boundary.
- Prefer raw packet carriage over semantic flow re-encoding on the Phase 2
  tunnel path. Bounded pump loops and fail-closed relays are reusable ideas;
  host/guest TCP state synthesis is not the target architecture here.
- Every new runtime affordance needs a clear owner:
  - guest protocol
  - host-only control socket
  - signed admission plan
  - builder control plane
- Every production transport claim needs a live witness on both macOS and
  Linux.

## Phase 0 — Align the execution line

**Goal:** freeze the architecture line before more implementation branches drift.

- [ ] Ratify this plan's core rules in the relevant ADRs and plans:
  - no guest-directed upstream sockets
  - no production guest NIC path
  - host-only mutable runtime controls
  - explicit destination-bound secret egress
- [ ] Mark which existing plans become direct dependencies versus which are
  superseded by this roadmap.
- [ ] Merge or close planning-only branches that restate the same direction in
  incompatible language.
- [ ] Update `specs/02-roadmap.md` to point at this plan as the integration
  roadmap for the current host-authority push.

**Exit criteria**

- One current plan is the integration source of truth.
- No active branch is still assuming a guest-NIC or transparent-net-first end
  state without calling it out as exploratory.

## Phase 1 — Finish the host-authority boundary

**Why first:** this is the architectural moat. If this stays fuzzy, later
runtime and secret work will duplicate authority or weaken policy.

- [ ] Land the remaining Plan 219 work so sealed guests receive and enforce
  plan-bound verb grants on the real boot path.
- [ ] Audit guest protocol verbs and classify each as:
  - host authority request
  - host-only control-socket operation
  - disallowed in production
- [ ] Remove or quarantine any production path that still lets the guest define
  mutable runtime state outside signed admission or host-owned control.
- [ ] Make backend capability descriptors the honest authority surface:
  `{ vsock, no_guest_nic, host_vsock_proxy }` must mean exactly that.
- [ ] Add negative-path tests proving production guests cannot regain forbidden
  verbs or widen their authority through reconnect, resume, or fallback paths.

**Primary reuse**

- Plan 202
- Plan 215 / 219
- Plan 230
- branch `fix/agent-verb-grant-delivery`

**Exit criteria**

- Every production guest-to-host privileged action is either a signed-plan
  consequence or an explicit host service call.
- No production path depends on guest-defined arbitrary external connectivity.

## Phase 2 — Make the data plane honestly vsock-only

**Why second:** the biggest competitive and security payoff is an audited
no-guest-NIC runtime that is actually true on both workload and builder paths.

### Phase 2A — workload path

- [x] Seed the cross-backend guest-TUN ↔ host-worker tunnel contract in
      `mvm_core::protocol::network_tunnel`:
  - bounded frame header + whole-frame decode/encode
  - typed control messages (`HELLO`, `HELLO_ACK`, `CONFIG`, `CREDIT`,
    `HEARTBEAT`, `ERROR`, `SHUTDOWN`)
  - session-bound identity fields (`tenant_id`, `vm_id`, `boot_id`,
    `session_nonce`)
  - guest interface/DNS/MTU config validation
  - fail-closed parsing and control-payload validation
  - explicitly backend-agnostic shape: usable by Firecracker, HVF, libkrun,
    and future backends that carry the same host-authority data plane
- [x] Add the guest-side blocking tunnel-session helper in
      `mvm_guest::network_tunnel` on top of that shared contract:
  - reuses the existing guest→host AF_VSOCK dial path
  - negotiates `HELLO` / `HELLO_ACK`
  - sends/receives typed control frames
  - sends/receives packet frames with shared fail-closed decode
  - keeps the transport reusable for every backend that provides the admitted
    host-authority vsock/UDS path
- [x] Add the host-side blocking tunnel-session helper in
      `mvm_hostd::network_tunnel` on top of that shared contract:
  - validates the first guest `HELLO` against host-owned
    `tenant_id` / `vm_id` / `boot_id` / `session_nonce`
  - emits the matching host `HELLO_ACK` from one reusable helper instead of
    per-backend ad hoc checks
  - sends/receives typed control frames
  - sends/receives packet frames with shared fail-closed decode
  - keeps backend adapters thin so Firecracker, HVF, libkrun, and future
    backends such as WHP can share the same session/identity boundary
- [x] Thread the launch-time packet-tunnel carrier through the shared runtime
      config and standing vsock map:
  - `TunnelSessionConfig` / `TunnelRuntimeConfig` live in the shared contract
    instead of per-backend ad hoc fields
  - `VmStartConfig` carries the optional tunnel runtime config explicitly
  - workload-role socket/spec mapping now exposes the optional guest-dials
    tunnel port as another standing per-VM vsock channel
  - host-side validation can derive `ExpectedTunnelSession` from the same shared
    session config instead of reconstructing it per backend
- [x] Thread the packet-tunnel runtime config through the sealed-boot cmdline
      handoff and guest bootstrap:
  - shared `mvm.network_tunnel=<hex(JSON)>` encode/decode helpers live beside
    the existing cmdline token helpers
  - HVF and libkrun append the token when the workload launch config carries
    the tunnel runtime config
  - guest tunnel bootstrap can recover the optional runtime config from
    `/proc/cmdline` and build the validated guest `HELLO` without re-deriving
    identity/session fields locally
- [x] Add the first guest-side tunnel network-config application helper on top
      of the shared contract:
  - `mvm_guest::network_tunnel` can now receive the host `CONFIG` control frame
    as a typed `TunnelNetworkConfig` instead of leaving that step as ad hoc
    caller logic
  - `mvm_guest::guest_net` now exposes one Linux-only
    `configure_tunnel_guest_network` entry point that reuses the existing
    ioctl-based interface bring-up path for MTU, static IPv4, route, and
    resolver staging
  - the shape remains backend-agnostic: Firecracker, HVF, libkrun, and future
    backends such as WHP can share the same guest-side config-application seam
    while each backend keeps its own transport adapter
- [x] Add the first full shared bootstrap exchange helper on both sides of the
      tunnel session:
  - `mvm_guest::network_tunnel` now exposes a `bootstrap_over_stream` /
    `bootstrap_from_cmdline` flow that completes `HELLO` / `HELLO_ACK` /
    `CONFIG` and returns the live session plus host-authored guest config
  - `mvm_hostd::network_tunnel` now exposes `send_network_config` and
    `accept_bootstrap` so backend adapters can validate one host-owned session
    and then send the guest's typed tunnel config without inventing another
    per-backend control sequence
- [x] Add the first guest-side TUN device abstraction on top of the shared
      bootstrap/config path:
  - `mvm_guest::guest_tun` can open `/dev/net/tun`, bind the
    host-authored interface name with `TUNSETIFF`, and exchange raw packets via
    blocking `Read` / `Write`
  - `BootstrappedGuestTunnel::prepare_tun_device` now ties that device open to
    the shared `CONFIG`-application step so the future packet pump can start
    from one backend-agnostic bootstrap result
- [x] Add the first bounded guest packet-relay helpers on top of the shared
      TUN/session bootstrap:
  - `BootstrappedGuestTunnel` can now pump one packet from the guest TUN to the
    tunnel session and one packet from the tunnel session back into the guest
    TUN
  - both directions enforce the negotiated frame size and fail closed on
    oversize payloads or short writes instead of silently truncating traffic
- [x] Add the first blocking guest tunnel pump-loop substrate:
  - `BootstrappedGuestTunnel::pump_ready` now gives the guest worker one
    testable readiness tick that can advance the guest→host and host→guest
    packet path without re-encoding flows semantically
  - `BootstrappedGuestTunnel::run_blocking_packet_loop` now provides the first
    poll-based runtime loop over the guest TUN fd and tunnel session fd so a
    later guest tunnel worker can own the full packet path without inventing a
    separate loop model
- [x] Add the first host-side default-deny tunnel worker on top of the shared
      session/bootstrap seam:
  - `mvm_hostd::network_tunnel::HostTunnelWorker` now accepts the validated
    shared bootstrap, owns per-session packet counters/limits, and applies an
    explicit host packet policy instead of leaving the host side as a bare
    socket placeholder
  - the worker now also sends a validated initial `CREDIT` grant after
    bootstrap, so the shared control-plane backpressure path is no longer just
    a placeholder enum variant
  - the first production-safe policy is `DropAll`: packets are accounted,
    audited, and refused by host-owned policy rather than forwarded implicitly
    or re-encoded as a higher-level transport
  - quota exhaustion now fails closed with shared `ERROR` / `SHUTDOWN` control
    frames, giving later admitted forwarders one reusable host-worker loop
    model before any backend-specific forwarding path lands
- [x] Tighten the guest runtime path so tunnel-enabled boots no longer lean on
      legacy guest-NIC behavior:
  - `mvm-guest-netinit` now detects the shared tunnel cmdline token and skips
    legacy `eth0` bring-up when the packet-tunnel path is requested
  - the guest tunnel packet loop now decodes host control frames in-band,
    ignores keepalive/credit updates, and treats host `SHUTDOWN` as a clean
    stop instead of crashing as if a control frame were malformed packet data
  - the guest tunnel loop now keeps one pending packet and stops draining the
    guest TUN when send credit is exhausted, then resumes forwarding only after
    a later host `CREDIT` update replenishes the bounded budget
- [x] Wire the first runtime-owned host tunnel worker subprocess into the
      workload backends:
  - `mvm-network-tunnel-worker` is now a dedicated `mvm-hostd` bin that binds
    the per-VM host UDS or host AF_VSOCK listener, accepts one tunnel stream,
    reuses the shared bootstrap/worker loop, and appends JSONL audit events
  - `mvm-backend::network_tunnel_spawn` now owns the backend-neutral spawn/reap
    seam, helper lookup, host-authored default `mvm-net0` config, listener
    selection, readiness polling, and fail-closed pid/socket lifecycle
  - the HVF workload runner and libkrun backend keep the per-port host UDS
    listener shape, while Firecracker now carries the same shared tunnel config
    into `FlakeRunConfig`, appends the shared `mvm.network_tunnel=` cmdline
    token, and starts/reaps the worker on a host AF_VSOCK listener for the
    configured guest port
- [x] Add the first host-side TUN packet-device seam for later admitted L3
      forwarding:
  - `mvm_hostd::host_tun::HostTunDevice` now owns the Linux `/dev/net/tun`
    bind/open path, validates interface names before any syscall, and exposes
    blocking packet read/write plus raw-fd access for the host-owned tunnel
    boundary
  - the helper is intentionally separate from backend launchers and session
    validation so later HVF/libkrun/Firecracker/WHP forwarders can share one
    host packet-device primitive instead of each growing its own TUN open/bind
    logic
- [x] Add the first pluggable host packet-path seam to the tunnel worker:
  - `HostTunnelWorker` now supports `run_until_shutdown_with_packet_path`,
    keeping the shared session/bootstrap, quotas, audit, and fail-closed
    control frames while allowing a later admitted forwarder to plug in a
    host-owned packet path instead of rewriting the worker loop
  - `HostTunPacketPath<D>` is the first concrete path adapter: it writes guest
    packets into a host-owned TUN device, records forwarded-packet audit/stats,
    and treats short writes or device errors as explicit host failures
    (`ERROR internal` + `SHUTDOWN host_error`) rather than silent truncation
- [x] Add the first host-side bidirectional relay loop over the shared tunnel
      session and a host-owned packet device:
  - `HostTunnelWorker::run_blocking_tun_relay_loop` now polls the tunnel stream
    fd and a `HostTunPacketPath` fd together, reusing the same host-owned
    bootstrap, quotas, audit, and explicit shutdown behavior for both
    guest→host and host→guest packet carriage
  - host-originated packets from the TUN path now go back to the guest as raw
    packet frames with audit/stats, proving the first concrete return-path
    substrate without introducing a guest NIC, bridge, or semantic flow
    synthesizer
- [ ] Fold `feat/vsock-port-handler-registry` into mainline and keep its
  readiness-driven host-I/O model.
- [ ] Finish the libkrun/HVF workload path so no workload boot depends on a
  guest NIC, gvproxy, or passt helper.
- [ ] Keep the port-handler registry and host-vsock proxy as explicit runtime
  infrastructure, not hidden compatibility paths.
- [ ] Make endpoint spawning an admitted-runtime decision, not a universal per-VM
  default:
  - fully deny-all, no-secret workloads should not pay for an unused endpoint
  - any admitted egress or secret authority keeps the endpoint fail-closed
- [ ] Add live workload witnesses for:
  - no guest NIC attached
  - no helper process drift into gvproxy-era behavior
  - successful host-mediated egress under admitted policy

#### Phase 2A · data plane — raw-L3 host-forwarded egress

> Execution: use `superpowers:subagent-driven-development` — fresh subagent per
> task, two-stage review between tasks. Steps are red → green → commit.

**Goal.** Make an admitted workload actually reach the network over the vsock
tunnel — DNS resolves, TCP egress works, ICMP echo replies — with **no guest
NIC, no gvproxy, no passt, no TLS MITM, and no semantic message layer.** This is
the missing forward policy behind the already-built `DropAll` host worker.

**Architecture — raw L3, host-forwarded (roadmap baseline).** The wire stays the
tunnel's existing typed control/framing envelope
(`HELLO`/`HELLO_ACK`/`CONFIG`/`ERROR`/`SHUTDOWN` + `PacketFrameHeader`); the data
plane inside `FrameType::Packet` is **raw IPv4 packets**, exactly as the guest
TUN emits them. The guest stays a dumb L3 endpoint: it keeps the *existing*
`BootstrappedGuestTunnel` pump (`pump_one_tun_to_session` /
`pump_one_session_to_tun` / `run_blocking_packet_loop`) unchanged — no
translator, no packet synthesis, no message enum. **Statefulness lives in the
host kernel, not our code.** The host worker enforces `NetworkPolicy` at L3/L4,
then injects admitted guest packets into a **host TUN**
(`host_tun::HostTunDevice`, `/dev/net/tun`); the host Linux kernel routes and
NATs (masquerade) them to the real egress interface and returns replies through
the TUN, which the worker frames back to the guest. One mechanism carries
TCP/UDP/ICMP/DNS uniformly — no userspace stack, no per-protocol handlers. The
worker already forwards guest packets into a `host_tun::PacketDevice` (tested
with a fake); this slice swaps in a real device + NAT. **Host forwarding is
Linux-only** (`HostTunDevice::open_named` bails on non-Linux); macOS host
forwarding (a `utun` + pf NAT path) is a separate deferred task — so this
slice's live egress is proven on the Linux/Firecracker workload tier, **not on
macOS/HVF** (the platform of the original `bad address` repro). This deliberately
does **not** import the `feat/vsock-transparent-net` semantic `mvm-net` protocol,
its synthetic DNS/IP mapping, or its TLS/plugin pipeline (roadmap non-goal,
"Existing work that already shrinks this plan").

**Why raw L3 over semantic.** The semantic design forces both guest and host to
synthesize TCP/ICMP/DNS packets back toward the workload — the stateful
return-path complexity this roadmap avoids. Raw L3 keeps the guest trivial and
concentrates the stack on the host, where it is audited and policy-gated once.

**Policy at L3/L4 (no synthetic DNS).** The guest resolver points at the tunnel
gateway; the host forwards guest DNS (UDP/53) to a **real** upstream resolver, so
the guest gets **real** IPs and does its own end-to-end TLS to the real cert
(HTTPS works with zero MITM). Egress is gated by dst IP∈`DnsPinRegistry` (the
admitted allowlist hostnames pre-resolved to their real IPs, exactly as
`mvm_net_spawn.rs::resolve_dns_pins` already does) plus dst port. A dial to an
unpinned IP is dropped and audited. This is real DNS + real-IP pinning — not the
rejected 198.19/16 synthetic allocator.

**TLS/secrets: not in this slice.** No TLS termination anywhere — the guest owns
its TLS. Host-side secret substitution belongs to the narrower host-authority
model (Phase 3), not a transparent-net MITM. Do **not** import from
`feat/vsock-transparent-net-return-path`: `crates/mvm-net/src/host_tls.rs`,
`stream_transform.rs`, `crates/mvm-core/src/crypto/egress_ca.rs`, the
`mvm_net_spawn.rs` TLS/transform fns, `substitution_spawn.rs`, or
`mvm-cli/src/egress_ca_env.rs`.

**Global constraints (every task).**
- No new mvm crate: host L3 forwarder → `mvm-hostd` + the existing
  `mvm-network-tunnel-worker` bin; guest is unchanged; worker config types →
  `mvm-core`/`mvm-hostd`.
- No new external dep: forwarding reuses the in-tree `host_tun::HostTunDevice`
  plus the Linux kernel's own routing/NAT. (That is the point of raw-L3 over a
  semantic or userspace-stack design — the kernel is the TCP/IP stack.)
- `#[serde(deny_unknown_fields)]` on every config/wire type; bound every payload
  by `MAX_FRAME_PAYLOAD_LEN`; fail closed on decode and on any unparseable
  packet (drop + audit, never forward).
- No plan/PR/ADR refs in code comments (CI-gated); reword any spec-ref comment to
  concept.
- TDD, one behavior per commit; `cargo nextest run --workspace` +
  `cargo test --workspace --doc` + `cargo clippy --workspace -- -D warnings`
  green before each commit.
- `DropAll` stays as the deny-all default policy — the L3 forwarder is an added
  policy variant selected only under an admitted non-deny-all `NetworkPolicy`.

**Salvage (only what the roadmap permits — abstractions + denied-path tests, NOT
the semantic protocol).**
- Keep and reuse the uds-tunnel guest pump as-is (`crates/mvm-guest/src/
  network_tunnel.rs` `BootstrappedGuestTunnel`, `crates/mvm-guest/src/guest_tun.rs`
  `GuestTunDevice`/`PacketDevice`).
- Reuse the host worker skeleton (`crates/mvm-hostd/src/network_tunnel.rs`
  `HostTunnelWorker`, `TunnelWorkerLimits`, `TunnelAuditSink`,
  `TunnelPacketPolicy`) and the spawn/reap seam
  (`crates/mvm-backend/src/network_tunnel_spawn.rs`).
- Reuse admission-time real-IP pinning: `mvm_core::policy::dns_pin::DnsPinRegistry`
  and the `resolve_dns_pins`/host-gateway address conventions from
  `crates/mvm-backend/src/mvm_net_spawn.rs` (drop that file's TLS/transform fns).
- Reuse only the *test shape* of `feat/vsock-transparent-net-return-path`'s
  `crates/mvm-cli/tests/transparent_net_e2e.rs` (gating, keep-failed-VM,
  denied-path assertions) — not its probe internals.

---

- [x] **T1 — Host L3 packet inspector + policy gate (drop-only, no egress yet).**
  - Files: create `crates/mvm-hostd/src/network_tunnel/l3_forward.rs`; modify
    `crates/mvm-hostd/src/network_tunnel.rs` to add
    `TunnelPacketPolicy::L3Forward(L3ForwardPolicy)` beside `DropAll`, and route
    inbound `FrameType::Packet` payloads in `HostTunnelWorker::run_until_shutdown`
    through it. `L3ForwardPolicy` holds the admitted `NetworkPolicy` + a
    `DnsPinRegistry`. This task only *parses + decides*: minimal IPv4 header parse
    (dst addr, protocol) and TCP/UDP dst-port parse; `decide(dst_ip, proto, port)`
    → allow iff `dst_ip ∈ pins && port allowed`, else drop + `TunnelAuditEvent`.
    Accepted packets are counted but not yet forwarded.
  - Steps: failing tests `l3_gate_allows_pinned_ip_and_port`,
    `l3_gate_drops_unpinned_ip`, `l3_gate_drops_banned_port`,
    `l3_gate_drops_unparseable_packet_and_audits`; run — fail; implement;
    run — pass; commit `feat(net-tunnel): raw-L3 packet policy gate`.

- [x] **T2 — Forward admitted packets through a real host TUN + kernel NAT (Linux).**
  - The worker already forwards guest packets into a `host_tun::PacketDevice`
    (`worker_can_forward_guest_packets_into_host_packet_path` uses a fake device).
    Swap the fake for a real `HostTunDevice::open_named`, and stand up the
    host-side plumbing so injected packets actually egress: assign the gateway
    address (`10.240.0.1/30`, matching the guest-config gateway) to the host
    TUN, bring it up, and install a
    masquerade NAT rule from the tunnel link to the host's default egress
    interface (nftables — salvage the rule shape from the Firecracker egress
    setup). Gate on T1's `decide()` **before** injection so no unpinned packet
    reaches the TUN.
  - Files: `crates/mvm-hostd/src/host_tun.rs` (Linux-cfg address/up/route
    helpers), `crates/mvm-hostd/src/network_tunnel.rs` (wire the real device into
    the forward path), `crates/mvm-backend/src/network_tunnel_spawn.rs` (NAT
    setup/teardown around worker spawn/reap).
  - Steps: failing tests `host_tun_forward_injects_only_admitted_packets`,
    `nat_rule_shape_masquerades_tunnel_link` (assert the composed rule string; no
    live net), `denied_packet_never_reaches_host_tun`; implement; commit.

- [x] **T3 — Reverse path: host TUN replies framed back to the guest + limits.**
  - Read reply IPv4 packets off the host TUN (`HostTunPacketPath` read side) and
    frame them to the guest as `FrameType::Packet` via the worker's `send_packet`.
    Because the kernel handles the flows, TCP, UDP, ICMP, and DNS all return
    through this one path — no per-protocol code. Enforce `TunnelWorkerLimits`
    (bytes/packets); fail closed with `ERROR`/`SHUTDOWN` on quota.
  - Steps: failing tests `host_tun_reply_packets_frame_back_to_guest`,
    `reverse_path_respects_worker_limits`,
    `reverse_path_quota_exhaustion_shuts_down`; implement; commit.

- [x] **T4 — Guest config: default route + admission pins as `/etc/hosts`.**
  - No live DNS resolver, no synthetic DNS, no dynamic pinning. Resolution is
    host-authored at admission: the host resolves each allowlisted hostname to its
    real IPs (the `DnsPinRegistry`) and hands the guest those `host→IP` pairs, which
    the guest writes to `/etc/hosts`. The guest then resolves each admitted name to
    exactly the IP the gate admits — pin-consistent by construction — and any
    non-allowlisted name simply fails to resolve (correct default-deny). This is
    complete for an allowlist policy: you can only reach what you allowlisted.
  - Add a bounded `host_entries: Vec<TunnelHostEntry { name: String, ip: Ipv4Addr }>`
    field to `TunnelNetworkConfig` (`#[serde(default)]`, `deny_unknown_fields`,
    length-capped, name/label validated). Host side: the worker/`send_network_config`
    populates it from the admitted `DnsPinRegistry` (IPv4 pins only).
  - Extend `mvm-guest` `apply_network_config` to: bring the TUN up, set MTU, install
    the default route via `gateway_ipv4`, and write the `host_entries` into
    `/etc/hosts` (append/replace an `mvm`-owned block, idempotent). `dns_servers`
    stays advisory (resolver of last resort); admitted names resolve from
    `/etc/hosts` first.
  - Steps: failing tests `tunnel_config_host_entries_serde_roundtrip_and_bounds`,
    `send_network_config_populates_host_entries_from_pins`,
    `apply_network_config_installs_default_route_and_hosts_block`,
    `apply_network_config_hosts_block_is_idempotent`; implement; commit.

- [x] **T5 — Production caller: populate `VmStartConfig.network_tunnel`.**
  - Files: the admitted workload launch path building `VmStartConfig`
    (`crates/mvm-backend/src/workload_runner/runner.rs` + the `mvmctl` machine/up
    caller). Today all four `Some(...)` sites are `#[cfg(test)]`
    (`spec_map.rs:312/329`, `hvf_backend.rs:914`, `libkrun.rs:1668`). Add the real
    caller: when the resolved `NetworkPolicy` is **not** deny-all, build
    `TunnelRuntimeConfig` (features `{ ipv4:true, audit_stream:true }`; **not**
    `typed_connectors`/`dns_intercept`) with the plan's `tenant_id`/`vm_id`/
    `boot_id`/`session_nonce`; deny-all keeps `None`/`DropAll`.
  - Extend `crates/mvm-backend/src/network_tunnel_spawn.rs` worker-config JSON to
    carry the admitted `NetworkPolicy` + resolved `DnsPinRegistry` (mirror
    `mvm_net_spawn.rs::host_netd_config_json` **without** `tls_intermediate` /
    `stream_transforms`); the `mvm-network-tunnel-worker` bin builds the
    `L3ForwardPolicy` from them.
  - Steps: failing tests `allowlist_policy_launch_config_carries_network_tunnel`,
    `deny_all_policy_launch_config_stays_drop_all`,
    `worker_config_json_carries_policy_and_pins_no_tls`; implement; commit.

- [x] **T6 — No-MITM / no-semantic-protocol guard + lifecycle.**
  - Test/lint witness: the tunnel data plane links **no** TLS-MITM surface
    (`TlsTransform`, `egress_ca`, `stream_transform`) and does **not** depend on
    the `mvm-net` semantic protocol / synthetic DNS map. Confirm the forwarding
    worker (and its NAT rule) is reaped/torn down on stop exactly like `DropAll`.
  - Steps: failing tests `l3_data_plane_has_no_mitm_or_semantic_protocol_symbols`,
    `worker_stop_tears_down_nat_and_host_tun`; assert; commit.

- [x] **T7 — Live workload witness (Linux/Firecracker — ticks the Phase 2A boxes).** *(harness written; live run NOT yet performed)*
  - New `crates/mvm-cli/tests/tunnel_net_e2e.rs`, gate `MVM_TUNNEL_NET_SMOKE=1`,
    keep-failed-VM + fixed scratch (reuse the return-path harness *shape*). Run on
    the **Linux KVM host** (host TUN is Linux-only): a Firecracker workload with
    `--allow-host google.com` resolves **real** DNS, `ping` echoes over the
    tunnel, and `wget https://<host>` **succeeds with real end-to-end TLS**
    (no MITM). Capture `network-tunnel.audit.jsonl` as the witness.
  - Also added `crates/mvm-hostd/tests/host_tun_nat_live.rs` (gate
    `MVM_TUNNEL_HOST_TUN_LIVE=1` + root): a no-VM Linux witness that opens the
    real host TUN, installs the masquerade NAT, injects a crafted IPv4/UDP packet,
    and asserts teardown removes the table.
  - **Live execution still needs a Linux + libkrun host and has not yet been run;
    the three Phase 2A "Add live workload witnesses" boxes stay unchecked until a
    real workload egress run captures the audit witness.**
  - On green, check the three Phase 2A "Add live workload witnesses" boxes
    (no guest NIC / no helper drift / host-mediated egress under admitted policy)
    and record the live evidence line here.

**macOS host forwarding — LANDED (userspace `smoltcp`, not `utun`+pf).** The Linux
path (`HostTunDevice` + kernel NAT) needs `CAP_NET_ADMIN`, and a macOS `utun`+pf
equivalent needs **root** (`pfctl`) — which would force `sudo machine run`. So
macOS forwards in a userspace TCP/IP stack instead
(`mvm_hostd::smoltcp_egress`, `#[cfg(macos)]`): admitted guest flows are
terminated in `smoltcp` and bridged to ordinary *unprivileged* host sockets,
behind the same worker/gate/audit seam (Linux path untouched). Shipped: TCP
(PR #1639), UDP (PR #1647), ICMP echo via an unprivileged ping socket (PR #1650).
This closes the original macOS/HVF `bad address` repro end to end (DNS via the
`/etc/hosts` pins + echo relay), no root. Dev-grade; production hardening (perf,
non-loopback ICMP) remains follow-up.

**Landed:** the Phase 2A raw-L3 egress data plane shipped across five merged PRs —
Linux host-TUN + kernel NAT (#1634), macOS smoltcp TCP/UDP/ICMP (#1639/#1647/
#1650), and the gate packet-parser fuzz target (#1643).

**Deferred (tracked, not in this slice):** the **live workload egress witness**
(needs a Linux + libkrun host — none currently available; the three "Add live
workload witnesses" boxes above stay unchecked until a real workload run captures
the audit witness); host-side destination-bound secret egress (narrow
host-authority model, not MITM — Phase 3/P1); IPv6 forwarding
(`TunnelFeatures::ipv6`), after the IPv4 path is proven; per-flow `Credit`
backpressure consumption (frames exist, nothing consumes them yet).

### Phase 2B — builder path

- [ ] Finish the Stage 0 and builder-VM vsock egress path so the builder is a
  policy profile, not a networking exception.
- [ ] Close the remaining Linux builder smoke failures after the Stage 0
  CONNECT-over-vsock cutover.
- [ ] Remove silent qemu or guest-NIC fallback escapes from builder selection.
- [ ] Keep one explicit dev/test escape hatch only where it is named and
  operator-visible.

### Phase 2C — claim + gates

- [ ] Promote the no-guest-NIC vsock-only data plane into a claim with witnesses.
- [ ] Add CI/lint gates against new guest-NIC attach points and legacy helper
  spawn sites.
- [ ] Add `doctor` reporting that distinguishes:
  - workload transport truth
  - builder transport truth
  - unsupported legacy paths

**Primary reuse**

- Plan 227
- worktree `feat/vsock-port-handler-registry`
- worktree `worktree-vsock-only-egress-cutover`
- worktree `feat/vsock-transparent-net` for tests/evidence only

**Exit criteria**

- Workload boots and builder flows run with no production guest-NIC dependency.
- Live macOS and Linux smokes prove it.

## Phase 3 — Narrow the secret-egress feature into a product strength

**Why here:** after the transport boundary is honest, secret delivery can stay
host-owned without inheriting a packet appliance.

- [ ] Re-scope the secret-egress path to explicit host-owned authorities first:
  destination-bound HTTPS request classes before anything broader.
- [ ] Keep the placeholder-never-equals-secret invariant and audit guarantees.
- [ ] Bind every substitution to an admitted destination set and auth mode.
- [ ] Fail closed on:
  - destination mismatch
  - missing identity
  - downgrade to unsupported transport
  - protocol shapes outside the supported set
- [ ] Document what is intentionally unsupported in v1.
- [ ] Add end-to-end leak-gate tests covering:
  - guest never sees raw secret
  - audit never carries the raw secret
  - destination binding is enforced

**Primary reuse**

- ADR-067
- Plan 129
- current `mvm-substitution-endpoint`
- current `mvm-egress-proxy`

**Explicit rejection**

- [ ] Do not turn transparent TLS MITM into the default architecture.
- [ ] Do not promise arbitrary-protocol substitution before explicit authority
  routing is proven.

**Exit criteria**

- `mvm` has a production-ready, explicit, auditable secret-egress story that is
  narrower, easier to explain, and easier to defend than a transparent-net
  design.

## Phase 4 — Ship a caller-owned runtime lifecycle

**Why here:** once the runtime and transport seams are correct, the product can
feel simpler without weakening trust boundaries.

- [ ] Finish `mvm-client` S0/S1/S2 so local runtime lifecycle is driven through
  the facade rather than frontend-private logic.
- [ ] Make runtime child ownership explicit:
  - caller-owned by default
  - explicit detach when requested
  - parent-death cleanup
- [ ] Make the density path a real detached runtime shape:
  - no retained foreground CLI parent per long-lived VM
  - documented create/start/exec/stop or detached-run lifecycle for sustained
    waves
- [ ] Move sensitive runtime launch/config state off argv everywhere practical.
- [ ] Standardize one lifecycle contract across CLI and SDKs:
  - create
  - run
  - exec
  - stop
  - logs
  - inspect
  - snapshot/restore as they land
- [ ] Keep local and remote clients as couriers only; no enforcement authority
  moves into the facade.

**Primary reuse**

- Plan 204
- Plan 211
- Plan 216
- Plan 218
- branch `feat/plan-216-s0-mvm-client`

**Exit criteria**

- Local and future remote clients share one runtime contract.
- The runtime lifecycle feels developer-owned while still routing through host
  authorities and signed admission.

## Phase 5 — Add a host-only mutable runtime control plane

**Why here:** mutable runtime operations should not widen the guest protocol.

- [ ] Introduce one host-only local control socket per VM or per runtime owner.
- [ ] Move host-owned mutable operations onto that socket:
  - memory target/state
  - CPU target/state
  - secret map rotation
  - health/metrics probes
  - reconfigure hooks where permitted
- [ ] Keep the guest protocol focused on guest service requests, not host
  runtime mutation.
- [ ] Add negative tests proving guest traffic cannot invoke host-only controls.
- [ ] Align `machine reconfigure` and later warm-path controls with this socket
  instead of inventing another side channel.

**Primary reuse**

- Plan 204
- Plan 224 / 225

**Exit criteria**

- Mutable runtime state has one explicit host-only control surface.

## Phase 6 — Tighten runtime-share and filesystem semantics

**Why here:** host/guest file exchange needs the same narrowness as the network
boundary.

- [ ] Define one dedicated runtime share schema for bounded host/guest runtime
  coordination.
- [ ] Keep raw secrets off that share.
- [ ] Put quotas, ownership rules, and cleanup rules on every runtime share.
- [ ] Finish in-process rootfs materialization as the normal run path.
- [ ] Keep virtiofs-root as a deliberate tiered path with explicit integrity
  posture, not a silent production replacement.
- [ ] Document what belongs on:
  - immutable root
  - runtime share
  - explicit user volume
  - host-only state dir

**Primary reuse**

- Plan 221
- Plan 223

**Exit criteria**

- The filesystem model is as explicit as the network model.

## Phase 7 — Prove the product, not just the code

**Why last:** after the runtime shape is fixed, publish evidence and DX on top
of reality.

- [ ] Extend signed audit leadership with runtime evidence:
  - transport mode
  - secret-substitution events
  - snapshot lineage
  - health lifecycle transitions
- [ ] Publish density and helper-footprint evidence as part of runtime truth:
  - detached versus foreground process shape
  - endpoint-on versus endpoint-skipped footprint class
  - measured host-capacity guardrails before claiming high VM counts
- [ ] Split admission audit from runtime telemetry so metrics do not become
  pseudo-audit.
- [ ] Add live benchmark/proof runs for:
  - no-guest-NIC workload boot
  - no-guest-NIC builder path
  - local runtime lifecycle
  - detached high-density idle waves with honest process/RSS accounting
  - warm/health/reconfigure flows as they land
- [ ] Refresh docs so the product surface matches reality:
  - two surfaces
  - host-authority model
  - explicit secret-egress scope
  - current backend truth

**Primary reuse**

- Plan 200
- Plan 212
- Plan 232 / 233
- Plan 230

**Exit criteria**

- `mvm` can state its differentiators in a way that is both simpler and more
  defensible than the field:
  - explicit host authorities
  - audited vsock/UDS transport
  - no guest-direct upstream sockets
  - destination-bound secret handling
  - caller-owned runtime lifecycle

## Merge and sequencing rules

- [ ] Do not start broad Phase 3 secret work until Phase 2 workload truth is
  live-proven.
- [ ] Do not start broad SDK surface expansion until Phase 4 lifecycle routing
  is real on the local path.
- [ ] Do not make high-density claims from foreground or always-on-endpoint
  shapes when the product intent is detached host-authority runtime operation.
- [ ] Do not merge transparent-network experiments as the default runtime
  architecture.
- [ ] Prefer folding in-flight worktrees into the nearest matching phase over
  opening new overlapping plans.

## Success criteria

- [ ] Production `mvm` has no hidden guest-NIC dependency on the workload path.
- [ ] Builder networking is a host-mediated policy profile, not a special
  exception architecture.
- [ ] The guest has no production path for arbitrary direct upstream sockets.
- [ ] Secret egress is explicit, destination-bound, and auditable.
- [ ] The local client/runtime lifecycle is facade-driven and caller-owned.
- [ ] Mutable runtime controls are host-only and separated from guest protocol.
- [ ] The docs, sprint log, and rollup all describe the same runtime truth.
