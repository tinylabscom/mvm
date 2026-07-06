# vsock-only egress cutover — Path A design

**Date:** 2026-07-05
**Status:** Draft (brainstorm output, pre-plan)
**Relates to:** [ADR-100](../adrs/100-vsock-sole-guest-world-channel.md) (vsock is the
sole guest↔world channel), [ADR-002](../adrs/002-microvm-security-posture.md) (claim 10),
[ADR-049](../adrs/049-secret-substitution-mechanism.md) / [ADR-059](../adrs/059-host-services-broker.md)
(claims 12/13 substitution + broker), [ADR-082](../adrs/082-rust-native-egress-gateway.md)
(in-house gateway), [ADR-083](../adrs/083-workload-backend-type-bar.md) (`WorkloadBackend`),
[Plan 214](../plans/214-clean-replacement-architecture.md),
[Step 2.3 libkrun cutover note](2026-06-29-adr100-step2.3-libkrun-cutover-plan.md).

## Goal

Make **vsock the sole egress transport for every workload guest** across all
backends, and **retire the virtio-net / userspace-gateway machinery** on the
workload path: gvproxy, passt, the in-house rvproxy, the redirect/TLS terminator,
and the FC nftables install. Egress becomes one host seam — `EgressGate` — fed by
guest→vsock streams, enforcing claim-10 default-deny and folding the claims-12/13
credential substitution onto the same path.

Separately, **close the builder VM's claim-10 gap** so its egress is policed and
recorded, without forcing `nix build` through a vsock proxy.

## Non-goals (explicit)

- **Builder VM egress does NOT move to vsock.** The builder keeps a real NIC +
  gvproxy/passt because `nix build` fans out to hundreds of parallel HTTPS/DNS/git
  fetches against binary caches; an L4 vsock proxy sustaining that is novel, risky
  ("builds break") work with a poor cost/benefit ratio for a trusted first-party
  box. The builder's *security* requirement — be tracked and monitored — is met by
  policing + auditing its existing NIC, not by changing its transport. Revisiting
  builder-over-vsock is deferred and out of scope here.
- No new inbound/listener model, no UDP/QUIC/raw-IP guest support beyond what the
  gateway already scopes. ADR-100's "inbound is a host port-forward terminated at
  the gateway" stands.
- No change to the control plane — console/exec/file-ops/secrets/broker are already
  vsock-only on every backend.

## Decision of record: "one policy, two enforcement points"

There are two distinct egress consumers with different trust and traffic profiles;
we enforce **one policy + audit model** at **two enforcement points**:

| Consumer | Trust | Traffic | Enforcement point |
|----------|-------|---------|-------------------|
| Workload guest | untrusted | low-volume TCP/DNS/TLS | **vsock → `EgressGate`** (no NIC) |
| Builder VM | trusted box running untrusted build inputs | high-volume nix fetcher fan-out | **NIC behind the packet-observer pipeline** (policed + audited) |

This is deliberately *not* "one transport everywhere." Forcing vsock onto the
builder optimizes architectural purity at the cost of the flakiest, highest-effort
work in the plan for a marginal gain (uniformity + guest-kernel surface) that does
not apply to a trusted build box. The security property the user wants — visibility
and policy on builder egress — is fully delivered by enforcement point #2.

### Consequence for "delete gvproxy/passt entirely"

Under this design gvproxy/passt do **not** reach zero survivors: they shrink to
**builder-only, and now audited**. rvproxy and the terminator **do** die (they are
workload gateways). If literal zero-survivors is later deemed a hard requirement,
that is the deferred builder-over-vsock project, taken on with eyes open.

## Current-state map (where the machinery lives)

- **HVF / in-house `vmm`** — already vsock-only, NIC-free; guarded by
  `xtask check-vsock-only-egress` (`crates/mvm-backend/src/{vmm,hvf,vsock_egress_bridge}`).
  This is the reference implementation; the shared core is `EgressGate`
  (`decide_request("ip:port") -> Allow/Deny/Malformed`, wraps `CanonicalEgress`).
- **libkrun** (`crates/mvm-backend/src/libkrun.rs`) — attaches a NIC via
  `with_gvproxy`/`with_passt`; already opens a vsock `SUBSTITUTION_PORT` host-listen
  channel for claims-12/13; threads `network_policy` to the gateway-bridge. Step 2.3
  note is the file-level plan; `EgressGate` + `mvm_vm_host::egress_server` +
  in-guest `mvm-egress-client` are already built and unit-tested.
- **Firecracker** — NIC + host **nftables default-deny** via
  `crates/mvm-hostd/src/supervisor/firewall/` (`linux_nft.rs`, `seam.rs`, `mod.rs`);
  netdev wiring via the FC bridge (`crates/mvm-vm-host/src/firecracker_bridge/`).
- **vz** (`crates/mvm-backend/src/vz.rs`) — NIC via `mvm_build::host_gvproxy` +
  `mvm-bridge` sidecar; backend is already being sunset.
- **Gateway machinery to retire (workload path):**
  - `crates/mvm-hostd/src/supervisor/gateway_bridge.rs` (4,540 lines)
  - `crates/mvm-hostd/src/supervisor/network/` (rvproxy_config/launch/policy/flow_audit,
    pipeline, packet, stages, latency, flow_count, flow_byte_log — 11 files)
  - `crates/mvm-hostd/src/supervisor/terminator/` (8 files)
  - `crates/deps/libkrun-sys/src/{gvproxy.rs,passt.rs}` — **retained** (builder needs them)
- **Packet-observer seam (Plan 141):** `network/pipeline.rs` + `network/mod.rs`
  (`Verdict`, `on_packet`), consumed by `gateway_bridge.rs`. Currently wraps the
  **workload** gateway. The **builder** spawns its own gvproxy via
  `mvm_build::host_gvproxy` and does **not** flow through this pipeline yet — so the
  builder-monitoring slice is "bring `host_gvproxy` egress under the observer +
  audit," not a one-line wiring.

## Decomposition (5 slices)

Each slice is independently shippable and independently testable. Sequence is
workload-first (lowest risk, already teed up), deletion after all workload
consumers are gone, builder-monitoring in parallel.

### Slice 1 — libkrun workload → vsock
Execute the Step 2.3 note. Delete the NIC attach (`with_gvproxy`/`with_passt`) on
the workload path; stand up the host egress server (`mvm_vm_host::egress_server`)
on a dedicated `EGRESS_PORT` UDS reusing `EgressGate`; fold claims-12/13
substitution onto the vsock path (security-touching — needs review + a live libkrun
boot). Host-side DNS via the pin registry.
**Done when:** a libkrun workload boots with no virtio-net device, egress flows
guest→vsock→`EgressGate`, claim-10 default-deny holds, claims-12/13 substitution
still works, live boot verified, and `check-vsock-only-egress` is extended to guard
`libkrun.rs`.

### Slice 2 — Firecracker workload → vsock
Delete the FC virtio-net netdev + the nftables `install_default_deny` from the
workload start path; route FC guest egress through the same vsock `EgressGate`
server. (Linux-only; validate on KVM.)
**Done when:** an FC workload boots NIC-free, egress is vsock-mediated through the
identical gate, the firewall/nft install is gone from the workload path, and the
gate is extended to guard the FC path.

### Slice 3 — vz workload → vsock (or delete vz)
vz is already sunset. Prefer **deleting the vz workload backend** outright if no
consumer remains; otherwise converge it like libkrun. Decide at slice start based
on vz's live status.
**Done when:** no vz workload path attaches a NIC — either removed or vsock-mediated.

### Slice 4 — delete the dead workload gateway code
Once slices 1–3 land and no workload consumer references them, delete
`gateway_bridge.rs`, `supervisor/network/rvproxy_*` + pipeline/packet/stages, and
`supervisor/terminator/`. Remove rvproxy config rendering + launch. Keep
`libkrun-sys/src/{gvproxy,passt}.rs` (builder). Prune dead deps + the `mvm-network`
provider surfaces no longer used.
**Done when:** `rg rvproxy crates/` returns only builder/spec hits; the workload
supervisor no longer compiles the gateway-bridge; CI green.

### Slice 5 — builder VM egress: policed + audited (NIC retained)
Bring the builder's `mvm_build::host_gvproxy` egress under the Plan 141
packet-observer pipeline (or an equivalent host seam), wire it to a builder egress
policy (default-deny-with-nix-cache-allowlist, tunable) and to the chain-signed
audit log so every builder flow is recorded. NIC stays.
**Done when:** builder egress flows are visible in the audit chain, a policy can
deny an off-allowlist destination, and `nix build` throughput is unregressed.

### Dependency graph
```
Slice 1 (libkrun) ─┐
Slice 2 (FC)       ─┼──→ Slice 4 (delete dead gateway code)
Slice 3 (vz)       ─┘
Slice 5 (builder monitoring) — independent, parallelizable, blocks nothing
```

## Security considerations

- **Claims 12/13 move transport.** Substitution shifts off the NIC onto the vsock
  path (slice 1). This is security-touching: every slice touching substitution
  needs the rejection-ladder tests re-run (denied destination, zeroize, no raw
  secret bytes on channel) plus a live boot. Execute with review, not blind.
- **Claim 10 becomes one seam.** After slices 1–4, the only workload egress
  enforcement is `EgressGate` on the vsock path — no nftables, no gateway-bridge.
  Fewer mechanisms to audit; a vsock stream cannot bypass it.
- **Builder claim-10 gap closes (slice 5).** The builder moves from "open NAT, no
  per-flow record" to "policed + audited NIC," closing the documented exception
  where claim-10 default-deny is enforced only on the two workload backends.
- **`check-vsock-only-egress` expands** its `GUARDED_DIRS` to cover each workload
  path as it converges (libkrun.rs, the FC start path), so regressions that
  re-attach a NIC fail closed.

## Testing & gates

- Per-slice: live boot (libkrun on macOS; FC on KVM), claim-10 default-deny
  positive/negative, claims-12/13 rejection ladder where touched.
- Expand `xtask check-vsock-only-egress` GUARDED_DIRS incrementally (slices 1–3).
- `cargo nextest run --workspace` + `cargo test --workspace --doc` + `cargo clippy
  --workspace -- -D warnings` + `cargo fmt --all -- --check` per slice.
- Slice 5: an audit-chain assertion that builder flows are recorded; a deny test;
  a `nix build` throughput sanity check.

## Risks / open questions

1. **Slice 1 substitution fold** is the sharpest edge — moving claims-12/13 onto
   vsock changes a security-critical path. Mitigation: it is already partly built
   and the Step 2.3 note has the file-level plan; gate on a live boot.
2. **vz fate (slice 3)** — confirm at slice start whether vz has any live workload
   consumer or can simply be deleted.
3. **Builder observer coverage (slice 5)** — `host_gvproxy` is not currently on the
   Plan 141 pipeline; scoping must confirm the cleanest way to route builder egress
   through the observer without regressing `nix build` fan-out. If that proves
   heavier than expected, fall back to a lighter-weight flow-logging shim on
   `host_gvproxy` that still feeds the audit chain.
4. **DNS host-side** — the vsock path resolves DNS via the pin registry; confirm
   coverage for the destinations real workloads use.
