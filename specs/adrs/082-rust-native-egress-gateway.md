# ADR-082 — Rust-native egress gateway replaces the vendored Go gateway

**Status:** Proposed
**Amends:** [ADR-055](055-passt-virtio-net.md) (libkrun/Vz networking via gvproxy + passt)
**Preserves:** [ADR-058](058-claim-10-bytes-leaving-trust-boundary.md) no-bypass invariant; claim 10 (default-deny egress); Plan 141 flow observation; Plan 129 egress secret substitution

## Context

On the workload backends mvm uses a userspace virtio-net gateway for guest
egress: gvproxy (gvisor-tap-vsock, a vendored Go binary) on macOS — libkrun
and Vz — and passt on Linux. ADR-055 chose this after TSI was removed for
bypassing virtio-net (ADR-058 / Plan 102 W6.A): egress must traverse the guest
network stack so the host can observe and enforce it, which TSI's syscall
impersonation defeats.

That decision is sound. The *implementation* it forces is not. gvproxy is an
opaque external binary sitting at the security chokepoint, and everything we
need from that chokepoint has to be bolted on around it:

- **No native flow/packet API.** gvproxy emits no flow events, so claim 10
  enforcement and Plan 141 auditing splice its unixgram socket in-process
  (`mvm_hostd::supervisor::gateway_bridge`, `VzGvproxy` splice) and re-parse
  frames with etherparse. The enforcement seam is reconstructed *outside* the
  daemon from raw bytes.
- **Uncontrollable logging.** gvproxy logs client-disconnect at error level on
  every VM teardown; with the supervisor's inherited stdio those lines leak to
  the operator console (no sidecar for the Stage 0 path). We cannot change a
  vendored binary's log discipline.
- **Hidden tuning.** Transport parameters (MTU, buffer sizes) are not surfaced
  through our spawn path; we pass `-listen-vfkit`, `-log-file`, `-ssh-port` and
  take the defaults.
- **A foreign binary inside the trust boundary.** ADR-002 trusts the host, but
  a Go dependency carrying every guest's egress is the largest unaudited
  surface in the substrate, and it cannot be reviewed or fuzzed the way the
  rest of the host path is.

Separately, an in-house Rust-native gateway daemon now exists that occupies the
same position as gvisor-tap-vsock: it binds a control API, accepts a VM
transport session (VZ/vfkit, Firecracker on `/dev/kvm`, host-local QEMU over
`qemu-unix`), runs a guest-network dataplane, and exposes a typed, plugin-aware
byte pipeline. Its seams map directly onto what we currently bolt onto gvproxy:

| mvm requirement (today, bolted onto gvproxy) | native seam in the Rust gateway |
| --- | --- |
| Plan 141 in-line flow observer (splice + etherparse) | byte-traffic observer plugin — `Inspector` / `SinkExporter` / `DecisionEmitter` classes with a typed `PluginDecisionSink` |
| Claim 10 `PlanFlowPolicy` deny-by-default gate (`gateway_bridge`) | `PolicyEngine` / `PolicyDecision` in the gateway's policy crate |
| Plan 129 egress secret substitution / name-constrained CA termination | secret-redaction + byte-replacement transform plugins |
| MTU / transport tuning (unsurfaced) | first-class `mtu` config field; owned transport layer |
| Vendored Go binary in the trust boundary | reviewable, fuzzable in-repo-family Rust crates |

## Decision

Adopt the Rust-native gateway as the egress gateway for the workload backends,
replacing the vendored Go gateway. Do it as a flag-gated, parity-tested
migration — the playbook used for the Swift→Rust supervisor cutover (Plan 152),
not a blind swap of the security seam.

- Add an `Rvproxy` variant to `NetworkingPreference` (`MVM_NETWORKING=rvproxy`).
  gvproxy/passt remain selectable until the parity gate passes.
- The native gateway must terminate the **same** `-listen-vfkit` unixgram
  protocol libkrun (`krun_add_net_unixgram`) and Vz (vfkit) already speak, so
  the backend dispatch (`apply_networking`, `host_gvproxy`) changes only which
  daemon it spawns.
- Claim 10 enforcement moves from the spliced `gateway_bridge` onto the
  gateway's native policy engine + decision sink. **The no-bypass invariant
  (ADR-058) is non-negotiable**: every guest packet still traverses virtio-net
  and passes the policy gate before egress; the gate is deny-by-default; a
  dropped flow is audited. The migration changes *where* enforcement runs (in
  the daemon vs. spliced beside it), never *whether* it runs.
- Logging and lifecycle become ours: structured logs to a sidecar, clean
  teardown, no console leak.

## Migration plan (parity-gated)

1. **Wire the flag.** `Rvproxy` variant + `apply_networking` dispatch + spawn
   path; daemon behind `MVM_NETWORKING=rvproxy`, default unchanged.
2. **Connectivity parity.** Builder + Stage 0 cold build over the Rust gateway
   reaches cache.nixos.org and completes byte-identical artifacts on libkrun and
   Vz. (Linux/passt parity tracked separately.)
3. **Enforcement parity.** Port the claim 10 witnesses
   (`policy_default_is_deny_all`, the gateway-bridge flow-drop tests) onto the
   native policy engine; assert deny-by-default + audited drops on the new path.
   Port the Plan 141 observer and Plan 129 substitution tests.
4. **Parity gate.** A CI lane runs the claim-10 / flow-audit / substitution
   suites against both gateways and asserts identical verdicts before the
   default can flip — mirroring Plan 152's boot-parity gate before deleting
   Swift.
5. **Flip the default** per-OS, keep gvproxy/passt one release as fallback.
6. **Remove the vendored Go gateway** and the splice/etherparse scaffolding once
   the gate is green and the fallback window closes.

## Consequences

**Gains:** the egress seam becomes owned, typed, reviewable, and fuzzable;
claim 10 / Plan 141 / Plan 129 become first-class instead of reconstructed from
spliced bytes; logging, teardown, and MTU come under our control; one fewer
foreign binary in the trust boundary (aligns with ADR-002 and the
limit-dependencies posture).

**Costs / risks:** the gateway is the security chokepoint — a regression is a
claim-10 regression, which is why the parity gate gates the default. Two
gateways coexist during migration. The Rust gateway's current signed-off scope
is VZ/vfkit, Firecracker on `/dev/kvm`, and host-local QEMU. libkrun-unixgram
interop is **already proven** (see §Validation); Linux/passt-replacement
parity remains an open item (below), not assumed.

**Explicitly not a performance decision.** This does not target bring-up time.
Cold bring-up is dominated by source compilation (kernel + guest agents),
not the gateway; gvproxy carries only the cold download leg and warm builds are
a cache hit. The kernel prebuilt + store persistence own bring-up speed. The
Rust gateway *enables* future transport tuning (MTU), but speed is not the
justification and must not be used to wave the parity gate through.

## Validation

- **libkrun `krun_add_net_unixgram` interop — proven.** The gateway implements
  the vfkit unixgram listener (SOCK_DGRAM, the `VFKT` handshake datagram, one
  ethernet frame per datagram with no length prefix, the `-listen-vfkit
  unixgram://` flag surface). mvm's own libkrun acceptance gate —
  `run_libkrun_gvproxy_bridge`, the DHCP `DISCOVER → OFFER` round-trip through
  the bridge — passes with the gateway binary as `MVM_GATEWAY_BIN` (verified
  unsandboxed, 2026-06-05). So the first macOS cutover covers **both** libkrun
  and Vz, not Vz-only. This closes the migration's largest risk before any code
  lands in mvm.

## Open questions

- **Linux/passt.** Does the Rust gateway replace passt on Linux too (one gateway
  everywhere), or is the first scope macOS-only with passt retained on Linux?
- **mvmd coupling.** mvmd consumes the gateway audit substrate; the typed
  control API is an opportunity to formalize that contract — needs mvmd input.

## Out of scope

Bring-up performance (kernel prebuilt / store persistence own it). Inbound TLS
(mvmd's edge, per ADR-058). The Firecracker nftables egress path (unchanged;
this ADR is the userspace-gateway substrate only).
