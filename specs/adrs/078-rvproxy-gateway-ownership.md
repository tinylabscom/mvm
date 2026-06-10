# ADR-078 — First-party virtio-net gateway ownership via rvproxy

**Status:** accepted 2026-06-10. Implemented by
`specs/plans/179-rvproxy-gvproxy-replacement.md`. **Amends ADR-055** (the
`gvproxy` backend remains the macOS/libkrun networking shape, but its
implementation no longer has to be upstream `gvproxy`) and extends the
claim-10 no-bypass posture in ADR-058 and the network-provider seam in
ADR-064.

## Context

`mvm` currently claims a high degree of control over the runtime, builder, and
network-policy surface. That claim is materially weakened on the macOS/libkrun
path by one remaining third-party runtime dependency: the per-VM virtio-net
gateway binary spawned from
`crates/deps/libkrun-sys/src/gvproxy.rs`.

Today the architecture is already close to what we want:

- `mvm` owns VM lifecycle, per-VM supervisor processes, and backend selection.
- `mvm` owns the gateway audit bridge and policy seam in
  `crates/mvm-hostd/src/supervisor/gateway_bridge.rs`.
- `mvm` intentionally removed TSI and requires a real virtio-net gateway on
  both builder and workload libkrun paths (`passt` on Linux, `gvproxy` on
  macOS) so claim-10 mediation always has a host-visible seam.

The remaining gap is that macOS/libkrun guest egress is still implemented by
an external Go binary whose lifecycle and feature surface `mvm` does not own.
That creates four problems:

1. the product claim "we own the runtime and network plane" is not literally
   true on that path;
2. `gvproxy` imposes behavior `mvm` does not want, most notably a mandatory
   SSH-forward port;
3. the gateway implementation is outside the repo's normal auditability and
   iteration loop;
4. `mvm` and `rvproxy` now already share a proven compatibility seam, so
   continuing to defer ownership no longer buys much.

`rvproxy` exists specifically to close that gap. It already proves the
unchanged `mvm` gvproxy-compatibility gate on the vfkit/unixgram transport
shape, DHCP round-trip, and daemon lifecycle contract.

## Decision

Adopt `rvproxy` as the **first-party implementation** of the macOS/libkrun
`gvproxy` gateway contract, while preserving the existing `mvm` architecture.

This is a **gateway implementation replacement**, not an architecture rewrite.
`mvm` keeps:

- the per-VM supervisor model;
- the audit/policy bridge as the claim-10 mediation seam;
- the existing builder/runtime gateway-selection flow;
- the `NetworkingPreference` model (`passt` on Linux, `gvproxy`-shaped
  unixgram gateway on macOS).

The practical meaning of "replace gvproxy" is:

1. `mvm` gains an explicit production gateway-binary override for the
   macOS/libkrun `gvproxy` path.
2. `rvproxy` is run in **gvproxy-compatible mode** as a constrained per-VM
   daemon behind that seam.
3. The integration target remains the current CLI + vfkit/unixgram + DHCP
   contract, not a new control API.
4. The first rollout target is **macOS/libkrun only**. Linux `passt` remains
   unchanged unless a later ADR deliberately broadens scope.

## Why this shape

### Preserve the seam `mvm` already got right

The key architectural fact is that `mvm` already treats the gateway as an
implementation behind a stricter seam:

- the libkrun launcher spawns a per-VM gateway and waits for a socket;
- the bridge sits between guest virtio-net traffic and that gateway;
- policy/audit stays in `mvm`, not in the gateway.

That means we do not need a larger redesign to gain ownership. Replacing the
gateway binary at that seam is enough.

### Ownership without over-coupling

`rvproxy` becomes first-party runtime code, but not the place where
`mvm` centralizes plan admission or control-plane logic. The host-side trust
boundary stays where `mvm` already places it: supervisor + bridge + vsock
broker, with the gateway as a narrowly-scoped egress dataplane component.

### Surface reduction, not expansion

In compat mode `rvproxy` can accept `-ssh-port` without binding a real SSH
listener and can avoid exposing its broader local API/control surface. That
improves the current posture rather than widening it.

## Security posture

This decision does not reduce the claim-10 posture. It changes who owns the
gateway implementation, not where mediation occurs.

Security effects:

- **Improved ownership:** the guest egress gateway on macOS/libkrun becomes
  first-party Rust code in the same engineering loop as the rest of the
  runtime.
- **No-bypass preserved:** all traffic still traverses the existing bridge
  seam; `rvproxy` is not allowed to bypass the supervisor or short-circuit
  policy.
- **SSH surface reduced:** unlike upstream `gvproxy`, `rvproxy` does not need
  to bind a meaningful SSH-forward listener just to satisfy CLI compatibility.
- **Control-plane surface constrained:** `mvm` must run `rvproxy` in its
  gvproxy-compat mode with no separately exposed local API.

What does not change:

- guest↔host control traffic remains on the existing `mvm` channels (not a new
  `rvproxy` control plane);
- Linux `passt` remains a separate external dependency until deliberately
  revisited;
- upstream parser/runtime bugs are replaced by first-party parser/runtime bugs,
  so the maintenance burden moves in-house.

## Consequences

- `mvm` can make a much tighter claim that it owns the macOS/libkrun runtime
  and network plane end-to-end.
- The builder VM and workload VM networking paths stay aligned because both
  already share the same `resolve_networking_mode()` seam.
- The integration can land incrementally because `rvproxy` already targets the
  exact contract `mvm` invokes today.
- The product claim must still be scoped honestly: adopting `rvproxy` on the
  macOS/libkrun seam does **not** mean `mvm` owns every network backend
  everywhere until Linux `passt` is addressed separately.

## Alternatives considered

- **Keep upstream `gvproxy` indefinitely.** Rejected. It keeps the weakest
  point in the "we own the plane" story and preserves behavior `mvm` does not
  want.
- **Rewrite `mvm` around an `rvproxy` control API.** Rejected for now. Too much
  churn for the immediate ownership win; the current seam is already good.
- **Replace Linux `passt` and macOS `gvproxy` together.** Rejected as the first
  step. It broadens scope and risk unnecessarily.
- **Vendor upstream `gvproxy` into `mvm`.** Rejected. It increases ownership of
  packaging, not of the gateway implementation or feature direction.

## Out of scope

- Replacing Linux `passt`.
- Changing the vsock control-plane architecture.
- Broadening `rvproxy` compat mode into the future `mvmd` control surface.
- Windows or broader all-backend network-plane unification.
