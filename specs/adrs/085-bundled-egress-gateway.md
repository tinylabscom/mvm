# ADR-085 — The egress gateway ships inside the mvmctl artifact

**Status:** Proposed
**Extends:** [ADR-082](082-rust-native-egress-gateway.md) — from "adopt the Rust-native gateway" to "ship it in the box"
**Depends on:** [Plan 193](../plans/193-rvproxy-network-substrate.md) (substrate cutover), [Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md) (host packaging)
**Preserves:** [ADR-058](058-claim-10-bytes-leaving-trust-boundary.md) no-bypass invariant; claim 10 (default-deny egress); [Plan 129](../plans/129-secrets-subsystem.md) substitution; [Plan 141](../plans/141-vz-payload-tap-and-rust-owned-shuffle.md) flow observation

## Context

ADR-082 settled *which daemon runs at the egress chokepoint*: the Rust-native
gateway (`rvproxy`) replaces the vendored Go gateway (gvproxy) and passt, behind
a parity gate. It did not settle *how that daemon reaches the user's machine*.

Today the gateway is an install-time prerequisite. On macOS the user runs `brew
install slp/krun/gvproxy`; on Linux they install passt from the distro. That is
the same first-run friction as the rest of the Homebrew trio — except it sits at
the security chokepoint, so it cannot be made optional.

The no-bypass invariant (ADR-058) is the structural reason this matters. Tools
that lean on a VMM's built-in networking can drop the external gateway entirely;
we cannot, because every guest packet must traverse virtio-net and pass an
auditing/enforcing/substituting gateway before egress. We *must* ship a gateway.
The only open question is whether the user installs it separately or it arrives
in the box.

The gateway is now uniquely suited to bundling:

- It is a **single self-contained Rust binary we build** — no Go toolchain, no
  foreign runtime, no per-distro build like passt.
- libkrun `krun_add_net_unixgram` interop is **already proven** (ADR-082
  §Validation: `run_libkrun_gvproxy_bridge` DHCP round-trip passes with the
  gateway as `MVM_GATEWAY_BIN`, 2026-06-05).
- Its native policy / audit / substitution seams are the ones claim 10,
  Plan 129, and Plan 141 want anyway (Plan 193), so bundling it and adopting it
  are the same motion.

Bundling gvproxy (a Go binary) or passt (a Linux-only C binary) would be a
vendoring chore at the trust boundary. Bundling our own gateway is not.

## Decision

The egress gateway is distributed **inside** the `mvmctl` release artifact, not
as a separate dependency.

- The CLI resolves its gateway from the bundle by default. `MVM_GATEWAY_BIN`
  remains a development override; the flag/env surface stays generic (no project
  slug in code), per ADR-082.
- **End-state: the bundled gateway is the *sole* gateway.** gvproxy leaves the
  macOS install contract once ADR-082's macOS parity gate is green. passt remains
  the Linux fallback only until the Linux parity gate (a Plan 193 follow-on,
  explicitly out of ADR-082 Phase 1) closes.
- The bundled gateway carries claim 10 / Plan 129 / Plan 141 through its native
  policy + audit seams, not the spliced `mvm-hostd` `gateway_bridge`. The splice
  + `etherparse` scaffolding is deleted when the fallback window closes.
- `mvmctl doctor` reports the resolved gateway *source* (`bundled` / `override`
  / `legacy-tap`) on the gateway line, mirroring the `builder backend` line, so
  the in-box path is observable.

Bundling is decoupled from defaulting: the binary can be present-and-selectable
before it becomes the default. The parity gate still gates the default flip — a
regression here is a claim-10 regression.

## Sequencing

1. **Bundle present.** The gateway ships in the artifact; resolved from the
   bundle but selectable via override. Default unchanged (gvproxy/passt).
2. **macOS parity gate green** (ADR-082 Phase 1, libkrun + Vz) → flip the macOS
   default to the bundled gateway → drop gvproxy from the macOS install contract.
3. **Linux parity gate green** (Plan 193 follow-on) → drop passt → remove the
   splice/`gateway_bridge` scaffolding.

## Consequences

- One Homebrew package (gvproxy) leaves the macOS first-run path; passt leaves
  the Linux path at step 3. This is the first concrete cut into the trio.
- The gateway is version-pinned to the CLI by construction (same artifact) —
  no skew between a bundled-but-stale gateway and the CLI that drives it.
- Bundle size grows by one static binary; tracked under [Plan 156](../plans/156-binary-size-reduction.md).
- The security-load-bearing networking code (claim 10 / 129 / 141) collapses
  from a spliced reconstruction into a contract with an in-box daemon we own.

## Out of scope

- Vendoring libkrun/libkrunfw and the full relocatable dependency-free bundle —
  [ADR-086](086-relocatable-dependency-free-host-bundle.md).
- Inbound TLS (mvmd's edge, per ADR-058).
- Linux/passt-replacement parity timing (Plan 193 follow-on).
- Bring-up performance — the gateway does not own it (ADR-082 §"not a
  performance decision").

## References

- [ADR-082](082-rust-native-egress-gateway.md) — adopt the Rust-native gateway
- [ADR-058](058-claim-10-bytes-leaving-trust-boundary.md) — no-bypass invariant, claim 10
- [ADR-055](055-passt-virtio-net.md) — gvproxy / passt gateway choice
- [Plan 193](../plans/193-rvproxy-network-substrate.md) — substrate cutover
- [Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md) — host packaging
- [Plan 129](../plans/129-secrets-subsystem.md), [Plan 141](../plans/141-vz-payload-tap-and-rust-owned-shuffle.md), [Plan 156](../plans/156-binary-size-reduction.md)
