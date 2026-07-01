# ADR-102 — One VMM driver seam; backends collapse to two role runners

**Status:** Accepted (2026-06-30)
**Relates to:** [ADR-100](100-vsock-sole-guest-world-channel.md) (vsock is the sole
guest↔world channel — this ADR makes its "single host gateway" the only egress
mechanism for *every* backend), [ADR-101](101-in-house-vmm-unified-egress-substitution-gateway.md)
(the in-house VMM's unified vsock gateway — the reference shape this ADR generalizes
outward), [ADR-083](083-workload-backend-type-bar.md) (`WorkloadBackend` permission —
preserved unchanged), [ADR-093](093-linux-builder-libkrun-fallback.md) (builder auto-fallback —
preserved), [ADR-002](002-microvm-security-posture.md) (claims 10/12/13 + per-backend
tier matrix), [ADR-055](055-passt-virtio-net.md) (the gvproxy/passt gateway this
ADR removes), [Plan 214](../plans/214-clean-replacement-architecture.md) (implementation).

## Context

The backend layer carries two parallel hierarchies, and most VMMs are implemented
twice. A *runtime* backend (`mvm-backend`: `VmBackend`/`WorkloadBackend`) and a
*builder* backend (`mvm-build`: `BuilderVm`) each embed their own copy of the
VMM-driving code:

| VMM | runtime (`mvm-backend`) | builder (`mvm-build`) |
|---|---|---|
| libkrun | `libkrun.rs` | `libkrun_builder.rs` (3.8k) |
| vz | `vz.rs` (4.3k) | `vz_builder.rs` (3.5k) |
| qemu | `qemu.rs` | `qemu_builder.rs` |
| firecracker | `firecracker.rs` + `microvm.rs` (4.3k) | *(builder is never FC)* |
| in-house HVF/KVM | `hvf_backend.rs` + `vmm/` | *(none — the gap)* |

The word "backend" conflates two separable things: **VMM mechanics** (create a VM,
load a kernel, attach disks, wire vsock, boot, wait, kill) and **role policy** (a
sealed workload's claim-8 admission / claim-10 egress / claims-12/13 substitution /
write-only console, versus a builder's job staging, broad-egress nix build, and
artifact collection). Because the two are tangled in every file, each VMM is written
twice, and the cross-cutting concerns are re-implemented per backend — egress and
substitution are scattered across `substitution_spawn.rs`, `egress_redirect.rs`,
`egress_shared.rs`, the vz endpoint, and `vmm/{egress_gate,egress_proxy,substitution_bridge}.rs`.
That scatter is a defect source in its own right: a launch path that forgets to wire
the policy is the exact shape of past egress-enforcement gaps.

Two prior decisions converge to make a clean cut possible now. ADR-100 fixed that a
guest's only channel off the box is vsock, through one host gateway — there is no
guest NIC. ADR-101 realized that concretely for the in-house VMM: `vmm/` is the
mechanics, `hvf_backend.rs` is a thin (~456-line) role adapter over a single
host-side vsock egress gateway that carries claims 10/12/13 in one endpoint. The
in-house VMM already has the shape every backend should have. This ADR generalizes
it.

A vsock-only production reference design (linked in the originating discussion)
corroborates the end state: no userspace network gateway, no host packet filter — a
single vsock chokepoint is the entire egress surface.

## Decision

**1. Introduce a `VmmDriver` high seam — pure mechanics, written once per VMM.**
`VmmDriver::boot(&VmmSpec) -> Box<dyn RunningVm>`, where `RunningVm` exposes
`wait`/`kill`/`pause`/`resume`/`status`/`vsock_connect`/`balloon`/`snapshot`. The
existing `vmm/hv.rs` `HypervisorVm`/`HypervisorVcpu` traits are a *lower* seam (vCPU
registers, the run loop, HVF-vs-KVM-vs-WHP) that stays *inside* `InHouseDriver`. The
two seams do not merge: the in-house VMM is one `VmmDriver` impl that uses the low
seam internally.

**2. `VmmSpec` has no NIC.** A guest VM has exactly three I/O channel kinds:
`blocks` (storage), `vsock` (everything else), `console` (write-only — the claim-15
property). There is no virtio-net device in any backend. "Networking" is a reserved
vsock egress port; the spec carries plumbing, never a `NetworkPolicy`. The driver
therefore physically cannot enforce — or bypass — egress; it only wires the wire.
Admission state (`plan_json`, `tenant_id`) never reaches the spec, so the driver
cannot launch an unadmitted plan.

**3. Composition, not a merged trait.** The two roles become two types, each holding
a `dyn VmmDriver`:

- **`WorkloadRunner`** — the sole `impl WorkloadBackend`. Maps `VmStartConfig →
  VmmSpec`, admits the plan, spawns the one vsock egress bridge, emits audit, waits.
  `LibkrunBackend`/`VzBackend`/`HvfBackend`/`FirecrackerBackend` dissolve into it —
  they were five copies of one role policy around five VMMs. With egress uniform, the
  `EgressSubstitutionTransport` enum collapses to a single `VsockChannel` and is
  deleted.
- **`BuilderRunner`** — the sole `impl BuilderVm`. Stage job → `VmmSpec` → boot →
  build session over vsock → collect artifacts → finalize → stage0.
  `libkrun_builder`/`vz_builder`/`qemu_builder` dissolve into it; the in-house
  builder falls out for free.

The per-VMM quirks must live in the driver, not the runner — they do: snapshot
fidelity is `driver.snapshot_capability()`; console-port exposure (per-port-UDS vs
multiplexed) is how the driver presents vsock. If a quirk can't be pushed into the
driver, the seam is wrong; snapshot and console were the hard cases and both fit.

**4. One host-side `vsock_egress_bridge` for claims 10/12/13, every backend.** The
backend-agnostic `vmm/{egress_gate,egress_proxy,substitution_bridge}` are promoted
out of `vmm/` into this shared module; `substitution_spawn`/`egress_shared` fold in.
`egress_redirect.rs` (FC nftables REDIRECT), the gvproxy/passt gateway, and
`broker_services_spawn.rs` are deleted. Egress is no longer "wired once per backend"
— it is one implementation, and the only thing a backend physically provides is
vsock.

**5. vsock-only everywhere, builder NIC deleted last.** The seam ships with no `net`
field from the start. Workloads migrate to the vsock bridge first. The builder keeps
its current NIC during migration via a clearly-deprecated `BuilderNet` side-channel
that lives *outside* `VmmDriver` (so the clean seam is never polluted), then cuts over
to a localhost-forward-proxy→vsock mechanism in the guest (nix honors `http_proxy`;
binary-cache fetches are HTTP(S), so no libc/kernel interception is needed). The final
slice deletes `BuilderNet` and every slirp/passt/tap line. End state: zero NICs in the
tree, one egress chokepoint.

## Consequences

**Security posture — preserved by construction, with one hardening.** The admitted-
launch funnel (claim 8) and the `WorkloadBackend` permission (ADR-083) are unchanged
and implemented by the workload role type only; neither the driver nor the builder
role can reach the funnel. The tier matrix gets *crisper*: "qemu is Tier-2, never a
workload" becomes "there is a `QemuDriver` but no `QemuBackend: WorkloadBackend`" —
the absence of a workload-role type is the enforcement, at the type level. The
hardening: egress/substitution become one host-side codepath instead of three, so
"boot a workload" and "wire the egress gate" are the same code and cannot desync;
removing virtio-net deletes the host-side frame-parser attack surface (the gvproxy-Go
/ passt-C parsers in ADR-055's untrusted-input list) and all host nftables state — a
smaller TCB. The one witness that *moves*: Firecracker's claim-10 witness migrates
from the nftables `install_default_deny` test to the shared vsock-bridge gate test (a
catalog edit in the FC slice).

**UX — zero change.** `--hypervisor`, `--builder`, `machine run`, the doctor lines,
and `VmStartConfig` are identical. The parity gate's job is to prove no observable
behavior changed. The only second-order benefit is that a new VMM (and the HVF-
everywhere direction) ships faster and with fewer backend-specific quirks.

**DX — the primary win.** A VMM is written once (driver) instead of twice; role
policy lives in one place; cross-cutting concerns are wired once. ~20k lines of
runtime backends + ~8.5k lines of builders become N thin drivers + two runner types +
one bridge. The security-bearing role logic becomes unit-testable without a
hypervisor (see Testing).

**Migration — witness-gated slices, no flag day** (Plan 214). Old and new coexist
behind `AnyBackend`; each slice swaps one VMM's constructor to the new path, proves
parity, then deletes the old type. Order: **S0** define the seam + promote the bridge
(no behavior change) · **S1** `InHouseDriver` + `WorkloadRunner` (HVF reference proof)
· **S2** libkrun · **S3** vz · **S4** Firecracker (the careful one — egress
nftables→vsock, old path retained until proven on live KVM) · **S5** delete the five
old workload types + the transport enum · **S6** `BuilderRunner` + migrate the three
builders (in-house builder falls out) · **S7** builder vsock-egress cutover; delete
`BuilderNet` + all NICs. The risky migrations are sequenced last within each phase;
rollback is per-slice (don't swap the constructor until parity passes). This subsumes
the in-house HVF-workload and in-house-builder goals — they arrive as products of the
seam rather than a bespoke spike.

**Testing.** A `MockDriver` (sibling to `mock.rs`/`mock_guest_agent.rs`) records the
`VmmSpec` and returns a scripted `RunningVm` with a loopback vsock, so
`WorkloadRunner`/`BuilderRunner` are fully unit-tested with no hypervisor — asserting
the sealed rootfs + verity disks, the egress vsock port, the write-only console, the
audit-chain entries — on every `cargo nextest`, every platform. The single
`vsock_egress_bridge` gets one canonical suite (the existing claims-10/12/13 tests +
the vsock-framing/supervisor-config fuzz targets), backend-independent. A per-slice
parity harness drives the same input through old and new and asserts equivalence:
byte-identical `BuilderArtifacts` (the existing equality-proof gate) for builders;
same egress allow/deny verdict, audit entries (modulo timestamp/nonce), and exit
status for workloads. Live boots stay environment-gated (HVF/Vz/libkrun on macOS,
FC/libkrun on KVM, the claim-10 probe per backend, the S7 cold vsock nixpkgs fetch),
captured as runbook proofs; `xtask check-claim-catalog` keeps the witness→test mapping
honest across every slice.

## Alternatives considered

**One merged backend trait (runtime + builder behind a single interface).** Rejected:
the two roles sit on opposite sides of the security model — the workload role *must*
enforce claims 8/10/12/13, the builder role *must not* (it is Tier-2). A unified trait
means either an interface bloated with role-only methods, or a dangerous symmetry
where a future edit wires claim-10 into the builder or drops it from the workload "to
match." The concerns must not be reachable from the same abstraction. Unifying on the
*VMM* (the driver), not the *backend* (the role), gives "write a VMM once" without
that coupling.

**Keep a real builder NIC permanently (vsock-only for workloads only).** Rejected: it
keeps a `net` attachment seam on `VmmDriver`, so every VMM still implements slirp/
passt/tap — exactly the per-backend divergence this ADR removes, merely relabeled
"builder-only." A permanent exception calcifies and the net code never dies. The
staged approach (decision 5) keeps the builder working throughout yet reaches a tree
with zero NICs.

**Do nothing / share more helpers ad hoc.** Rejected: the partial sharing
(`substitution_spawn`, `egress_shared`, `audit_substrate`) already exists yet is
called separately from four backend `start()` sites; without the seam the duplication
and per-backend egress divergence persist, and the in-house VMM remains a one-off
rather than the general shape.

## Out of scope

A malicious host (the host holds the hypervisor and build keys — unchanged from
ADR-002). The in-house VMM's *lower* `hv.rs` seam and its HVF/KVM/WHP coverage —
that is ADR-101's territory and is consumed unchanged here. Multi-tenant guests (one
guest = one workload, unchanged). The auto-detect default flips toward the in-house
VMM remain gated on live verification and are not decided by this ADR.
