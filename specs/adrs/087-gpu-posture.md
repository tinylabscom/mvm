# ADR-087 — GPU posture: paravirtual display GPU is a deferred fast-follow; compute passthrough is out of scope

**Status:** Accepted
**Relates to:** [ADR-002](002-microvm-security-posture.md) (tier matrix, out-of-scope discipline); [Plan 60](../plans/60-mvm-libkrun-migration.md) Phase 7b (`gpu-virgl` scaffold); [Plan 111](../plans/111-cardoso-gap-coordination.md) Workstream D (GPU deferral); [Plan 37](../plans/37-whitepaper-alignment.md) (`GpuRequirement` enum stub)
**Does not gate:** [ADR-085](085-bundled-egress-gateway.md) / [ADR-086](086-relocatable-dependency-free-host-bundle.md) — the host bundle ships without GPU

## Context

A competing sandbox tool leads its marketing with "Vulkan access to the host
GPU." That raised the question of whether mvm must ship GPU support to be
competitive, and whether our security model makes it prohibitively expensive.

The question conflated two unrelated features with different cost structures:

- **(A) Paravirtual display/3D GPU** — virtio-gpu + venus/virgl, giving the guest
  Vulkan/GL against the host GPU. No VFIO, no dedicated device, no Cloud
  Hypervisor requirement. libkrun supports it; Plan 60 Phase 7b already scaffolds
  it behind an off-by-default `gpu-virgl` flag. This is what the competitor
  actually ships (render / GUI / computer-use demos).
- **(B) Compute passthrough** — real CUDA/ROCm via VFIO. This is the one
  Firecracker refuses by design, that needs the Cloud Hypervisor path, that
  breaks one-VM-per-workload density and opens a hardware attack surface. The
  competitor does **not** ship this.

mvm is a sandboxing product. The fastest-growing relevant use-case —
computer-use / browser / GUI agents — needs (A), a framebuffer with GL/Vulkan,
not (B). The "we'll lose without GPU" framing applied to (B); it does not survive
the disambiguation.

The cost of (A) is not the hypervisor — it is **one new untrusted-input parser
surface** (the venus/virgl command stream the guest writes), which must be kept
away from the sealed-prod claim set.

## Decision

1. **(A) is a deferred fast-follow, not a launch requirement.** The host bundle
   (ADR-085/086) and the `machine`/pack UX ship first; the security substrate is
   the moat and the GPU demo is a fast-follow. GPU does not gate launch.

2. **When (A) lands, it is a dev / computer-use tier feature**, modelled exactly
   like `console` and `do_exec`:
   - off by default;
   - **never linked into the sealed-prod untrusted path** (a sealed prod agent
     has no GPU device, the same way it has no console — claims 1–15 unaffected);
   - **libkrun-path only.** Firecracker has no virtio-gpu (so GPU is not a
     Firecracker prod-tier feature); the Vz Linux-guest Vulkan path is unverified
     and not assumed. "GPU ⇒ libkrun" is the routing rule.

3. **(A) stays out of the default zero-dependency bundle.** venus needs a host
   Vulkan userspace present, which fights ADR-086's zero-dep promise. GPU is an
   opt-in add-on component with its own `mvmctl doctor` probe; it must not
   reintroduce a brew-trio-style first-run dependency into the core install.

4. **(B) compute passthrough is out of scope**, deferred with an explicit
   trigger rather than left as a silent gap: revisit only on **named customer
   demand for in-VM compute *and* a matured Cloud Hypervisor backend**. Until
   both hold, mvm does not do VFIO GPU passthrough.

## Consequences

- Launch is not blocked on GPU; engineering spend goes to the bundle + UX moat
  first.
- (A) is cheap when scheduled — flip an already-scaffolded flag on the libkrun
  path — but carries one obligation: the venus/virgl parser is a new fuzz target
  if GPU is ever proposed for anything beyond the dev/computer-use tier. Any such
  promotion is a separate ADR-002 amendment (new claim + parser fuzzing), and is
  expected to be resisted.
- The `GpuRequirement` enum (Plan 37) and Plan 60 Phase 7b scaffold remain valid;
  this ADR sets their posture and tier, it does not schedule the work.
- (B) being a written, trigger-gated "no" keeps it from resurfacing as an
  unscoped panic; the trigger is the place to reopen it.

## Out of scope

- Scheduling (A) — that is a plan/sprint decision once the bundle and UX ship.
- VFIO / compute passthrough mechanics — gated behind the (B) trigger above.
- Inbound TLS, networking, and packaging — covered by their own ADRs.

## References

- [ADR-002](002-microvm-security-posture.md) — security posture, tier matrix, out-of-scope discipline
- [ADR-085](085-bundled-egress-gateway.md), [ADR-086](086-relocatable-dependency-free-host-bundle.md) — the bundle GPU does not gate
- [Plan 60](../plans/60-mvm-libkrun-migration.md) — Phase 7b `gpu-virgl` scaffold
- [Plan 111](../plans/111-cardoso-gap-coordination.md) — Workstream D GPU deferral
- [Plan 37](../plans/37-whitepaper-alignment.md) — `GpuRequirement` enum
