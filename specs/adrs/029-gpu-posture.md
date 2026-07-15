# ADR-029: GPU posture — no GPU support today; display is a possible fast-follow, compute passthrough is out of scope

## Status

Accepted.

## Context

"GPU support" conflates two structurally different asks:

- **(A) Paravirtual display/3D GPU** — virtio-gpu plus venus/virgl,
  giving a guest GL/Vulkan against the host GPU. No dedicated device, no
  VFIO. This is what a computer-use, browser, or GUI-agent workload
  actually needs: a framebuffer with accelerated GL/Vulkan.
- **(B) Compute passthrough** — real CUDA/ROCm via VFIO, needing a
  dedicated device, breaking one-VM-per-workload density, and opening a
  hardware attack surface. Firecracker refuses this by design.

mvm is a sandboxing product; the cost of (A) is not the hypervisor, it is
one new untrusted-input parser surface — the guest-supplied venus/virgl
command stream — which must be kept away from the sealed-prod claim set
until it earns its way in.

## Decision

1. **mvm ships no GPU support today.** No backend wires a virtio-gpu
   device; the workspace has no `gpu`, `virgl`, or `venus` feature flag
   or dependency.
2. **libkrun's C API exposes paravirtual-GPU hooks** (`krun_set_gpu_options`,
   the `KRUN_FEATURE_GPU` flag) at the FFI-binding layer
   (`crates/deps/libkrun-sys`) that mvm links against but never calls.
   This is a possible attach point for (A), not a commitment to build it.
3. **If (A) is ever built, it is bound by the same posture as the
   console / interactive-access dev-tier features:** off by default;
   never linked into the sealed-prod untrusted path; libkrun-path only
   (Firecracker has no virtio-gpu device model, so GPU is never a
   Firecracker prod-tier feature; an HVF Linux-guest GPU path is
   unverified and not assumed). Promotion past the dev/computer-use tier
   requires the same fuzzing discipline every other host-side parser of
   guest-controlled bytes carries — the venus/virgl command stream is a
   new untrusted-input surface, not a free extension of an existing one.
4. **(B) compute passthrough is out of scope**, with a named reopening
   trigger rather than a silent gap: revisit only on named customer
   demand for in-VM compute *and* a workload-bearing VFIO-capable
   backend existing in the tree. Neither holds today.
5. **Beginner-facing docs never describe GPU as an available default.**
   `xtask check-machine-doc-guards` fails CI if a machine/limitation doc
   mentions GPU without marking it explicitly unsupported, future, or
   non-default.

## Consequences

No GPU work is scheduled; engineering effort goes elsewhere.

If (A) is ever built, it inherits an existing fuzzing obligation (the
new virgl/venus parser) and an existing tier rule (dev/computer-use
only, never sealed-prod) rather than needing either decided from
scratch.

(B) stays a written "no" with a concrete, checkable trigger, which keeps
it from being silently reconsidered as scope creep rather than a
deliberate decision.
