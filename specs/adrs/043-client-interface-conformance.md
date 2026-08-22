# ADR-043: Conforming to a client interface mvm did not invent

Backing: preview
Validation: none — this ADR proposes a decision and is enforced by nothing

## Status

**Proposed.** This ADR frames a decision; it does not take one. Nothing in it
is implemented, and the recommendation at the end is to build the narrow
variant and refuse the broad one.

## Context

Every verb mvm exposes is a verb mvm invented. `mvmctl machine run`,
`mvmctl build image`, `mvmctl template build` are coherent and
self-documenting, and they are also entirely unfamiliar: a team evaluating mvm
must learn a new noun set before they can run anything, and none of their
existing tooling can drive it at all.

The prompt for writing this down was an outside read of an edge-inference
runtime whose CLI serves an HTTP API it did not design. Because that API is the
one clients in its domain already speak, every existing client works against it
unmodified and the adoption cost of the runtime is approximately zero. The
runtime kept its own engine and conformed only at the wire.

The analogous move for mvm is to speak an interface that orchestrators and
developer tooling already emit, while continuing to boot exactly the microVMs
it boots today. The engine does not change; only the protocol at the edge does.

This is worth stating precisely because it is *not* the decision the project
already made and reversed.

## What this is not

**ADR-034 introduced a Docker-backed dev tier. Plan 329 retired it and removed
the implementation.** The retirement rationale is directly relevant here:

> The existence of a Docker-backed tier created brand confusion between
> containers and microVMs, carried a large host-privileged code path, and
> diluted MVM's core value proposition of hardware-isolated per-workload
> kernels.

That decision was about a **backend** — where the workload actually runs. A
shared-kernel container is not a microVM, cannot carry the hardware-isolation
claims, and had to go.

What this ADR raises is a **client interface**, not a backend. The workload
would still boot on Firecracker, libkrun, or HVF, behind a hardware boundary,
under a signed `ExecutionPlan`, with the same claims intact. Only the shape of
the request arriving at the front door changes.

That distinction is real. It is also **not a complete answer to ADR-034**, and
this ADR should not pretend otherwise: the brand-confusion half of the
retirement rationale partially survives the distinction. An interface whose
vocabulary is containers invites the reader to conclude mvm is a container
runtime — which is exactly the confusion Plan 329 paid code deletion to remove.
A compatibility surface can be technically honest and still be positioned
badly.

## Constraints any implementation inherits

These are not negotiable and are the reason this needs an ADR rather than a
plan.

1. **One admission path.** Claim 8 holds because every workload boots from a
   signed, audited `ExecutionPlan` through `admit_for_run`. A conformance
   surface must *synthesize a plan and go through that admission*, not around
   it. A second entry point that reaches a backend without admission does not
   weaken claim 8, it voids it.

2. **One egress decision point.** Claim 10 holds because the per-VM network
   endpoint's shared `EgressGate` is the sole decision point, and `xtask
   check-single-network-path` pins Firecracker, libkrun, and HVF to one spawn
   site and rejects a second workload socket owner. A conformance surface
   must inherit that seam verbatim. Any request field that appears to configure
   networking must resolve to a policy the existing gate evaluates, or be
   refused.

3. **The funnel is `AnyBackend::as_workload_backend`.** It returns `Some` for
   Firecracker, libkrun, HVF, Wasm, and Apple Container, and `None` for QEMU.
   A conformance surface routes through it and inherits that refusal rather
   than reimplementing backend selection. (Note for readers working from
   `CLAUDE.md`: that file still lists Wasm among the barred tiers. It is not —
   Wasm is a real workload backend, claim-free, mediating egress to the same
   substitution endpoint. The code is right and the prose is stale.)

4. **Unmappable fields fail closed.** A foreign interface carries a large
   surface mvm has no equivalent for — privileged mode, host mounts, host
   networking, capability grants, device passthrough. Every one of those must
   be refused with a named reason. Silently ignoring a security-relevant field
   because mvm "doesn't do that anyway" produces a caller who believes they
   requested an isolation posture they did not get. This is the single largest
   source of risk in the whole idea and it is a *specification* problem, not an
   implementation one: the refusal list has to be enumerated up front.

5. **No claim inherits by proximity.** The surface documents which claims hold
   for workloads admitted through it. It does not restate the claims ledger.

## Options

**A — Full container-API compatibility.** Broad surface, immediate familiarity,
existing tooling drives mvm unmodified. Largest refusal list, largest ongoing
compatibility burden, and it walks straight into ADR-034's brand-confusion
objection with the word "container" in the interface name.

**B — Narrow, explicitly-scoped run surface.** A small HTTP or socket API
covering exactly the operations mvm already performs — admit a workload from an
image reference, stream its output, stop it, report status — using the
vocabulary of the thing mvm actually is. Conforms to the *shape* callers expect
(an API rather than a CLI) without borrowing a vocabulary that misdescribes the
boundary. Much smaller refusal list because the surface never offers the fields
that would have to be refused.

**C — Do nothing.** The CLI stays the only entry point. Zero risk, and the
adoption cost stays where it is.

## Recommendation

**Option B, and an explicit refusal of Option A.**

Option A's value is real but it is borrowed familiarity, and the thing being
borrowed is a vocabulary that describes a weaker boundary than the one mvm
provides. mvm spent a plan removing that confusion. Reintroducing it at the API
layer weeks later, for adoption convenience, trades the project's clearest
differentiator for a shortcut.

Option B captures most of the adoption benefit — the complaint is usually "I
can't drive this from my service" rather than "I can't drive this with one
specific client" — while keeping the refusal list small enough to enumerate
honestly.

If Option A is later chosen anyway, it must arrive as its own ADR that
confronts Plan 329 directly, not as an extension of this one.

## Consequences

- No implementation begins until this ADR is Accepted with an option chosen.
- Whichever option is chosen, constraint 4's refusal list is written and
  reviewed **before** any endpoint exists, because it is where the security
  argument lives.
- If Option C, the adoption gap should be closed by documentation and SDK reach
  instead, which is cheaper and carries none of this risk.
