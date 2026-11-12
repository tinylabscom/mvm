# ADR-059: Typed policy authoring across SDKs

Backing: preview
Validation: none

## Status

**Accepted direction. Launch integration not implemented.** The owner chose full policy-profile
composition for Rust, Python and TypeScript, in that order, without a legacy SDK
policy surface. The owner also confirmed [#5115](https://github.com/tinylabscom/mvm/issues/5115):
MVM does not manage named guest or Layer 7 tools. This ADR specifies the model
and its security boundary, not a claim that SDK-authored policies can already
be launched. The tool-removal work landed before the SDK policy schema was
regenerated; launch must still enforce every exposed dimension.

## Context

Policy is a core product feature, but SDK launch options currently expose
individual egress destinations and a `profile` string that names a *security
tier*, not an authored policy. The CLI already has structured policy documents:
groups, profiles with `extends`, group selection, platform-conditional `when`
blocks, and a body covering network, secrets, shares, environment and resource
ceilings. Named-tool policy was retired under #5115; the SDK must not
reintroduce it. The host resolves policy under the documented composition
rules and lowers the result into a signed execution plan.

A loose JSON parameter, or independent policy implementations in three SDKs,
would let authoring and enforcement drift apart. A policy that appears accepted
by an SDK but is ignored at launch is a security failure.

## Alternatives

1. **Keep only named file references.** Reuses CLI policy resolution, but does
   not let SDK users construct a policy as structured program data. Relative
   files also introduce an implicit, mutable dependency at machine restart.
2. **Expose only typed direct rules.** Makes simple launches easy but cannot
   express the reusable groups, inheritance and conditional overrides available
   to CLI authors. Rejected as a second-class policy interface.
3. **One canonical typed authoring model, with native SDK surfaces.** Chosen.
   Costs more cross-language schema and host-library work, but preserves one
   policy language and one resolver.

## Decision

### Model

The authored contract has three document shapes: a reusable **group**, a
**profile** that composes other profiles and groups, and a **body** containing
rules. Preserve the existing profile semantics: ordered `extends`, group
include/exclude (including required groups), conditional `when` blocks for
host OS, architecture and backend, and profile overrides. The body covers all
five system-level dimensions: network, secrets, shares, environment and
resources. Named-tool allow/deny/ask, executable maps and tool-scoped routes
or credentials are not policy fields. Reject old `[tools]` input explicitly
rather than silently dropping a restriction. A direct body is a profile with
no parents or groups, not a separate kind of policy with different merge rules.

Rust owns the serializable, versioned authored-policy schema. Reuse the existing
`PolicyBody`, `GroupFile` and `ProfileFile` concepts; put data-only contract
types where both Rust authoring and host resolution can use them without a
dependency cycle. Keep file loading, platform detection, composition and
enforcement in the host-side resolver. Generate the Python and TypeScript
contract types from the same Rust schema, then expose small native authoring
conveniences around those types. Numeric limits and endpoints should have typed
SDK inputs; pattern expressions remain patterns, not unrestricted JSON values.
Unknown fields, unknown variants and unsupported restrictions are errors.

An SDK launch takes an authored policy/profile value or an explicit policy
reference. It does not reuse the security-tier `profile` parameter: the latter
is a separate concept and should have an unambiguous name in the new API. Do
not maintain parallel legacy `allow_hosts`/egress policy knobs alongside the
structured launch policy; make one authoritative path from policy input to
admission. The CLI's existing policy documents and resolver remain part of that
path, not a second implementation.

### Resolution and authority

The SDK may validate local structure for fast feedback but cannot declare a
policy effective. The host parses the authored contract, resolves references
and provenance, applies the existing deny/ceiling/grant precedence, validates
the requested permissions against host and signed application constraints,
then signs and admits the resulting plan. A failure at any stage refuses the
launch; unsupported enforcement is never silently downgraded.

Expose a read-only effective-policy result with the applied layers, decisions,
reasons and plan/policy identity for inspection. It is an output, never a
launch input. Preserve the distinction between a host-owner grant, a package
request, and a ceiling: a package cannot grant itself access by authoring a
policy. An SDK must not promise enforcement of a dimension on a launch path
that does not actually enforce it.

### References and persistence

Reference resolution is host-owned and respects each source's trust origin.
For an inline profile, a relative file reference has no implicit directory:
either an explicitly supplied, validated source base resolves it or the host
rejects it. A signed package cannot import an arbitrary user-local policy.

A persistent machine stores the authored policy and the exact resolved
user-authored dependencies (with their identities/digests), not just the
effective permissions or live paths to mutable files. Each start rechecks
current host constraints and signed application bounds and admits a fresh
signed plan. Changing an authored dependency or widening previously admitted
permissions requires an explicit policy update/re-admission; a file edit or
relaxed host default must not silently widen a stopped machine on restart.
Host constraints may always tighten or refuse a restart.

Host-directory shares are snapshotted when registered or created, not read
again on restart. CLI and SDK paths refresh only on an explicit update after
the machine stops. Guest writes stay inside a private writable snapshot and
never reach the host directory; replacing a writable snapshot requires an
explicit acknowledgement that guest writes are discarded. Boot reads the
pinned snapshot without scanning the host source. A read-only image is
digest-verified before admission; that still reads image bytes at start, so
measure restart latency rather than assuming the verification is free.

`env.readmit` is an exact-name, user-authored exception applied at every
host-mediated guest process launch, never an implicit inheritance of the
host's environment. A sealed production guest refuses it even if no initial
command happens to use the name; development posture must be explicit.
Host, organization, and signed application denies still take precedence.
Audit variable names and decisions, never values.

## Boundaries and risks

- The current in-process machine launch and host-library request do not carry
  authored profiles. They must route the new input through the shared resolver
  and signed-plan admission before any SDK can advertise this feature.
- The SDK-authored schema contains no `ToolsSection`; keep its generated
  bindings in sync with the shared Rust contract as policy rules change.
- Existing policy-schema generation covers file documents, but the SDK/host
  transport needs a versioned, closed contract and generation checks across
  Rust, Python and TypeScript. The transport encoding is not the public SDK API.
- Source-relative shares, `extends` and group paths need an explicit origin
  when authored inline; packaging their transitive dependencies for persistent
  machines is the highest-risk part of this design.
- The effective-policy view must describe *enforced* behavior, including
  backend-specific unsupported capabilities, rather than presenting authored
  intent as a guarantee.

## Single-host capacity requirement

The target is 600–1,000 **concurrently running, working microVMs** on a
suitably provisioned host, not merely 1,000 stored agent identities with a
small active subset. Each VM may process mailbox events later, so event
delivery needs bounded per-recipient queues, ordering and backpressure rather
than an immediate response from every guest. Parking truly idle sessions is
useful beyond this target but does not count toward it.

Density is the normal launch path, not an alternative security profile.
Isolation and per-VM signed grants remain intact. Admission must account for
actual host memory and helper-process capacity; a host that cannot safely run
the requested set queues or refuses excess work rather than promising 1,000
running VMs on arbitrary hardware. The present 512 MiB SDK default, per-VM
rootfs byte-copy fallback on non-reflink filesystems, and one mailbox helper
process per granted VM are capacity risks to measure and address. A mailbox
is a scheduling and delivery primitive, not a way to share guest memory.
Do not claim the target until simultaneous-workload tests measure guest and
host memory, allocated disk blocks, process/descriptor counts, launch rate
and mailbox delay on representative Linux and macOS hosts.

## Launch gate

The Rust resolver can now capture an inline profile and the exact bytes and
SHA-256 digest of every file-backed dependency it parsed, including groups
subsequently excluded. This is an in-memory capture, **not** a persistent,
authenticated policy snapshot. Neither a digest stored beside its source nor
a resolved body in `machine.json` alone can authorize a restart.

Before adding `policy` to any SDK launch request:

1. Admit the resolved policy under current host, organization and signed
   application bounds, and represent its enforceable network/routes, secrets,
   shares, environment/readmission and resource decisions in the signed plan.
   Hostd must reject any dimension it cannot project to the actual backend
   configuration and its runtime gates.
2. Store authenticated authored input and captured dependencies for persistent
   machines; restart must re-admit them without reopening mutable user policy
   files. Changing those inputs requires an explicit policy update. Share
   snapshots have their own explicit refresh and private writable lifecycle.
3. Check environment admission against the signed decision at *every*
   host-mediated process start, not only the initial command. `env.readmit`
   remains unavailable to sealed production workloads.
4. Exercise the same composed policy from Rust, Python and TypeScript through
   the real host-library launch and a persistent restart. Only then expose the
   three launch parameters and effective-policy inspection surface.

The smallest de-risking check is one profile with inheritance, a required group,
a conditional override, a deny and a resource ceiling, authored in Rust and
round-tripped through both generated language contracts. Resolve it on the host,
compare the effective policy and signed plan across all three inputs, then
restart a persistent machine after modifying a referenced file and after
tightening host constraints. Accept the design only if all three languages get
the same decision and neither restart silently widens it.
