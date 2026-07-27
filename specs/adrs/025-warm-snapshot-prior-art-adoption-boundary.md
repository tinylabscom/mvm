# ADR-025: Warm-snapshot prior art — adoption boundary

## Status

Proposed. Records a design boundary for future warm-path work; nothing
in this ADR has shipped yet.

## Context

A wider survey of the fast-boot microVM space turned up a commercial
sandbox runtime that binds the host hypervisor interface directly and
runs OCI images as hardware-isolated microVMs with measured boot times in
the tens of milliseconds and cold snapshot-restore times under 100 ms on
Apple Silicon. It is the closest external proof point for the warm-boot
work mvm's own snapshot/restore and fork/fan-out design is aiming at, so
it is worth a deliberate record of what mvm takes from it and what it
refuses — because its fastest paths are built on tradeoffs mvm's security
posture forbids.

This ADR is clean-room: it records design-level learnings from public
documentation, not copied code. Nothing here vendors or links the
runtime it studies; it is inspiration, never a dependency.

Its defining techniques: driving the host hypervisor interface directly
(a layer below both of mvm's macOS backends) for tighter control over
guest memory; baking a "warmed" snapshot at image-build time whose guest
page cache is already populated, so a restored guest doesn't pay cold
page-fault cost on first access to its working set; treating a restored
image as a copy-on-write mapping of that baked snapshot, so restore
overhead stays low; an auto-scaling pool that can hand a released worker
straight back to idle *without* restoring snapshot state, keeping the
guest's page cache hot across job cycles; and routing guest network I/O
through a host-side socket-translation layer that handles ordinary
TCP/UDP transparently but has no support for raw sockets, multicast,
TUN/TAP, or ICMP.

A second, independent data point comes from an open-source AI-sandbox
offering — reviewed in `specs/research/external-sandbox-refactor-lessons.md`
and referred to here only as the open-source competitor, never by name.
It is a KVM microVM sandbox for AI agents built on the `rust-vmm`
community crates plus a self-developed, minimal-device VMM. Independently
of both mvm and the commercial runtime above, it converged on the same
warm-path shape: a per-guest kernel with a minimal virtio device set, a
pre-warmed pool that forks instances by copy-on-write clone from a
template (O(1) `FICLONE`-style clones, metadata-only/shared-extent
snapshots, incremental dirty-page memory delta), and host-side credential
injection so secrets never enter the guest. Read this as independent
validation of mvm's warm-snapshot, CoW, and host-side-secret-substitution
direction — a second team reaching the same shape under the same
constraints — not as a new idea for mvm to adopt.

The same offering is also a second, independent instance of a tradeoff
this ADR already refuses below: cross-workload guest reuse.
`specs/plans/255-vsock-first-snapshot-egress-adoption.md`, which surveys
this offering, lists reusing dirty guests across jobs among the paths it
demonstrates mvm should refuse. The research reviewed here does not
document the offering's specific reuse mechanism, so this is not the
commercial runtime's page-cache-hot, no-restore handback described above
— only the same outcome, a worker carrying prior-workload state into its
next job. A second, differently-built system converging on cross-workload
reuse under the same performance pressure reinforces this refusal rather
than calling it into question: mvm's warm path forks a paused clean
parent into a fresh, identity-scrubbed child and never resumes a parent
to continue a prior workload.

Where the offering goes further than the commercial runtime is its
egress-policy surface: a first-class L7 proxy in front of every guest,
enforcing a domain-allowlist with header-based credential injection. That
proxy is the inspiration, not the source, for mvm's own typed-connector
policy enrichment — mvm's planned scheme/host/sni/method/path/audit-level
vocabulary is mvm's own design, not a feature the offering documents. The
mechanism the offering's proxy rides on is refused either way: it depends
on terminating guest TLS transparently — a baked root CA that changes the
guest's trust model — and on a guest-NIC data plane, both refused below
under "Refuse — transparent host-socket networking" for the same reason
mvm already refuses a host-socket shortcut.

## Decision

### Adopt — page-cache priming at freeze time

When a warm-parent snapshot is taken at its ready point, prime the guest
page cache (touch the declared working set) so the snapshot captures a
warm cache, and let restore inherit that warmth. This is a refinement of
the freeze step in mvm's own warm-snapshot design, not a new mechanism —
it composes with the existing three-layer model (immutable verity rootfs
plus sealed warm overlay plus memory snapshot): page-cache warmth becomes
a property of the memory-snapshot layer, captured once at freeze, costing
nothing at child boot. This is pure upside under mvm's model because the
warmth lives inside a snapshot that is already signed, sealed, and
single-workload — nothing about admission, provenance, or the audit
chain has to change to get it.

**Scope constraint — the immutable rootfs only, never volumes, never
secrets.** A primed page cache becomes part of the memory snapshot every
forked child restores from, so priming anything mutable or sensitive
would share it across every fork. Priming is therefore confined to the
read-only, verity-sealed root volume; a declared working set that
resolves outside it is rejected. Mounted data and app-dependency volumes
are never primed into the shared base — each fork gets its own
per-instance volume disposition — and secrets never live in any volume
to begin with, since they arrive as destination-bound signed credentials
over the host broker, never as raw bytes in the guest.

### Refuse — cross-workload guest reuse

The studied runtime's fastest path reuses a dirty guest across jobs:
page cache and other in-memory state survive from one workload to the
next. That directly violates two standing invariants: one guest is one
workload (a reused guest is a multi-workload guest, which mvm's threat
model does not cover), and every workload boots from a freshly
synthesized, signed execution plan that is admitted and audited — a
worker pulled hot from a pool with prior in-memory state has no fresh
admission and carries un-attested residue across the audit boundary.
mvm's warm path is the opposite shape: fork fresh children from one
paused base, each getting its own identity (address, instance id, secrets
disk, nonce) and post-resume hygiene (entropy reseed, clock resync,
generation-id rotation). mvm adopts warm *snapshots*; it refuses warm
*guests*. The only tier where cross-cycle reuse is even conceivable is
the dev-only builder VM, a different security tier where the hardened
workload claims don't apply — and even there it is out of scope for this
ADR, needing its own decision and its own threat-model note if ever
pursued. It is never available to workload microVMs.

A second, independently-built offering also reuses dirty guests across
jobs, for the same performance reason (see `## Context` above); that
convergence reinforces this refusal, it does not soften it.

### Refuse — transparent host-socket networking

The studied runtime routes guest network I/O through a host-side socket
translation layer rather than a real virtio-net device. mvm removed the
equivalent shortcut from its own history for the same reason it refuses
to adopt one here: bypassing virtio-net means guest traffic never crosses
the auditable network bridge every byte leaving a guest is required to
traverse. This ADR does not reopen that decision; the studied runtime's
own documented limitation list for that approach — no raw sockets, no
multicast, no TUN/TAP, no ICMP — is cited here as independent supporting
evidence for the cost mvm already chose to pay by staying on virtio-net,
not as a reason to reconsider.

A second offering runs a domain-allowlist egress proxy with header-based
credential injection — inspiration for mvm's own richer typed-connector
vocabulary, not its source — but its transparent-TLS-MITM-plus-guest-NIC
mechanism is refused for the same reason as above: it would move
enforcement off the vsock seam and change the guest's trust model,
exactly what this refusal rejects.

## Out of scope

Warm-pool sizing and admission policy at the fleet level; the warmed-
parent producer's declarative warmup contract and its ready probe;
restore-correctness gaps (seccomp-on-restore, entropy reseed, clock
resync); and builder-VM warm reuse, which needs its own plan and
threat-model note if ever pursued. Each is a decision for the workstream
that owns it, not this one.

## Consequences

Page-cache priming at freeze time is a deferred follow-up on mvm's
existing warm-snapshot design; no code or schema exists yet. No security
claim changes as a result of this ADR — it is a prior-art boundary
record, not a security-claim ADR.
