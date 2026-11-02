# ADR-058 — Competitive posture: trust-first over product parity, and the prior-art boundary

Backing: preview
Validation: none

**Status: Accepted**

## Context

On 2026-11-02 we carried out a source-level comparison of this stack against a
competing hosted microVM platform. The competitor ships a local engine CLI, a
hosted multi-tenant service, and an SDK for both. We read its published
documentation in full and inventoried this repository and the sibling
control-plane repository at source level.

The comparison was run to answer one question: where do we actually stand, and
what should we do about the gaps? Not to produce a feature checklist. The
answer was not a list of missing features.

The research lives in issue #5013. That issue holds the findings as a
checklist and the full note in an expandable section. This ADR carries the
decision that came out of it and the evidence the decision rests on, so the
decision survives without turning the note into a tree-resident document.

### What the comparison found

Four axes carry the decision. The competitor's documentation is silent on
audit trails, signed artifacts, verified boot, attestation, provenance, and any
policy engine beyond egress allow-lists, so on the assurance axis there is
nothing to match against.

**Product surface.** We expose roughly fifty top-level commands with deep
subtrees; they expose one `machine` group with about thirty-five verbs, a
`pack` verb, and a `serve` verb that exposes a local HTTP API. Their hosted
service adds accounts, organizations, scoped keys, metered billing, a prepaid
balance, port links, custom domains, in-service checkpoints, detached jobs, and
an interactive WebSocket exec path. We have no hosted service; the fleet
authority lives in the sibling control-plane repository and is self-hosted.

**Isolation, egress, and credentials.** Both of us keep the guest without a
routable network interface by default. The difference is what happens when
network is wanted. They select an interface-bearing backend, and the guest
then has a real interface; the host-side gateway applies allow and deny
lists, and a deny is checked before any allow. On their hosted service the
network mode defaults to open when omitted. We never give the guest an
interface: every connect, datagram, and DNS answer is decided by one gate in
a per-VM host endpoint reached over vsock, and the network policy is derived
from the signed grant set, so the policy in force and the policy the plan was
signed over cannot drift apart. `xtask/src/check_single_network_path.rs` pins
the single spawn site so a backend cannot grow a second path.

On credentials, their substitution model is the more polished shape: an opaque
placeholder in the guest, substituted host-side for HTTPS requests to a bound
host, header-only unless the caller opts into bodies, refused in URLs, with
wildcards and per-branch resolution. Ours has the same shape on the managed
path and a manual path that still ships raw bytes, which our own ledger marks
as an open gap. Their other model injects plaintext into the guest and says
so plainly, which is honest but is a different guarantee.

**Trust and assurance.** This is the widest gap, and it runs our way. Their
admission is an authenticated request followed by a ceiling check. Ours is a
signed plan admitted under a grant ceiling, over a root filesystem sealed with
dm-verity, with a hash-chained audit log, receipts, and provenance, and a
machine-checked claim catalog. Our claim catalog carries twenty-five numbered
claims with typed witnesses; their documentation claims nothing that could be
witnessed.

**Platforms, GPU, artifacts, and performance.** They ship a native Windows
host and a graphics path through a paravirtualized GPU. We ship no Windows
host, and our GPU posture is compute-by-remoting only, which
`specs/adrs/053-gpu-compute-over-vsock.md` records; there is no graphics path
on our side at all, and our own reference material says so. Their CUDA support
and ours both remote the API over vsock rather than passing a device through,
so on compute the shapes are close; the graphics lane is theirs alone. On
performance we hold the stricter method and the thinner record: our launch
budgets are ceilings enforced in CI, contaminated samples are refused, and
comparability fingerprints are required, while our published dataset is a
single row on one host. Their documentation publishes no latency numbers at
all, only qualitative descriptions.

**The hosted-service axis.** Their control plane is a product: a signup, a
machine in seconds, real money rails, and a console. Ours is a cryptographically
chained fleet authority — signed budget holds, signed reservation receipts,
signed placement leases, launch permits carrying the fleet-signed execution
plan, and usage receipts chained by digest and signed by the node — with
**no** fault tolerance, metering that never runs in the shipped path, no TLS,
no key revocation, an unreachable mailbox, and persistence that cannot evolve.
The authority design is ahead; the operational story is absent.

## Decisions

### 1. The trust chain is the spine. Product-surface parity does not outrank it.

We keep the NIC-less deny-all egress model, the signed admission path, the
verified boot, and the hash-chained audit. We do not trade any of them for a
wider command surface, a hosted service, or a host platform we do not support.

The comparison is the evidence: their hosted admission is an authenticated
request, ours is a sequence of signed, generation-fenced, replay-protected
artifacts in which a controller can choose a host but cannot make it accept,
and a host can refuse but cannot mint fleet authority. That separation is the
thing worth having. A broader command surface would not close the gap that
matters, and a hosted service built on today's fleet authority would reproduce
the weaker model at higher cost.

### 2. Sequence: make the fleet authority operable before pursuing hosted-service parity.

Their advantage on the hosted axis is operational maturity, not authority
design. We cannot match it without a fleet authority that survives node loss,
meters what it runs, and can be operated by someone who did not write it.
Until those are true, the hosted-service gap is not closable, and a hosted
service of ours would ship the weaker trust model to a wider audience.

This also decides the order of the product-surface gaps. A local HTTP daemon,
a published SDK, and a beginner-facing command surface all become cheap once
the fleet authority is operable, because they are thin layers over a surface
that already exists. The reverse order builds the thin layers over an authority
that cannot fail over.

### 3. Prior-art boundary.

**Keep, because we already hold it and the comparison did not change our
mind:** the interface-less guest and single-gated egress; credential
substitution with the guest holding only a placeholder; the warm standby pool
with a shape-matched claim and a hard latency ceiling.

**Do not adopt:**

- *An interface-bearing egress path.* Ours is refused structurally rather
  than by configuration, which is the stronger of the two postures. An
  egress policy that can be reconfigured into a permissive state is a
  different guarantee from one that has no permissive state.
- *A hosted-only tenancy model.* It retires the sovereign deployment option,
  which is a real differentiator for the deployments that care about the
  trust chain.
- *Unsigned portable artifacts.* Our signed bundle and publisher trust store
  stay; a portable artifact that carries no signature cannot take part in
  the admission path.

**Open, and deliberately not decided here:** live copy-on-write fan-out with a
workload-declared branch point, and a graphics path. Both are plausible
adoptions and both carry cost we have not yet priced.

### 4. The research lives in the issue; this ADR carries the decision.

The comparison's findings are tracked in issue #5013. The note itself does not
live in the tree: `specs/` holds the PRD, the README, the ADRs, and the
contracts, and `xtask/src/check_root_layout.rs` allow-lists the repository
root, so no in-tree directory fits a research document. This ADR carries the
decision and the evidence summary. It does not carry the work items, and it
does not carry a status ledger.

## Consequences

**We accept a narrower product surface for longer.** A competitor can ship a
hosted service, a Windows host, a graphics path, and a local HTTP daemon
before we ship any of them. Users comparing us on features will find us
missing things.

**We accept the cost of the trust chain.** A heavier launch path, a signed
plan authoring surface, and an operational burden a smaller competitor does
not carry. The chain only pays off if the operability work in decision 2
actually lands; until then, the burden is carried without the benefit.

**We do not claim their product is unsafe.** Their documentation is silent on
audit trails, signed artifacts, verified boot, attestation, and provenance.
Silence is not absence. The honest statement is that each side describes what
it can witness, and only one of the two sets of statements is machine-checked.
The comparison records the silence rather than filling it in.

**Decision 2 becomes the critical path.** Every product-surface gap in issue
#5013 is sequenced behind operability. That is a deliberate choice to look
slower on a feature-count chart in exchange for a fleet authority that can be
operated and audited.

## What must be true before the hosted-service gap can close

The findings live in issue #5013 as a checklist. In rough dependency order:

- The fleet authority survives node loss: a live peer-death contract, a
  heartbeat, failover, and re-placement, rather than a manual replacement call.
- The live conformance suite runs in CI, so the claims about the fleet rest on
  a machine that booted rather than on a design sketch.
- Usage is metered in the shipped path, so a receipt travels from the node to
  the account.
- The HTTP API terminates TLS, and API keys expire and revoke.
- The mailbox is reachable by a user and by a guest.
- Persistence carries a schema version, a backup and restore path, and
  metrics.

## What this ADR does not decide

- Whether to ship a local HTTP daemon, and in what shape. Tracked in
  issue #5013.
- Whether to support a Windows host. Not priced here.
- Whether to add a graphics path. Not priced here.
- The contract of a future hosted service of ours. That follows the
  operability work, not this ADR.
- The exact shape of the research note's long-term home beyond issue #5013.
