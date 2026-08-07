# ADR-041 — The node-control API, and where the cross-node trust root belongs

**Status: Accepted — the mvm half is implemented (`mvm_hostd::nodectl`).
The issuer half is a control-plane responsibility and is deliberately not
built here. Tracked as issue #2120.**
**Date: 2026-08-04**
**Answers the question ADR-040 §P1 left open, and is the ADR that
unblocks — or, as it turns out, only half-unblocks — the node-to-node
transport.**

## The question

ADR-040 established that cross-node traffic is blocked on there being an
issuer both nodes trust, and named this workstream as the place that
issuer could come from. So: **does the cross-node trust root belong in
this API, or in the control plane?**

There is a real argument each way, and the honest answer splits the
question rather than picking a side of it.

## The answer

**The issuer belongs to the control plane. The verification belongs to
the node. This API is the node half, and it cannot supply the issuer.**

An issuer is by construction an authority *over a set of nodes*. Deciding
which nodes are in that set, minting the key, rotating it, and revoking a
node's membership are all decisions about a fleet, made by something that
can see more than one node. A single host has no vantage point from which
to make any of them: it knows itself, and it knows what it was told.

The tempting move — have nodes establish a keypair with each other, or
share a cluster secret — was already rejected in ADR-040 §P1, and this
workstream does not reopen it. It would put the most security-relevant
key in the system behind the least authenticated mechanism in it, and it
would sit beside the plan-signing root that `mvm-core`'s host signer
already anchors. Two roots is one too many.

What a node *can* do, and what nothing else can do for it, is **verify**.
Verification is a local act against material the node holds: it needs no
view of the fleet, and it is precisely the property that must not be
delegated, because a node that trusted a peer's account of its own
authorization would be trusting the thing it is defending against.

So the split is:

| Half | Owner | Why |
|---|---|---|
| Who may issue, what the key is, how nodes learn it, when it rotates | mvmd | Requires a view of more than one node |
| Whether a presented grant verifies, and whether it names *this* node and *this* boot | mvm | Must not be delegated, and needs no fleet view |

This mirrors the split the repository already runs on — image,
entrypoint, source and dependencies are mvm's; resources and network
policy are mvmd's — and it is the same shape `NetworkLease` was designed
around: "a standalone `mvmctl` mints one locally; a control plane will
later issue one centrally", with one verification path either way.

## The verification seam the node needs

The seam already exists and is already the right shape. `verify_lease`
takes a `&dyn LeaseVerifier` and selects on `key_id`; nothing in the
packet path knows or can ask which kind of issuer produced the lease it
is running under. `LocalLeaseAuthority` is simply the impl that answers
for `key_id == "local-node"` and refuses every other id with
`LeaseError::UnknownKey` — a refusal, note, that happens *before* any
field of the grant is read.

What is missing, stated precisely so it is not mistaken for more than it
is: **a `LeaseVerifier` that holds verifying keys by `key_id` and no
signing key at all.** That is a small impl. It is deliberately not
written in this pass, because what it would select over — the issuer's
key format, and how a node comes to hold that key without asking a peer
for it — is exactly the mvmd decision this ADR declines to make. Writing
the map before knowing what it maps is inventing the issuer by
implication.

Three properties must survive that addition, and each is already
asserted by a test that must keep passing:

- **`WrongNode` does not relax.** A centrally-issued lease still names
  exactly one node, and a node still refuses one naming another before
  reading the grant (`a_lease_from_another_node_is_refused`). Reaching a
  peer is a *different object* — a peer-scoped grant, per ADR-040 §P3 —
  not a lease with its node check loosened. Any change that made a lease
  transferable would delete the property that makes leases worth signing.
- **The node holds verifying material only.** A node that could sign as
  the issuer is an issuer, and then every node is one.
- **Unknown `key_id` fails closed**
  (`an_unknown_key_id_is_refused_before_any_comparison`). A node that
  fell back to "try them all" would accept a lease from any issuer it had
  ever been told about, which is the revocation hole.

## What mvmd must supply

Enumerated, so the boundary is checkable rather than gestured at. None of
these is buildable in this repository, and each is a prerequisite ADR-040
already names:

1. **An issuer identity and its verifying key, distributed to nodes out
   of band of any peer.** ADR-040 P1. A key learned *from* the peer it
   authenticates authenticates nothing.
2. **Address allocation with a scope in which an assignment is unique
   among nodes that can reach each other.** ADR-040 P2. `PoolAllocator`
   remains correct as the standalone single-node path; what it cannot do
   is be two of itself.
3. **A peer-scoped grant in the policy projection, and a source-scoped
   ingress declaration.** ADR-040 P3.
4. **A caller-to-tenant mapping.** See below — this one is new, and it is
   this API's own limit, not the transport's.

## Identity in this API, and the limit it inherits

The caller is identified by the kernel: `SO_PEERCRED` on Linux,
`getpeereid` elsewhere, read from the connection before a byte of the
request is parsed. A field in a message naming its own sender is not an
identity, and `CallerIdentity` deliberately has no `Serialize` so it
cannot become one by accident.

That gives a uid, and a uid is the whole ownership model: a caller is
answered about a machine it registered and refused about every other. The
refusal for "not yours" and the refusal for "no such machine" are the same
bytes, for the reason ADR-040 gives for the flow-announcement case — a
node that distinguishes them is a membership oracle for anyone who can
open a connection to it. There is no superuser exception; a root caller
owns what root registered and nothing else.

The limit is worth stating plainly rather than discovering later:
**a uid is not a tenant.** Scoping by tenant would need a caller identity
issued by something both the node and the caller trust — which is the
same missing issuer as P1, arriving from a completely different
direction. So the node-control API's own authorization model is bounded
by the same absence that bounds the transport, and it will get its tenant
scope from the same place or not at all. Until then, the deployment this
model is correct for is the one where the control plane's node agent runs
under its own uid.

## What this node serves

- **`describe_node`** — the node id, the selected forwarding backend's
  own `ForwardingCapabilities` value carried through unchanged, the
  fallback reason when forwarding is not the packet-level path, and the
  list of fleet-level work this node does not do. The capability
  structure is passed through rather than re-described: a second
  representation could disagree with the one admission enforces, and the
  disagreement would surface as a workload a control plane admitted and a
  node refused.
- **`list_machines`** — the caller's machines, by `VmInstanceIdentity`.
- **`describe_machine`** — one of the caller's machines, with the signed
  lease it is running under, carried whole rather than summarised.

## What this node refuses

Everything else, and it says so before being asked. `describe_node`
reports four `unserved` values, one per ADR-040 prerequisite:
`cross_node_trust_root`, `cross_node_address_uniqueness`,
`peer_scoped_policy`, `gateway_audit_chain`. There is deliberately **no
request variant** for any of them — a surface that accepted a
cross-node question and failed it later would be advertising a capability
nothing serves, which is the failure mode this branch is specifically
trying not to repeat.

An unreadable protocol version is refused before the request is
interpreted; an unknown field fails the parse outright
(`deny_unknown_fields` on every wire type); a body over the frame cap is
refused on the length prefix, before it is allocated for.

## Bounds

256 machine registrations, each at most 4 KiB serialized, refused at
capacity rather than evicting a live one — a table that can be churned is
one where any caller who can register can make another's machine
unanswerable. Request frames cap at 8 KiB, response frames at what a full
registry plus its envelope can be. The worst case is
`nodectl::limits::MEMORY_CEILING_BYTES` (2,109,440 bytes), asserted term
by term with the response frame taken as the residual, so a term dropped
from the formula fails under its own name.

## What is not built, and why

**No binary hosts this surface.** The surface is per-node; the daemons
that exist are per-VM (`mvm-netd`) and per-tenant (`mvm-host-agent`).
Hosting it in either would put it at the wrong granularity and have to be
undone when the node-level process arrives — and adding an accept loop to
`mvm-netd` specifically would put a control listener inside the process
whose whole reason for existing is that it parses hostile guest bytes in
its own address space. So `serve_connection` handles one connection and
the listener's lifetime is left to the process that will own the node's
state. Everything below that line is exercised over real sockets.

**Nothing registers a machine yet.** `NodeRegistry::register` is called
by tests. The launch path does not call it, because the thing that would
hold the registry across launches is the same absent daemon. A node with
no registrations answers "no machines", which is true of a node with no
registrations — but it is not yet true of a node that is running
machines, and that gap is the honest reason this is not a shipped
end-user surface.

**The multi-issuer verifier is not written.** Reasons above.

## Alternatives rejected

**Put the issuer here, scoped to "just enough" for two nodes to talk.**
This is ADR-040 §P1's rejected shortcut wearing a smaller hat. An issuer
scoped to a node pair is still a second trust root; it is just one whose
blast radius is only obvious once there are three nodes.

**Authenticate the caller with a host-key signature instead of peer
credentials.** The host-agent control channel does exactly this, and it
is right there: the messages are host-signed over their JCS canonical
bytes. But it answers a different question. A signature proves the
message came from something holding the host key — which every mvm
process on this host does — and so it cannot distinguish two callers on
one node, which is precisely what ownership scoping needs. Peer
credentials and a host signature are complementary, and a future caller
identity issued by mvmd would sit alongside both rather than replace
either.

**Report capabilities as a node-control-specific structure.** A second
representation of what forwarding can carry is a second thing to keep in
sync with admission. `ForwardingCapabilities` travels through unchanged.

**Answer "forbidden" for a machine the caller does not own.** Correct
HTTP manners, wrong here: it confirms the machine exists.
