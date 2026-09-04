# ADR-040 — The node-to-node transport trust boundary

**Status: Proposed — designed, deliberately not implemented. Three of the
four properties the hop must preserve cannot be preserved today, for
reasons named below. Nothing here should be built until its prerequisites
land. Tracked as issue #2119.**
**Date: 2026-08-04**
**Complements ADR-036 (L3 TUN-over-vsock) §"Cross-node traffic", which
described the interface and recorded it as not implemented, and ADR-052
(the userspace socket datapath), which owns the local forwarding backend
unchanged.**

## Why this ADR needs to exist before the code

Every property `l3-vsock` enforces today is enforced inside one process on
one machine. A packet crosses vsock, is bound to a host-owned session,
passes structural validation, passes the signed plan's policy, and reaches
a datapath — and every one of those steps reads state the host owns and
nobody else can write.

Carrying a flow to a VM on another machine breaks that. The destination
node must act on an assertion made by a peer it does not control, about a
workload it cannot see, under a policy it did not resolve. That is a new
trust boundary, and which side of it decides what is the whole design.

ADR-039 was written for the same reason and reached a different answer.
The precedent is the point: a decision that moves the trust boundary gets
a signature, not an implementation detail buried in a networking feature.

## What the hop must preserve

Four invariants, restated from the requirement so they can be checked
rather than paraphrased.

| # | Invariant |
|---|---|
| I1 | The remote end is authenticated. A node accepts flows only for VMs it actually hosts, and a node asked about another node's VM refuses rather than answers |
| I2 | Default-deny survives the hop. Crossing a node boundary is never an implicit admission; the destination is authorized by the same code path as a local flow |
| I3 | The audit chain records what happened, on the node that made the decision |
| I4 | No workload NIC appears anywhere. The transport is host-to-host; the guest still reaches it only over vsock |

I4 holds for free and stays that way: the transport terminates in
`mvm-netd`, on the host side of the vsock boundary, in the position the
host TUN and the socket gateway already occupy. Nothing about it is
reachable from a launch path, and no design below adds a device to a
guest.

I1, I2 and I3 do not hold today, and cannot be made to hold by anything
that lives in this repository right now.

## The four prerequisites, and why each is a prerequisite

### P1 — There is no cross-node trust root, and inventing one here is the wrong move

`mvm_net::lease::LocalLeaseAuthority` signs with a per-node symmetric MAC
under the fixed `key_id` `"local-node"`, and `verify_lease` refuses a
lease naming any other node with `LeaseError::WrongNode` before it reads a
single field of the grant. That is not an oversight to be relaxed; it is
what makes a lease non-transferable, and it is asserted by
`a_lease_from_another_node_is_refused`.

Node A therefore has no way to verify anything Node B says, and no way to
learn Node B's verifying key. The only object in the system that could
carry cross-node authority is a lease issued by an authority both nodes
trust — which is exactly what a control plane is for, and which
ADR-036 §"Local versus central responsibility" already assigns to the
central side.

The tempting shortcut is a node-peer keypair or a shared cluster secret,
established node-to-node. **That is a second trust root**, sitting beside
the plan-signing root that `mvm-core`'s host signer already anchors, and
it would be the component that decides which workloads can reach each
other — the most security-relevant key in the system, established by the
least authenticated mechanism in it. Rejected.

**Unblocked by:** an issuer whose key is not node-scoped, and a way for a
node to obtain a peer's verifying key from that issuer rather than from
the peer.

**Where that comes from — settled by ADR-041, and not here.** This ADR
named the node-control API (#2120) as the likely source. It is not: an
issuer is an authority over a set of nodes, and a single host has no
vantage point from which to mint one. ADR-041 splits the question — the
issuer is the control plane's, the *verification* is the node's — and
builds the node half. So P1 stays open, but its remaining half now sits
in a named place outside this repository rather than in an unwritten
workstream inside it. The verification seam a node needs
(`LeaseVerifier` selecting on `key_id`, holding verifying material only,
with `WrongNode` unrelaxed) is designed in ADR-041 §"The verification
seam the node needs".

### P2 — Addresses are not unique across nodes, so a destination IP does not name a VM

`l3::alloc::PoolAllocator` hands out `/30`s from `DEFAULT_POOL`
(`10.201.0.0/16`) against a per-process cursor and a per-process
`leased` set. There is no node discriminator anywhere in the allocation.
Two nodes booting their first machine both issue the same `/30`: gateway
`.1`, guest `.2`.

The consequence is worse than ambiguity. A plan that opens the pool CIDR
so that VMs can reach each other cannot distinguish a remote peer's
address from a local machine's, because they are the same address. The
node would route a flow intended for a peer to whichever local VM holds
that address — a mis-delivery that no admission check would catch, since
the destination is genuinely admitted and genuinely local.

ADR-036 requires that "the guest cannot tell whether a destination VM is
local or remote". Under a colliding address plan that requirement is not
merely unmet, it is unachievable: the two cases are not distinguishable
from the packet.

**Unblocked by:** address allocation moving to the issuer, with a scope
under which an assigned address is unique among the nodes that can reach
each other. `PoolAllocator` remains correct as the standalone single-node
path; what it cannot do is be two of itself.

### P3 — The policy language cannot express a peer VM, and inbound admission has no source

I2 says the destination is authorized by the same code path as a local
flow. Follow that path and see what it decides.

On the source node nothing changes: `admit_outbound` judges a destination
address against `CanonicalEgress`, and a peer VM's address is an address.

On the destination node, `admit_inbound` admits a packet in exactly two
cases — it is return traffic on a flow in the `FlowTable`, or
`IngressTable::admits(protocol, guest_port)` is true. An unsolicited
packet from a peer VM is neither, so it is denied `UnsolicitedInbound`.
Default-deny survives the hop, which is the correct failure, but it means
the feature does not work.

Making it work has only two shapes, and one of them is a widening:

- Declare a host-facing ingress mapping on the destination VM. But an
  `IngressMapping` is keyed `(host_addr, host_port) → guest_port` and
  `admits` takes only a protocol and a guest port — **there is no source
  in it at all**. Declaring one to admit a peer VM also admits the entire
  host network to that port. "Reachable by my peer" and "reachable by
  anything that can send to this host" become the same declaration.
- Add a peer-scoped grant. `CanonicalRule` is `(proto, IpNet, port
  range)`; it can name an address but not a workload. Naming a peer needs
  a grant that carries tenant and VM identity, a lease field to carry it,
  and a source-scoped form of `IngressTable`.

The second is right and the first is not, but the second is a change to
the policy language, the plan schema and the lease — decided in
`mvm-core` and `mvm-net`, not invented inside a transport. A transport
that reached for the first shape because it was available would be
choosing a widening on the plan author's behalf.

**Unblocked by:** a peer-scoped egress grant and a source-scoped ingress
declaration, landed in the policy projection and the lease before any
transport consumes them.

### P4 — The audit chain does not reach the L3 gateway at all — CLOSED

I3 asks that the chain-signed audit log still record what happened. It
does not record what happens now.

`Gateway` returns `GatewayEvent` values rather than logging them, so that
the caller decides what to audit — a good seam. The caller is
`mvm-netd`, and `log_event` turns five of the twelve variants into stderr
lines and drops the rest to counters, on the stated and correct grounds
that a log line a guest can trigger at line rate is itself a denial of
service. There is no `AuditEmitter` anywhere under
`crates/mvm-hostd/src/netd/`, and none in the binary.

A property that does not hold on either side of a hop cannot be preserved
across it. Worse, the hop is where an audit record earns its keep: a
local flow is reconstructible from the plan and the flow table, whereas a
cross-node flow is the one case where two machines must later agree on
what was decided and by whom.

The fix is not part of this design and should not be smuggled into it.
Connecting `GatewayEvent` to the chain-signed log is worth doing on its
own merits, for the local path, with its own rate-discipline decision
about which decision classes are chain-entries and which stay counters.

**Closed.** `mvm_hostd::netd::audit::NetdAuditor` now routes every
`GatewayEvent` onto the chain-signed per-tenant log through the existing
supervisor `Recorder`, under `EventCategory::L3`, with the
rate-discipline decision this section asked for made explicitly: bounded
dedup on decision classes, a per-window emission budget, and a teardown
entry stating what neither admitted. See ADR-036 §"Audit and
observability" for the served set and the six facts that remain
unserved.

## The design, so far as it can be settled now

Recording this is the other half of the ADR's job. The prerequisites
change what is available, not what is wanted.

### Where the decisions are made

```text
VM A → local vsock → Node A mvm-netd → authenticated node channel
                   → Node B mvm-netd → local vsock → VM B
```

Both nodes decide, and neither defers to the other:

| Node | Decides | Using |
|---|---|---|
| A (source) | may this workload reach that peer | `admit_outbound`, unchanged |
| B (destination) | may that peer reach this workload | `admit_inbound`, unchanged |

**The destination node never trusts the source node's admission.** A
source node is a peer, not an authority; if it were trusted to have
admitted correctly, compromising one node would grant reach to every
workload on every other. Two admissions on two nodes is not the "second
admission check" that I2 forbids — that phrase means a second check
against the *same* policy on the same side, which is where drift hides.
Here each node runs its own policy exactly once, through the code path it
already runs for local traffic.

### What authenticates, and at what granularity

Per-connection, not per-packet. The node channel is one mutually
authenticated, confidential channel per node pair, and a flow inside it
inherits the channel's authentication. Signing per packet was considered
and rejected: it costs an asymmetric verify per packet on the forwarding
path, and it authenticates the wrong thing — the question is never "did
Node B sign this packet" but "is this channel Node B's", which a channel
answers once.

What the channel must bind, beyond the peer's identity, is the VM
identity on each end. `VmInstanceIdentity { node_id, vm_id, boot_id,
plan_digest }` is already the object everything authorizes against, and it
is what a flow announcement carries — so a flow names a boot, not a
machine, and a restart cannot inherit its predecessor's reach.

### What a node answers about VMs it does not host

Nothing. A flow announcement names a destination `VmInstanceIdentity`;
the receiving node looks it up among the sessions it currently hosts and
refuses if it is absent. The refusal must not distinguish "no such VM"
from "not mine" — a node that answers those differently is a
cluster-membership oracle for anyone who can open a channel to it.

`node_id` in the announcement is checked against the receiving node's own
identity for the same reason `verify_lease` checks it: a lease, and now a
flow, that names another node is refused before its contents are read.

### Bounds

The transport joins the module's existing posture rather than inventing a
second one: a cap on peer channels and a cap on flows per peer, both
consts; at capacity the new flow is dropped and no live flow is evicted,
so one peer cannot displace another; and any buffer the transport
introduces is a named term in `MEMORY_CEILING_BYTES` with its own
assertion in `limits.rs`, in the residual form that makes a dropped term
fail under its own name.

## Alternatives rejected

**Stretch AF_VSOCK between machines.** ADR-036 already refuses this. A CID
is not an authorization input and cannot be made into one; the address
space is per-host by construction.

**A shared cluster-wide pre-shared key.** Every node holds the same
secret, so compromising the least-protected node forges any node's
identity, and rotation is a fleet-wide flag day. It also makes I1's
"only for VMs it actually hosts" unenforceable in principle: with one
key, nothing distinguishes the node that hosts a VM from the node that
claims to.

**Trust the source node's admission and forward.** One admission instead
of two, and the destination node becomes a packet injector for anything
holding a channel. Rejected under I2.

**Tunnel node-to-node traffic through the existing egress path as
ordinary host traffic.** It appears to need no new anything — but the
destination node receives it as unsolicited host-network traffic, with no
peer identity attached, and the only way to admit it is a host-facing
ingress declaration. That is P3's widening arrived at by a different
route, and it loses the source VM identity that I1 exists to preserve.

## What must be true before this is implemented

- [ ] An issuer exists whose signing key is not node-scoped, and a node
      can obtain a peer's verifying key from it — not from the peer (P1,
      #2120)
- [ ] An assigned address is unique among the nodes that can reach each
      other, and a node can tell a remote peer's address from an
      unallocated one in its own pool (P2)
- [ ] The policy language can name a peer workload, and an ingress
      declaration can be scoped to a source, so admitting a peer does not
      admit the host network (P3)
- [ ] `GatewayEvent` reaches the chain-signed audit log on the local path,
      with its own decision about which classes are entries and which stay
      counters (P4)

Until all four hold, `l3-vsock` serves local destinations only, and a
plan naming a peer on another host is refused for the reason it is
refused today: the destination is not reachable, not that the feature is
missing.

## What this ADR does not decide

The wire format of the node channel, its transport (TLS over TCP, QUIC,
or something narrower), the flow-announcement encoding, and whether a
node pair keeps one channel or one per tenant. All of them are downstream
of P1: the trust root determines what a handshake can prove, and choosing
a format before that is choosing it twice.
