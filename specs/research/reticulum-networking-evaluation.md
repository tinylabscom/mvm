# Research — Reticulum for mvm and mvmd networking

**Status:** Research note; no implementation commitment
**Date:** 2026-08-10
**Owner:** mvm
**Source:** [reticulum.network](https://reticulum.network/) manual §Understanding,
[markqvist/Reticulum](https://github.com/markqvist/Reticulum) (Python reference impl),
[Reticulum-rs](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs) (MIT Rust port),
[leviculum](https://codeberg.org/Lew_Palm/leviculum) (`no_std` + `alloc` core)
**Companion:** `veilid-networking-evaluation.md` — same question, adjacent answer,
and the reasoning there is not repeated here where it transfers unchanged.

## TL;DR

**Do not adopt, in either repo.** Take three ideas, no code.

Reticulum is a cryptography-first mesh stack for adverse links — LoRa, packet
radio, serial — engineered down to a 5 bit/s floor and a 500-byte physical MTU.
It is a better-engineered and much smaller thing than veilid, and its protocol
is public domain, so this is not the same rejection. But it fails on mvm's guest
path for a structural reason (it deliberately removes the attribution the audit
chain is built on), and it fails on mvmd's fabric for an arithmetic one (mvmd
moves rootfs and vmlinux artifacts; Reticulum's payload ceiling is 465 bytes).

The parts worth keeping are design discipline, not dependencies:

1. **Self-certifying, namespaced addressing** — mvmd already has half of this via
   iroh `NodeId`, and Reticulum shows what the other half buys.
2. **Per-destination ratchets** — forward secrecy for connectionless packets,
   the right pattern for store-and-forward attestation delivery at the edge.
3. **An anti-pattern, precisely named** — an ephemeral per-process identity is
   exactly the failure key-derived addressing exists to make unrepresentable.
   mvmd has one today, and it is already logged as a known weakness.

## What Reticulum is

A stack for building *many independent* networks, not one network. Deliberately
minimal, and honest about its constraints.

- **Addressing.** A destination is a 16-byte truncated SHA-256 over an identity
  public key plus an application/aspect namespace. Anyone can mint one; no
  allocation authority exists. Addresses are portable across topology — the same
  destination stays reachable after it moves.
- **No source addresses.** Not an omission; a headline feature.
- **Crypto.** Ed25519 signatures, X25519 ECDH, HKDF, AES-256-CBC with PKCS7,
  HMAC-SHA256, SHA-256/512. Fernet-shaped, encrypt-then-MAC — *not* AEAD.
- **Links.** A three-packet handshake (request / proof / establish) totalling
  297 bytes yields a forward-secret bidirectional channel; the initiator stays
  anonymous throughout. Keepalive is 20 bytes; 100 concurrent links cost about
  0.45 bit/s.
- **Ratchets.** Opt-in per destination. The destination key rotates and the
  current ratchet rides along in announces, so even a single connectionless
  packet gets forward secrecy without establishing a link.
- **Transport.** Probabilistic announce flooding, default 128-hop limit, 2%
  per-interface bandwidth cap. No node knows a full path — each transport node
  learns only its next hop. Convergence is on the order of a minute.
- **Physical floor.** 500-byte MTU, 465-byte max payload, half-duplex, 5 bit/s.
  Medium-agnostic across LoRa, packet radio, serial, WiFi, Ethernet.
- **Stated non-goals.** Not a single network, not LoRaWAN-compatible, no QoS or
  priority routing. Plain and group destinations do not traverse multiple hops —
  only encrypted single destinations and links do, by design: to be transported,
  information must be encrypted.

Maturity, in the project's own words: the API and wire format are stable, but it
"has not been externally security audited, and there could very well be privacy
or security breaking bugs."

## Licensing — read this before reading anything else

Three distinct artifacts, three distinct answers:

| Artifact | License | Usable? |
|---|---|---|
| The **protocol** | Public domain (dedicated 2016) | Yes, freely |
| Python **reference implementation** | Bespoke "Reticulum License" | **No** |
| **Reticulum-rs** / leviculum ports | MIT | Yes, on merit |

The Reticulum License is a modified-permissive grant carrying two field-of-use
restrictions: no use in a system able to "purposefully do harm to human beings",
and no use "directly or indirectly, in the creation of an artificial
intelligence, machine learning or language model training dataset."

The second clause is disqualifying in practice for this product line regardless
of how narrowly it is read. It is non-OSI, untested, and bespoke; it would need
a `deny.toml` exception and a legal read, on a codebase whose dependency posture
(ADR-002) is permissive-leaning and dependency-minimising. Nothing under that
license enters either workspace.

This matters less than it first appears, because the protocol being public domain
means the *ideas* below are free to take, and the Rust ports are MIT. The
licensing objection kills the reference implementation, not the concepts.

## Why it does not fit mvm's guest path

The reasoning in `veilid-networking-evaluation.md` §"mvm's actual networking
model" transfers verbatim and is not restated. Four things are specific to
Reticulum:

1. **No source addresses is the disqualifying property.** mvm's audit chain
   exists to record *who* did what. Claims 10, 13 and 16 all rest on the host
   originating and observing every outbound flow, then attributing it. Reticulum
   deliberately removes precisely the field the audit needs. This is not
   configurable away — it is the design.

2. **The threat model is inverted, not merely different.** Reticulum's goal is
   communication that "cannot be subjected to outside control, manipulation or
   censorship." In mvm, the party doing the controlling *is the host*, and the
   host is the trusted enforcement point, not an adversary. A stack engineered to
   defeat the operator is not a stack to build the operator's enforcement seam on.

3. **Wrong envelope by three orders of magnitude.** 465-byte payloads,
   half-duplex, tuned for a 5 bit/s floor, against OCI layers and Nix closures.

4. **Crypto would be a regression and a duplication.** AES-256-CBC + HMAC-SHA256
   is sound-but-dated encrypt-then-MAC, against AEAD in the workspace stack; and
   `mvm-core::crypto` already carries Ed25519/X25519. Same dependency-floor
   objection ADR-002 raises against every second crypto stack.

As with veilid, a `kind() == "reticulum"` provider is *mechanically*
constructable against `NetworkProviderRegistry` + `ir::NetworkMode::Custom`.
It must be refused for the same reason, and this paragraph exists so a future
session does not rediscover the seam and mistake it for permission.

## Why it does not fit mvmd's fabric either — and the sharper reason

mvmd's fabric research (`specs/research/003-multi-host-transport-models.md`,
`003-generalized-connectivity-fabric.md`, feeding ADR 0026) evaluates iroh as
default with veilid as a privacy provider. Reticulum's fit against that frame:

- **RPC shape** — mechanically possible, and it is the only shape that fits at
  all. Control messages are small.
- **Gossip shape** — announce flooding is not pub/sub, and the 2% per-interface
  bandwidth throttle is a design for radio, not for a datacentre heartbeat.
- **Blob shape** — hopeless. mvmd distributes rootfs and vmlinux artifacts; the
  payload ceiling is 465 bytes and there is no stream primitive or backpressure.

The sharper point: **mvmd already has Reticulum's best idea, and has it in a
form that can also move bytes.** An iroh `NodeId` *is* an Ed25519 public key,
`mvmd-iam` already treats it as service identity
(`Principal::Service { node_id, … }`), and the transport underneath is QUIC with
NAT traversal and relay. Reticulum's addressing model would be a lateral move on
identity and a catastrophic one on throughput.

**One narrow case remains genuinely arguable.** If ADR 0026 keeps a
privacy/censorship-resistance provider slot, Reticulum is a *more defensible
candidate than veilid for that slot specifically*:

| | veilid | Reticulum |
|---|---|---|
| Closure size | ~2M SLoC transitive | small; MIT Rust port, `no_std`-capable core |
| External network needed | yes — DHT bootstrap/rendezvous | **no** — a private network over your own interfaces |
| Protocol license | MPL-2.0 code | public-domain protocol, MIT port |
| Wire stability | evolving | declared stable |
| Fit for low-rate control RPC | good | good |
| Fit for gossip / blobs | weak / poor | weak / **unusable** |

The "no external peer network required" row is the one that matters: it is the
only candidate in this class that does not violate the hermetic posture by
construction. That is not an endorsement — it is a note that *if* the privacy
slot survives ADR 0026, this is the comparison to run, scoped strictly to
low-rate control messages and never to gossip-at-scale or artifact distribution.

## What to actually take

### 1. Namespaced self-certifying addressing — mvmd (idea, no dependency)

Reticulum's destination is `hash(identity_pubkey ‖ app ‖ aspect)`: **one identity,
many destinations**. mvmd today has one identity and, effectively, one destination
— exactly one live ALPN, `/mvmd/agent/1`, with the fabric research noting gossip
and blob ALPNs built but never registered on a Router.

The aspect model is the cleaner answer to that than minting an ALPN per service:
derive a per-service destination from the node identity plus a service namespace,
so a service address is checkable arithmetic over the node key rather than a
separate registration to keep in sync. Cost is a hash; the benefit is that
"which service is this" stops being a string both ends must agree on out of band.

### 2. Identity is persistent and *is* the address — mvmd (fixes a live weakness)

`QuicDispatcher::new()` generates a fresh ephemeral iroh identity per process, so
wake/autoscale/gateway callers are not strongly authenticated — already recorded
as a known weakness in the multi-host transport research.

Reticulum makes that state unrepresentable: you cannot be simultaneously
anonymous and addressable, because the address is derived from the key. That is
the discipline to import — not the stack. Concretely: node identity is loaded
from `identity.rs`, never generated at dispatch time, and any code path that can
mint an identity implicitly should fail closed instead. This is the single
highest-value item in this document and it costs one dependency: zero.

### 3. Per-destination ratchets — mvm edge tier (mechanism, not code)

Forward secrecy for packets sent *outside* a link, with the current ratchet
published in announces. mvm's vsock channels are host-local memory, so FS there
is close to moot — but the Tier-2 edge link is real wire. If store-and-forward
attestation or audit delivery over an untrusted relay ever ships, this is the
pattern to copy: rotate the destination key, publish the current ratchet with
the identity, accept the previous one for a bounded window.

## What this changes for mvm

Three things, in descending order of consequence.

### A. ADR-040 P1 conflates authentication with authorization

ADR-040 §P1 states that Node A "has no way to verify anything Node B says, and no
way to learn Node B's verifying key", and rejects the node-peer-keypair shortcut
as a second trust root. The rejection is right. But the two halves of P1 have
different answers, and Reticulum separates them cleanly:

- **Learning a peer's key** does not require an issuer *if the peer's node
  identifier is a hash of that key*. A self-certifying identifier cannot lie
  about the key it commits to; obtaining it from the peer is then safe, because
  verification is local arithmetic against the name you already had. This is
  precisely the property that makes Reticulum's trust-root-free addressing work,
  and it introduces **no** second trust root — there is no new key to establish,
  only a naming convention over an existing one.
- **Deciding which workloads may reach each other** genuinely does require an
  authority over a set of nodes. That is the control plane's, exactly as ADR-041
  concluded.

So P1 as written is broader than it needs to be. The blocking half is
authorization; the key-distribution half is solvable inside this repo with a
naming rule. This does not unblock #2119 — `LeaseVerifier` still needs an issuer
whose `key_id` is not node-scoped, and `WrongNode` stays unrelaxed — but it
narrows what "unblocked by" has to deliver, and removes a stated obstacle that
is not actually an obstacle.

**Proposed action:** amend ADR-040 §P1 to split the two, or record this note as
the reason the split exists. Not a reversal of any decision; a narrowing of one.

### B. The Tier-2 transport seam should be decided, and decided small

`specs/notes/2026-07-27-mvm-protocol-baremetal-embedding.md` leaves the Tier-2
transport as the open design question: vsock is a hypervisor construct, absent
off a VMM, and the ESP32↔Pi link needs something else.

Reticulum is the strongest off-the-shelf candidate that exists for that slot —
`no_std` + `alloc` core, medium-agnostic over serial/BLE/TCP/LoRa, frames sized
for exactly this class of link. **Take it anyway as a no.** For a point-to-point
link between a verifying client and its host, a length-prefixed framing over
serial is on the order of a couple hundred lines; the DTOs are already
transport-agnostic and the verify path needs no RNG. Reticulum would buy
multi-hop mesh, announce flooding and rendezvous that a two-node link does not
use, plus the crypto duplication above, plus an unaudited stack underneath
CI-enforced claims.

Keep the seam a trait so the decision stays reversible. Revisit only on a
concrete many-to-many or intermittently-connected edge requirement — that is the
one scenario where the mesh machinery would earn its cost.

### C. The Merkle proof shape is validated by a hostile envelope

Incidental but worth recording: an RFC 6962 inclusion proof is log(n) hashes, so
a verifier's working set fits comfortably inside a 465-byte-class MTU. The
existing `crates/mvm-contract/src/merkle.rs` design is already the right shape
for a constrained edge link, which is a useful independent confirmation ahead of
the still-open footprint measurement.

## Weighed against the binding constraints

- **Limit dependencies (ADR-002):** fails for any Reticulum code in either repo —
  a second crypto stack duplicating `mvm-core::crypto`, for a transport neither
  repo's throughput profile can use.
- **License posture:** the reference implementation is disqualified outright by
  its AI/ML field-of-use clause. Ports are MIT; the protocol is public domain.
- **Hermetic / no external services:** **passes**, and notably so — unlike veilid,
  a Reticulum network needs no bootstrap peers or public DHT. This is the one
  constraint where it scores strictly better than the incumbent alternative.
- **Auditable-vsock-seam invariant:** direct violation on the guest path. No
  source addresses means no attribution.
- **Claims 10 / 13 / 16:** each defeated by an unattributable guest-originated
  transport.
- **Unaudited crypto:** the project says so itself. Not acceptable beneath
  CI-enforced security claims.

## Decision

**Do not adopt Reticulum in mvm or mvmd.** The guest path is architecturally
opposed to an unattributable transport; the fabric path already holds the good
idea (key-derived identity, via iroh) in a form that can also move artifacts; and
the reference implementation carries a field-of-use restriction that disqualifies
it before technical merit is reached.

Take three things and no code: **namespaced self-certifying addressing** and
**identity-is-the-address** into mvmd's fabric design, and **per-destination
ratchets** into the edge tier if store-and-forward delivery ever ships.

Revisit only under two specific conditions: (a) ADR 0026 keeps a
privacy/censorship-resistance provider slot, in which case benchmark Reticulum
against veilid for *low-rate control RPC only* — it wins on closure size, wire
stability and the absence of an external peer network; or (b) the Tier-2 edge
grows a genuine many-to-many or intermittently-connected topology, at which point
the mesh machinery starts to earn its cost. In neither case does it approach a
guest data path.

## Sources

- [reticulum.network](https://reticulum.network/)
- [Understanding Reticulum — protocol specifics, wire format, primitives](https://reticulum.network/manual/understanding.html)
- [markqvist/Reticulum](https://github.com/markqvist/Reticulum) and its `LICENSE`
- [Reticulum-rs (MIT Rust port)](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs)
- [leviculum (`no_std` + `alloc` core)](https://codeberg.org/Lew_Palm/leviculum)
- mvm `specs/research/veilid-networking-evaluation.md`
- mvm `specs/adrs/003-hypervisor-egress-policy.md`,
  `specs/adrs/040-node-to-node-transport.md`,
  `specs/adrs/041-node-control-api.md`
- mvm `specs/notes/2026-07-27-mvm-protocol-baremetal-embedding.md`
- mvm `crates/mvm-net/src/{provider,registry}.rs`,
  `crates/mvm-contract/src/merkle.rs`
- mvmd `specs/research/003-multi-host-transport-models.md`,
  `specs/research/003-generalized-connectivity-fabric.md`
