# Mission demo: presenter notes

`scripts/mission-demo-live.sh` is the demo. These notes cover the optional
networking segment and the three statements to make about networking and
post-quantum cryptography.

## The optional networking segment

```sh
NETWORK_SEGMENT=1 MVMD_DIR=~/work/tinylabs/mvmco/mvmd scripts/mission-demo-live.sh
```

It runs mvmd's own `scripts/smoke-iroh.sh` after the evidence step and prints:
the node's Iroh endpoint id, and the controller's health (`"status": "ok"`,
`single_controller`, not replicated).

Say exactly this about it, and no more:

> A mvmd node and controller run as separate processes on this machine and
> talk over Iroh, which is QUIC, on loopback with the relay turned off.

It is **not** two hosts, WAN or NAT traversal, SpiralCore object transfer, or a
live microVM launch, and the script prints that on screen. What it shows is
that the node binds its Iroh endpoint and the controller comes up healthy.
The script's own comment says it proves controller-to-node RPC, with
quarantine admission and signed envelopes, but its output does not show that
RPC (the controller log holds one line, also at debug level), so do not claim
it from the output.

It is off by default, needs a built mvmd checkout (the first run builds it, about
90 s; later runs take 2 to 3 s), and can never change the demo's result: a
carrier that fails, hangs (240 s limit, `NETWORK_SEGMENT_SECS`), or is not
installed is printed and the demo still ends in its own verdict. If it
distracts, leave it off and use the architecture explanation below.

Measured on the demo Mac: 5 of 5 runs passed, 93 s with the build and 2 to 3 s
after.

## What to say

Three kinds of statement, kept apart in the slides and in the spoken script:
what is **implemented**, what the demo **demonstrates**, and what is
**proposed**. Say which one you are in.

### Implemented

**Networking.**

> Our fleet networking uses interchangeable carriers behind MVMD's networking
> interface. The supported carrier today is Iroh over QUIC. We prototyped a
> Veilid carrier and retired it from the build. Transport connectivity does not
> itself authorize an operation; fleet membership and command authorization
> remain separate.

Changed from an earlier request that said the current repository includes "an
experimental Veilid adapter": mvmd's `docs/VEILID_WAN_SPIKE.md` says that
carrier is **retired from the supported build** and survives only in git
history (commit `50d64da`), so it cannot be called current.

**Signing.** Ed25519 for execution-plan and audit signing. This is covered in
the first sentence of the script below.

### Demonstrated

The contain, terminate and replace sequence described at the end of this file,
and, if you run the optional segment, the loopback Iroh smoke test described
above. Nothing in the next section is demonstrated.

### Proposed: post-quantum roadmap. None of it is implemented.

Say this regardless of whether anyone asks:

> Today, MVM uses Ed25519 for execution-plan and audit signing. Our proposed
> post-quantum roadmap prioritizes long-lived audit evidence: versioned,
> algorithm-explicit formats first, then dual Ed25519/ML-DSA signatures,
> followed by execution plans. Algorithm identifiers alone do not provide
> post-quantum protection. For cross-host traffic, we plan to evaluate hybrid
> X25519/ML-KEM key establishment within our existing networking architecture.
> These post-quantum extensions are not implemented today.

If asked about defense requirements:

> CNSA 2.0 alignment is a requirements-led direction, not a current compliance
> claim. We would scope the algorithms, cryptographic modules, deployment
> configuration, and supporting evidence against your requirements. We are not
> claiming a qualified FIPS deployment for this demo.

**The audit-first ordering is unconfirmed.** It came from the same source as
this wording and still needs Ari's confirmation. One thing to settle first:
ADR-062 section 7 orders the work differently. It puts hybrid X25519 +
ML-KEM-768 for mailbox key agreement and cross-host transport **first**
(recorded traffic can be decrypted later), and hybrid Ed25519 + ML-DSA-65 for
audit and epoch seals, evidence archives, packs and plans **second**. If the
ADR's order is the intended one, the first and last sentences about priorities
swap; the "not implemented today" sentence stays either way. A search for ML-DSA,
ML-KEM and Kyber finds only that ADR in either repository.

## What the demo itself claims

Contain, terminate, and replace on a real VM, with an audit chain that verifies
and carries no message body. The three nodes are simulated in one process in the
hermetic test, delivery into a second guest is not built (#5312), the uplink
loss act is the simulated offline-lease path (#5120), and the production
profile on a signed image has not been run (#5353).
