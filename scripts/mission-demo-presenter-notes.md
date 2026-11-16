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

**Networking.**

> Our fleet networking uses interchangeable carriers behind MVMD's networking
> interface. The supported carrier today is Iroh over QUIC. We prototyped a
> Veilid carrier and retired it from the build. Transport connectivity does not
> itself authorize an operation; fleet membership and command authorization
> remain separate.

Changed from the requested wording: it said the current repository includes
"an experimental Veilid adapter". mvmd's `docs/VEILID_WAN_SPIKE.md` says that
carrier is **retired from the supported build** and survives only in git
history (commit `50d64da`), so it cannot be called current. If you want it
back in the build, say so and the sentence changes.

**Today's signing.**

> Today, MVM uses Ed25519 for execution-plan and audit signing.

**The proposed post-quantum roadmap. Proposed, not implemented.**

> Our proposed post-quantum roadmap starts with versioned, algorithm-explicit
> audit formats, followed by dual Ed25519/ML-DSA signatures. An algorithm
> identifier is migration groundwork, not post-quantum protection. We would
> then extend that approach to execution plans and evaluate hybrid
> X25519/ML-KEM key establishment for cross-host communication.

> CNSA 2.0 is a requirements-led direction we can discuss, not a compliance
> claim. None of those post-quantum extensions is implemented today.

These priorities were proposed and still need confirmation. One thing to
settle first: ADR-062 section 7 orders the work the other way round. It puts
hybrid X25519 + ML-KEM-768 for mailbox key agreement and cross-host transport
**first** (recorded traffic can be decrypted later), and hybrid Ed25519 +
ML-DSA-65 for audit and epoch seals, evidence archives, packs and plans
**second**. The wording above follows the request; if the ADR's order is the
intended one, the two halves swap. Either way, nothing post-quantum exists in
either repository today: a search for ML-DSA, ML-KEM and Kyber finds only that
ADR.

## What the demo itself claims

Contain, terminate, and replace on a real VM, with an audit chain that verifies
and carries no message body. The three nodes are simulated in one process in the
hermetic test, delivery into a second guest is not built (#5312), the uplink
loss act is the simulated offline-lease path (#5120), and the production
profile on a signed image has not been run (#5353).
