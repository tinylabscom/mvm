# Research — veilid for mvm networking

**Status:** Research note; no implementation commitment
**Date:** 2026-07-22
**Owner:** mvm
**Source:** [veilid-core](https://gitlab.com/veilid/veilid/-/tree/main/veilid-core), reviewed against `docs.rs/veilid-core`

## TL;DR

**Do not adopt.** `veilid` is a peer-to-peer, DHT-addressed, anonymity-routing
overlay. Its entire purpose — reach arbitrary peers over an encrypted overlay
that intermediaries (and the sender's own host) cannot associate with a
destination — is the direct inverse of mvm's networking model, which is *one
host-mediated egress chokepoint per guest, default-deny, fully audited*
(ADR-003, claim 10). On the guest data path it is not merely a poor fit; it is
a textbook covert-egress channel that would defeat the auditable-vsock-seam
invariant, claim-10 default-deny, and claim-13 secret substitution
simultaneously.

The one seam where a P2P provider is even *mechanically* pluggable — the
`NetworkProvider` fleet-mesh registry — lives in **mvmd, not this repo**, is
already served by authenticated WireGuard/Tailscale mesh providers, and *wants*
the non-anonymous, host-identified routing that veilid deliberately hides. Even
there veilid is the wrong tool.

## What veilid is

A privacy-preserving P2P network framework. Each app instance is a node
identified by a 256-bit public key; there are no special nodes and no central
party. It composes a BitTorrent-style DHT, IPFS-style decentralized storage,
and Tor-style onion/route-based traffic routing. `RoutingContext` is the API
surface: by default "safety routing" gives sender privacy, and "private routes"
give receiver privacy — you address a `RouteId` or `NodeId`, *not* an IP:port.
Transport is authenticated, timestamped, end-to-end encrypted, and signed
(VLD0 suite: blake3 / ed25519-dalek / chacha20poly1305).

Practical profile relevant to adoption:

- **Mandatory async runtime** (tokio, async-std, or wasm-bindgen-futures).
- **Large closure**: pulls its own full crypto stack plus overlay/DHT
  infrastructure (~2M SLoC transitively per lib.rs).
- **Needs a peer network to be useful**: a node's value is reaching *other*
  veilid nodes via DHT rendezvous/bootstrap — an external, non-hermetic
  runtime dependency.
- **License MPL-2.0** (file-level copyleft; distinct from the workspace's
  permissive-leaning posture).

## mvm's actual networking model (what it would have to fit)

Grounded in `specs/adrs/003-hypervisor-egress-policy.md` and the code:

- **Egress is a single host-mediated chokepoint, default-deny.** The
  `NetworkProvider` trait (`crates/mvm-net/src/provider.rs`) provisions one
  VM's network against a `NetworkSpec` whose `policy` defaults to
  `NetworkPolicy::deny_all()` — opening egress is opt-in (claim 10). The
  `EgressEnforcer` seam (`crates/mvm-net/src/enforcement.rs`) fails **closed**
  (`EnforcementError::NotWired`) rather than boot a VM with silent host egress.

- **Vsock-only on the workload backends.** HVF and libkrun guests attach *no*
  virtio-net device: no guest kernel IP stack, no tap, no gateway process. The
  guest's only channel out is `AF_VSOCK`. This is the standing
  auditable-vsock-seam invariant — the vsock boundary is exactly where audit
  and secret substitution happen.

- **One shared host forwarder.** The guest hands the host raw IPv4 packets over
  a dedicated vsock port; a decision gate (`L3ForwardPolicy::decide_packet`)
  checks each packet's destination against the admitted policy projected
  through a host-side DNS-pin registry (there is no guest-side DNS to trust);
  admitted packets go to an in-process userspace `smoltcp` stack that
  terminates the flow and splices it to an ordinary host socket
  (`crates/mvm-hostd/src/smoltcp_egress.rs`). Unparseable packet, unpinned
  host, or no IP pin all resolve to *drop*. Firecracker adds a TAP behind
  nftables default-deny; when the tunnel is configured the TAP is pinned
  deny-all so the audited tunnel is the sole path.

- **Secrets never enter the guest.** A per-VM host-side substitution endpoint
  swaps an opaque placeholder for a real credential only on the outbound leg,
  after a destination allow-list check, with a per-VM name-constrained
  intermediate CA (claim 13; ADR-003 §secret-bound destinations; the claim-16
  egress-substitution leak-gate).

Every one of these mechanisms depends on the host being able to see, name,
authorize, and audit each destination the guest reaches.

## Why veilid conflicts on the guest path

The conflict is structural, not incidental:

| mvm requires | veilid provides |
| --- | --- |
| Host names + authorizes every destination (IP-pinned, default-deny) | Guest addresses opaque `RouteId`/`NodeId`; destination is *hidden by design* |
| No guest-side IP stack (vsock-only); host is the sole egress origin | A full in-guest overlay stack that originates its own encrypted flows |
| Every outbound flow audited on the vsock seam | Onion-routed traffic the host cannot associate with a destination |
| Secret substitution at a host chokepoint the guest can't bypass | End-to-end encrypted guest-originated channel — nothing to substitute into |
| Sealed guest agent stays tokio-free, minimal fuzzed surface (claims 4/5/15) | Mandatory async runtime + megabytes of crypto/DHT in the guest binary |

Putting veilid in the guest is precisely the covert-egress channel that Plan 111
Workstream A audits *against* (DNS / control-plane / broker as covert egress).
It would give a compromised workload an anonymizing, host-unobservable exfil
path — nullifying claim 10, claim 13, and the audit log's egress record in one
move. This is disqualifying regardless of dependency cost.

## The only narrow niche — and why it still loses

The `NetworkProvider` trait is deliberately backend-agnostic and registers
mesh providers via `NetworkProviderRegistry` (`NetworkMode::Custom`), and
ADR-003 notes the same trait is implemented *outside* single-host mvm for
fleet-mesh networking. So a `kind() == "veilid"` provider is *mechanically*
constructable. That is the shallow reading. It fails on substance:

1. **Wrong repo.** Fleet-mesh between coordinators/hosts is an **mvmd**
   concern; this repo (mvm) owns single-VM guest egress, which veilid must
   never touch.
2. **Impedance mismatch with the trait contract.** `NetworkSpec` is *a
   deny-by-default policy over explicit admitted destinations plus a
   `slot_index`*. veilid has no notion of an admitted IP allow-list to enforce
   or a `policy()` to report; its model is "reach any peer anonymously." The
   trait would host it in name only.
3. **Anonymity is a liability for a control plane.** A fleet mesh *wants* to
   know exactly which authenticated host it is talking to. WireGuard/Tailscale
   (the incumbent providers) give authenticated, non-anonymous, low-dependency
   transport. veilid's sender/receiver privacy is dead weight — or worse, an
   auditability regression — for that role.
4. **No genuine gap.** There is no current mvm requirement (NAT-traversing,
   censorship-resistant, central-authority-free rendezvous) that the incumbents
   don't already cover for the fleet case.

## Weighed against the binding constraints

- **Limit dependencies (ADR-002):** hard fail. ~2M SLoC transitive, a second
  full crypto stack duplicating what `mvm-core::crypto` already carries, a
  mandatory async runtime, and a runtime dependency on an external peer network
  — the antithesis of "reuse workspace crypto crates; question every new dep."
- **No lock-in / isolate transports behind traits:** the trait *seam* survives,
  but veilid's model can't be isolated behind it cleanly because its transport
  *is* the abstraction — you would be modeling an anonymity overlay through a
  deny-by-default egress-policy interface. That is lock-in dressed as a plugin.
- **No external services / hermetic + deterministic:** needs bootstrap peers /
  DHT rendezvous to function — an external, non-deterministic runtime service,
  against the same grain as the no-external-cache-provider posture.
- **Auditable-vsock-seam invariant:** direct violation on the guest path (above).
- **Claim 10 / claim 13 / claim 16:** each defeated by an anonymizing,
  host-unobservable, guest-originated transport.

## Decision

**Do not adopt veilid for mvm networking.** It is architecturally opposed to
the host-mediated, default-deny, vsock-only, fully-audited egress model on the
guest path, and it is a heavy, external-network-dependent, license-divergent
dependency that duplicates the workspace crypto stack. The only pluggable seam
belongs to mvmd's fleet mesh, where authenticated WireGuard/Tailscale providers
already win and veilid's anonymity is a liability. Revisit only if mvmd ever
develops a concrete need for decentralized, central-authority-free coordinator
rendezvous — and even then benchmark it against a plain authenticated mesh
first, and keep it strictly out of any guest data path.

## Sources

- [veilid-core repository](https://gitlab.com/veilid/veilid/-/tree/main/veilid-core)
- [veilid-core on docs.rs](https://docs.rs/veilid-core)
- [veilid-core on lib.rs](https://lib.rs/crates/veilid-core)
- [Veilid developer book — Why Veilid](https://veilid.gitlab.io/developer-book/why-veilid/index.html)
- mvm `specs/adrs/003-hypervisor-egress-policy.md`
- mvm `crates/mvm-net/src/{provider,enforcement,registry,lib}.rs`
- mvm `crates/mvm-hostd/src/smoltcp_egress.rs`, `crates/mvm-runtime/src/network_provider.rs`
