# Plan 236 Phase 2B — production host-forwarder unification (ADR-110)

**Date:** 2026-07-11
**Decision doc:** ADR-110 (uniform userspace vsock egress).
**Goal:** ship the production-ready `smoltcp`-everywhere host forwarder on the two
production backends (libkrun, Firecracker) plus HVF — unprivileged, no NAT device,
retiring the Linux host-TUN + kernel-NAT path — **without colliding** with the Phase 2A
vsock-protocol work in `feat/plan-236-2a-l3-forward`.

## Sequencing decision (why this shape)

**One atomic PR, built on the settled protocol. Not split into scaffolding-now.**

- The unification is inherently atomic: promote `smoltcp` to the universal forwarder,
  wire the `l3_forward` dispatch on every backend, retire `host_tun`/NAT, add
  `HostIcmpEcho`, prove TCP/UDP/ICMP/DNS parity, land a live witness. A half-applied
  forwarder swap is not shippable; un-gating `smoltcp` on Linux without the dispatch
  swap is dead code behind `#[allow(dead_code)]` plus needless churn.
- It plugs **into** the Phase 2A protocol — the `l3_forward` policy resolution and the
  capability triple (`no_routable_guest_nic` / `host_vsock_proxy` /
  `packet_tunnel_forwarder`). Building the production data plane against a wire contract
  that is still being defined is the wrong order. Phase 2A is the foundation; Phase 2B
  is the host-side impl beneath it.

**Land it stacked on the Phase 2A branch** the moment that WIP is committed (a strict
descendant → zero conflict → fast-forwards onto main after Phase 2A merges), **or** off
`main` once the Phase 2A protocol lands. Either way it is one coherent, reviewable,
live-proven PR.

## Collision surface (verified 2026-07-11)

The Phase 2A WIP heavily rewrites `network_tunnel.rs` (+1410), `network_tunnel_spawn.rs`
(+352), `net_l3.rs` (+180) and adds the protocol doc, the no-guest-NIC claim, and the
legacy-workload-transport gate. It does **not** touch `smoltcp_egress.rs`,
`host_tun.rs`, `mvm-hostd/src/lib.rs`, or `mvm-hostd/Cargo.toml`.

- **No overlap:** the wire protocol, ports, frame layout, capability flags, the
  `smoltcp` forwarder impl, and the retired `host_tun` file. Phase 2B owns the forwarder
  impl; Phase 2A owns the wire.
- **Only overlap:** the forwarder **dispatch** in `network_tunnel.rs` /
  `network_tunnel_spawn.rs` — where the worker reads the `l3_forward` policy and picks a
  forwarder. That is the one region that must land on Phase 2A's final version.

## Seam ask to Phase 2A

Keep the host forwarder a **single swappable dispatch point** behind the `l3_forward`
policy (the `TunnelPacketPolicy` resolution). If the "pick a forwarder" decision is one
localized site, Phase 2B is a small impl swap there, not a rewrite of the orchestration
— which shrinks the eventual rebase to near-zero.

## Slices (one PR, or a tight stack on Phase 2A)

1. Promote `smoltcp_egress` from `#[cfg(target_os = "macos")]` to all targets; add the
   `smoltcp` dep to the Linux build (own `Cargo.toml`/`lib.rs` edits — collision-free).
2. `HostIcmpEcho` trait + per-OS impls: Linux unprivileged ping socket
   (`SOCK_DGRAM`/`IPPROTO_ICMP`, `ping_group_range`), macOS `SOCK_DGRAM`/`IPPROTO_ICMP`,
   Windows raw ICMP (new files — collision-free).
3. Wire the `l3_forward` dispatch to `smoltcp` on **every** backend (libkrun,
   Firecracker, HVF); drop the host-TUN branch. (The one Phase-2A-overlapping edit.)
4. Retire `host_tun.rs` + the nft NAT setup/teardown + the `host_tun_nat_live` witness.
5. Prove **TCP + UDP + ICMP + DNS-pin** parity through `smoltcp` on **Linux** (unit +
   gated integration) — smoltcp currently only exercised on macOS.
6. **Live workload-egress witness on a production backend** — the outstanding gap:
   - HVF on macOS 26 (this Mac; `smoltcp` is already the macOS forwarder): the original
     `machine run --image busybox --allow-host google.com -it -- /bin/sh` must resolve
     (pins → `/etc/hosts`), `ping google.com`, and reach an admitted TCP host, audited.
   - Linux + libkrun on a working host: same, over `smoltcp` instead of host-TUN+NAT.
7. CI green: no-MITM / no-semantic guards, the legacy-workload-transport gate,
   duplicate-majors, fmt/clippy/nextest, Linux zigbuild `--workspace --bins`.

## Production bar

Not done until slice 6 passes on **at least one production backend** and every guard in
slice 7 is green. Mechanism-only or macOS-only proof is not production-ready.

## Out of scope

- The option-C kernel-socket vsock proxy / TSI (ADR-110's documented escape hatch;
  benchmarked as unnecessary at this tier).
- The secret-substitution reconciliation (host-originated vsock substitution) — tracked
  separately; this note is the non-secret forwarder.
