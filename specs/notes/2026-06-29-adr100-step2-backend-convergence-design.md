# ADR-100 Step 2 — converge Firecracker / libkrun / vz onto vsock-only egress

Step 1 is done: the in-house VMM (HVF reference) carries a workload guest with **no
NIC** — control, the transient workload-exit signal, and egress all ride vsock,
with the host gateway enforcing the claim-10 decision (deny-default, allow + TCP
proxy, admitted-policy gate, DNS pins, async streaming). This note sequences Step 2:
removing the virtio-net NIC from the other workload backends and routing their
egress over the same vsock gateway. It is a design for review — no production code
should change until the order and the guest-image story below are agreed.

## Where each backend stands today

All three carry a guest NIC and enforce claim-10 *around* it (three mechanisms):

- **Firecracker** — virtio-net + host tap; egress default-deny via nftables
  (`install_default_deny`). Linux/KVM, workload-bearing (Tier 1).
- **libkrun** — `krun_add_net_unixgram` → gvproxy (macOS) / passt (Linux); egress
  via the gateway-bridge `PlanFlowPolicy` + packet scans. Workload-bearing.
- **vz** — Virtualization.framework NAT via gvproxy. macOS, workload-bearing.
- **qemu** — dev/test only, claim-10 deliberately not wired (Tier 2). Out of scope
  except for the CI-guard exemption note.

Each guest therefore still runs a full IP stack, and the egress decision lives in a
different place per backend. ADR-100's end state collapses all of that to one rule
set (`CanonicalEgress`, already shared) and one transport (vsock).

## Target shape (same as HVF)

Two reusable pieces, one per side of the vsock:

1. **Host-side egress server** — the connect→decide→proxy state machine already in
   `vmm::vsock` (`handle_egress_request` + `drain_egress` + `EgressGate`). For the
   external VMMs (FC/libkrun/vz) this logic belongs in the shared bridge
   (`mvm-vm-host` `mvm-bridge`), which already terminates their host-side vsock and
   already holds the `PlanFlowPolicy`. Extract the decision+proxy core into a
   backend-agnostic module both the in-house VMM and the bridge call, so there is
   exactly one egress server implementation.

2. **Guest-side egress client** — a tiny in-guest shim that turns an outbound
   connect into the vsock egress protocol (`SUBSTITUTION_PORT` framing: first frame
   = `"ip:port"`, then stream bytes). Today the HVF demo guests speak this directly;
   real workloads expect a socket API. Options, cheapest first:
   - **a)** an in-guest transparent proxy (a `mvm-guest-helpers` bin) that listens
     on localhost and forwards over vsock — workloads keep `connect()`, no NIC.
   - **b)** an LD_PRELOAD/syscall shim — fragile, rejected.
   - **c)** kernel `AF_VSOCK`-backed netdev — large, later.
   Start with (a); it requires no workload change and no IP stack.

## Sequencing (why this order)

1. **Extract the host egress server** into a shared module (no behavior change;
   HVF keeps working, covered by the existing live echo + unit tests). Pure
   refactor, lands first, de-risks everything after.
2. **Guest egress client (option a)** baked into the rootfs by `mkGuest`, behind a
   build flag so it ships only in images that opt in. Prove it on HVF (already
   NIC-less) end to end with a real workload before touching a NIC-bearing backend.
3. **libkrun first** of the NIC backends: add the vsock egress server to its bridge
   path, boot a guest with the egress client and **no `krun_add_net`**, prove parity
   (deny-default + allow + a real fetch) against the gateway-bridge baseline, then
   remove the NIC attach. libkrun first because its egress is already vsock-adjacent
   (unixgram) and its bridge already holds the policy.
4. **vz**, then **Firecracker** — same pattern. Firecracker last: its nftables path
   is the most battle-tested claim-10 enforcement, so it stays as the fallback
   reference longest.
5. **Widen `check-vsock-only-egress`** to each backend's dir as it converges, and
   delete its NIC attach + per-backend enforcement (nftables / PlanFlowPolicy
   packet scans) only once the vsock path is the sole egress and proven. qemu stays
   exempted (documented Tier 2, dev/test).

## Risks / guardrails

- **Production paths.** FC/libkrun/vz carry untrusted multi-tenant workloads (via
  mvmd). Each cutover is parity-gated: keep the NIC path until the vsock path passes
  the same claim-10 matrix live, behind a flag, reversible.
- **DNS.** The NIC path resolves names in-guest; vsock-only resolves host-side via
  the pin registry (as HVF does). Workloads that resolve names themselves need the
  guest client to proxy DNS too, or a host resolver over vsock — scope before vz/FC.
- **Performance.** The proxy adds a host hop + (on the in-house VMM) the heartbeat;
  the external VMMs already hop through the bridge, so the delta is small. Measure
  per backend before deleting the NIC.
- **Guest image size / boot.** Option (a) adds one small bin to the rootfs; no IP
  stack is a net reduction.

## Definition of done for Step 2

Every workload backend boots a guest with no virtio-net device; all egress flows
guest → vsock → shared host gateway → claim-10 decision; `check-vsock-only-egress`
covers every workload-backend dir; the per-backend NIC-era enforcement is deleted;
the claim-10 witness matrix passes live on each backend over the vsock path.
