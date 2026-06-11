# ADR-079 — App-builder product surface: adopt the ergonomics, reject the isolation model

**Status:** Accepted 2026-06-10. Implemented by
[`specs/plans/181-app-builder-product-surface.md`](../plans/181-app-builder-product-surface.md).
**Extends** [ADR-070](070-browser-reachable-verification-surface.md) (the
mvm-primitive ↔ mvmd-transport boundary), and builds on
[ADR-078](078-rvproxy-gateway-ownership.md) / Plan 179 (the first-party gateway
seam preview ingress publishes through) and the network-provider seam in
ADR-064. **Cross-refs:** ADR-002 (security posture — claims 1/2/10 are the lines
this ADR refuses to cross), ADR-041 (signed/audited execution plans — where
published ports get signed), Plan 33 (hosted transport — mvmd owns it),
Plan 170 (the same primitive↔product split applied to density), Plan 118 /
Plan 123 C4 / Plan 175 (warm pool + warm-start, the wake-on-access machinery),
Plan 169 / Plan 172 (agent-RPC + streamed exec, the task/files transport).
**Input:** a comparison against a sibling self-hosted AI-app-builder backend.

## Context

A sibling self-hosted AI-app-builder backend delivers a DX mvm does not yet
match: a single request creates an isolated environment, runs a coding agent in
it, and returns a **live, shareable preview URL**; instances `stop` to free RAM
and **wake on access**; a tasks API streams agent progress and a files API edits
the workspace; one command installs the whole stack and prints runnable next
steps; uninstall is graduated and workspace-preserving by default.

It buys that DX cheaply by discarding exactly the properties mvm exists to
provide. Its isolation is Docker containers; its control plane and edge router
run with the **Docker daemon socket mounted** (root-equivalent on the host) and
**symmetric host-path bind mounts** so sandboxes reach files by host path; its
API auth is **off by default** and its containers carry **no resource caps by
default**. Each of those is a direct contradiction of an mvm claim — claim 1
(no host-fs access beyond explicit shares), claim 2 (no guest elevation to
uid 0), claim 10 (no untrusted egress without policy), and the jailer/cgroup
posture.

mvm has the inverse profile: a much stronger engine (microVM isolation,
signed/audited execution plans, default-deny egress, secret substitution —
claims 1–15) behind a CLI-first surface that does not deliver the product loop.
The question this ADR settles is **which half of the sibling's design we take.**

The ergonomics do not depend on the isolation. The preview loop rides the
gateway seam we already own (ADR-078); wake-on-access rides warm-start
(Plan 123 C4 / Plan 175); the task/files surface rides agent-RPC + streamed
exec (Plan 169 / Plan 172); the lifecycle verbs and install/uninstall are CLI
plumbing on the `vm`/`env` groups. None of it requires relaxing a claim. The
weak isolation is not load-bearing for the DX — it is just the cheapest engine
the sibling had to hand.

## Decision

1. **Adopt the product-surface ergonomics; reject the isolation model.** mvm
   grows the create→agent→preview-URL loop, the instance-vs-workspace lifecycle
   split, a streamable task/files protocol, and one-command install/uninstall.
   mvm does **not** adopt container isolation, a daemon-socket-mounted control
   plane, host-path mounts into a workload, auth-off/caps-off defaults, or
   baked-in coding agents. These rejections are normative non-goals, recorded so
   they are not relitigated when the DX gap is felt again.

2. **Split every capability into an mvm-side primitive and an mvmd-side product
   leg, per ADR-070.** mvm ships the bridgeable primitives — a signed
   published-ports model, a per-port routing label at the gateway seam, a
   wake-on-access `VmBackend` hook, the task/files vsock protocol with an
   SSE-ready event shape, and the idle-TTL/keepalive contract. mvm does **not**
   grow a multi-tenant HTTP listener or tenant auth; that transport + auth +
   wildcard-DNS/TLS surface is mvmd's (Plan 33 / ADR-070 §5). This is the same
   boundary Plan 170 drew for density.

3. **One exception: a local, single-machine dev ingress lives in mvm.** So
   `mvmctl up`/`run` can hand a contributor a working
   `http://s-<id>-<port>.preview.localhost` URL on one box, mvm carries a tiny
   first-party reverse proxy bound to `localhost` only — no auth, no TLS, no
   wildcard DNS. This occupies the same single-host, no-tenant scope `mvmctl
   dev` already does, so it crosses no new trust boundary; `*.localhost`
   resolves to loopback in browsers with no DNS setup.

4. **Preview routing is L4 publication, not an HTTP proxy, and only published
   ports are routable.** The gateway exposes explicitly published guest ports
   under a stable id-derived key (`s-<vm>-<port>`); it does not parse HTTP. The
   published set is signed into the `ExecutionPlan` (audited, not ambient), so
   default-deny egress (claim 10) and the gateway mediation seam are unchanged —
   exposing a preview port is an admitted, recorded act, not a hole.

5. **The substrate stays agent-agnostic.** The task protocol carries an opaque
   runner/entrypoint reference; no coding-agent binary is baked into any rootfs.
   Agent tooling is a workload/SDK concern.

## Consequences

- mvm gains the product loop that makes app-builder backends feel magical, on
  top of an engine the sibling cannot match (strong enough to run *untrusted*
  code) — a combination neither the sibling (too weak to trust) nor mvm's
  current CLI-first surface delivers.
- mvmd gets a clean set of primitives to wrap: published-ports + routing label +
  wake hook → fleet preview URLs; the task/files vsock protocol + SSE shape →
  its HTTP API; the keepalive/idle-TTL contract → its density loop (already
  Plan 170 WS-D).
- No claim regresses. Preview ports are signed and audited; the wake hook reuses
  warm-start; the local ingress is loopback-only. `xtask check-claim-catalog`
  stays green.
- A small, owned local reverse proxy enters the tree (reusing the
  rvproxy/hyper surface), and a workspace-data lifecycle becomes a named concept
  in `mvm_core::config` distinct from instance lifecycle.

### Follow-ups

- [ ] Plan 181 WS-A–WS-D implementation (preview ingress, lifecycle verbs,
  task/files protocol, install DX).
- [ ] Decide L4-only-now vs. a fuller local HTTP router (Plan 181 WS-A open
  decision); recommendation is L4 + loopback proxy first.
- [ ] If/when a hosted (non-localhost) preview surface is wanted, it is an mvmd
  effort (Plan 33), not mvm — same disposition as ADR-070 §5's hosted console.

## Alternatives considered

- **Take the sibling's stack wholesale (containers + socket + host mounts).**
  Rejected: it discards claims 1/2/10 and mvm's reason to exist. The DX does not
  require it.
- **Build the full multi-tenant preview/ingress + auth in mvm.** Rejected:
  violates the ADR-070 / Plan 33 boundary that reserves transport + tenant auth
  for mvmd. mvm ships primitives + a single-machine dev ingress only.
- **Ambient (unsigned) port exposure for convenience.** Rejected: it would make
  egress reachability an unrecorded side effect, weakening claim 10. Published
  ports are signed into the plan and audited.
- **Bake specific coding-agent binaries into the base image like the sibling.**
  Rejected: couples the substrate to specific agent tooling; the runner stays
  opaque.
- **Do nothing (keep the CLI-first surface).** Rejected: the product loop is the
  difference between an engine and a product, and it is achievable with zero
  claim cost.
