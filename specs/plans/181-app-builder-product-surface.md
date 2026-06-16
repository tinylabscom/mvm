# Plan 181 — App-builder product surface (preview ingress + lifecycle verbs + task/files protocol + install DX)

> **Numbering:** 181 is the next free plan number after 180. Confirm still free
> at merge.
>
> **Decision source:** [ADR-079](../adrs/079-app-builder-product-surface.md)
> (adopt the ergonomics, reject the isolation model). **Boundary:**
> [ADR-070](../adrs/070-browser-reachable-verification-surface.md) — browser/remote
> **transport + tenant auth is mvmd's** (Plan 33); mvm owns only the
> cleanly-bridgeable primitives + a local single-machine dev ingress. The gateway
> seam this builds on is owned by
> [ADR-078](../adrs/078-rvproxy-gateway-ownership.md) /
> [Plan 179](179-rvproxy-gvproxy-replacement.md).

**Goal:** Put a best-in-class AI-app-builder *product surface* on top of mvm's
hardened microVM substrate — the create→agent→**live preview URL** loop, a
clean instance/workspace lifecycle, a streamable task/files protocol, and a
one-command install/uninstall — **without adopting the weak isolation that
sibling self-hosted app-builder backends rely on to get that DX cheaply.**

## Why now

A sibling self-hosted AI-app-builder backend gets a delightful DX (one HTTP
call → isolated env + coding agent + shareable `*.preview.localhost` URL, plus
stop/wake/keepalive lifecycle and a tasks/files API) by running **Docker
containers with the daemon socket mounted and host-path bind mounts** — exactly
the host-fs-access and privilege-escalation surface mvm claims 1/2 exist to
kill, with auth off and no resource caps by default. mvm has the inverse
profile: a far stronger engine (microVM isolation, signed/audited execution
plans, default-deny egress, secret substitution — claims 1–15) behind a
CLI-first surface that does **not** yet deliver that product loop. The
high-leverage move is to graft the *ergonomics* onto our *engine*. None of the
ergonomics require relaxing a single claim; they ride seams we already own
(gateway bridge, warm-start, agent-RPC/streamed-exec, the `vm`/`env` CLI
groups).

## Architecture (mvm primitive ↔ mvmd product, per ADR-070)

Every workstream below ships an **mvm-side primitive** and names the **mvmd-side
product leg** that consumes it. mvm never grows a multi-tenant HTTP listener or
tenant auth — that is fleet-orchestration territory (Plan 33 / ADR-070 §5). The
exception is a **local, single-machine dev ingress** (`localhost` only, no auth,
no wildcard TLS) so `mvmctl up`/`run` can hand the contributor a working URL on
one box — the same scope `mvmctl dev` already occupies.

Load-bearing seams reused (do not fork):

- Gateway / egress plane: `crates/mvm-hostd/src/supervisor/gateway_bridge.rs`,
  `crates/deps/libkrun-sys/src/gvproxy.rs` (rvproxy under Plan 179), Linux
  `passt`. Per-port publication and wake-on-access hang here.
- Backend trait + wake: `crates/mvm-backend` (`VmBackend`), `VmBackend::warm_start`
  (Plan 123 C4 seam), warm pool + reaper (Plan 118 / Plan 170 WS-B).
- Agent RPC / streamed exec: Plan 169 (`fs`/`cp` transport), Plan 172
  (`ExecEvent` streamed exec), Plan 173 (exec timeout).
- CLI groups: `vm` (single-VM lifecycle) and `env` (bootstrap/uninstall/update),
  post Plan 178.
- Paths/config: `mvm_core::config` (never inline `$HOME` joins).

**Tech stack:** Rust; existing supervisor/gateway/backend crates; vsock
agent-RPC; the `mvmctl` CLI. No new heavy dependencies — a local reverse proxy,
if needed, reuses the rvproxy/hyper surface already in-tree.

---

## Guardrails (every task)

- **Reject the sibling's isolation model, not just decline it.** No Docker
  socket, no host-path bind mounts into a workload, no auth-off default beyond
  the existing localhost-dev scope, no removing resource caps. Capture these as
  explicit non-goals (below) so they are not relitigated.
- Do not weaken any of claims 1–15. Preview ingress routes only **explicitly
  published** ports; default-deny egress (claim 10) and the gateway mediation
  seam (claim 10 no-bypass) are unchanged.
- Keep the substrate **agent-agnostic.** The task protocol carries an opaque
  entrypoint/runner; mvm does not bake specific coding-agent binaries into any
  rootfs (that is a workload/SDK concern).
- Respect the ADR-070 boundary: no multi-tenant HTTP listener or tenant auth in
  mvm. mvmd owns transport + auth + wildcard DNS/TLS.
- Workspace-data lifecycle is distinct from instance lifecycle (the verb split
  below) and both honor `mvm_core::config` data dirs / `MVM_DATA_DIR`.

---

## WS-A — Preview ingress: published ports + wake-on-access + local URL

The marquee item: building a workload should hand you a live URL, and hitting a
stopped workload's URL should wake it.

**mvm primitives**

- [ ] **Published-ports model.** A first-class `published_ports: Vec<u16>` on the
  launch/admission path (signed into the `ExecutionPlan` so the set is audited,
  not ambient), surfaced on `mvmctl vm list`/`status --json`. Only listed ports
  are routable; everything else stays default-deny.
- [ ] **Per-port routing label at the gateway seam.** Teach
  `gateway_bridge.rs` / the rvproxy spawn to expose published guest ports on the
  host with a stable, id-derived key (`s-<vm>-<port>`), the unit an external
  router (an edge router, in mvmd) keys on. No HTTP parsing in mvm — this is
  L4 publication, not an HTTP proxy.
- [ ] **Wake-on-access seam.** A `VmBackend` hook so a request to a *stopped*
  (RAM-freed) instance triggers `warm_start` (Plan 123 C4 / Plan 175) before the
  connection is serviced, with a bounded cold-wake fallback. The trigger is
  generic (a connection attempt on a published port); the *router* that detects
  it and calls the hook is local (WS-A local ingress) or mvmd (fleet).
- [ ] **Local dev ingress (single machine, localhost only).** A tiny first-party
  reverse proxy (reuse the rvproxy/hyper surface) that maps
  `http://s-<id>-<port>.preview.localhost` → the published host port, and calls
  the wake hook on access. No auth, no TLS, no wildcard DNS — `*.localhost`
  resolves to loopback in browsers. `mvmctl up`/`run` prints the URL(s) for each
  published port in its "next steps" output (ties to WS-D).

**mvmd-side product leg (named, not built here)**

- Multi-tenant edge router: wildcard `*.preview.<domain>` DNS, TLS via
  cert resolver, tenant auth on the route, and the fleet wake-on-access detector
  calling the same `VmBackend` hook. Consumes the published-ports model + routing
  label + wake hook verbatim.

**Decision to confirm with owner:** start L4 (publish port + print
`localhost:<port>` and the `s-<id>-<port>.preview.localhost` hostname via the
local proxy) and leave HTTP-aware routing to mvmd, vs. ship a fuller local HTTP
router now. Recommendation: L4 + local proxy first (cheap, owns nothing we don't
already own); richer routing rides mvmd.

**External-benchmark datapoint (supports L4-first).** A DX comparison against a
peer self-hosted sandbox backend — whose pitch is the same create→agent→live
preview URL loop — found the preview URL is the *only* local-DX gap worth
closing here; the rest of its surface is either already matched (one-command
bring-up, live output streaming) or correctly mvmd's:

- Its idle-sleep + wake-on-request density and its HTTP control plane sit on the
  mvmd side of ADR-070, not in mvm. The wake-on-access *seam* above is the mvm
  primitive; the detector/router stays in mvmd (fleet) or the local proxy (dev).
- Its lazy-wake exists to hide slow cold starts. Our warm pool (Plan 118) +
  sub-second up/down (Plan 198) already cover that, so the local proxy can dial
  the wake hook synchronously without a "waking…" UX of its own.
- That peer buys the DX with Docker-socket isolation, host-path mounts, and
  auth/caps off — the posture §Non-goals already rejects. The takeaway is the
  *shape* of the URL, not the trust model.

This validates shipping L4 + local proxy first and resisting an ambient,
per-route HTTP proxy with its own port registry (the cheap-but-weaker shape the
peer uses): keep ports signed into the `ExecutionPlan` and route at the gateway
seam. Note publication is **not** claim-15-gated — a sealed prod workload
*serving its published port* is the intended behavior, distinct from interactive
console access; only ambient (unpublished) ports stay default-deny.

## WS-B — Lifecycle verb taxonomy (instance vs. workspace)

Adopt the sibling's clean split between *instance* lifecycle and *workspace-data*
lifecycle on the `vm` group (post Plan 178), built on the warm-pool/reaper and
warm-start primitives we already have.

- [ ] **`vm stop`** — free RAM / suspend the instance; **wake-on-access**
  re-materializes it (WS-A hook). Distinct from today's terminate. Maps to
  `warm_start`-capable backends; fail-closed label on those that can't suspend.
- [ ] **`vm rm` (delete)** — drop the instance, **preserve the workspace**
  directory (default). The non-destructive default.
- [ ] **`vm purge`** — drop the instance **and** delete the workspace data.
  The explicit destructive verb.
- [ ] **`vm keepalive`** — extend the idle TTL on the reaper (Plan 118 / Plan 170
  WS-B), so an active session isn't reaped. mvmd's density loop (Plan 170 WS-D)
  consumes the same TTL.
- [ ] Workspace-data lifecycle is a named concept in `mvm_core::config`
  (a per-instance workspace dir under the data root); stop/delete/purge act on it
  consistently and `--json` reports its state.
- [ ] Audit taxonomy: each verb emits a distinct chain-signed `cmd.*` event
  (mirrors the Plan 178 note — claims 8/12/13 event names stay stable).

## WS-C — Streamable task + files protocol (agent-agnostic)

Make headless, streamable agent runs and workspace file access first-class —
over vsock, agent-agnostic, with an SSE-shaped event stream mvmd can bridge to
HTTP directly.

- [ ] **Async task protocol.** A `submit task {entrypoint/runner, prompt-or-args}
  → task id → poll/stream events → result` shape over the agent-RPC transport
  (Plan 169), reusing the `ExecEvent` streaming model (Plan 172) so progress is
  incremental. The "agent" is an **opaque runner reference**, not a baked-in
  binary list.
- [ ] **SSE-ready event shape.** The event stream serializes to the shape mvmd
  can forward as `text/event-stream` with no re-modeling (mvm emits the events;
  mvmd owns the HTTP/SSE transport per ADR-070).
- [ ] **Files API parity.** Confirm/extend the Plan 169 `fs` RPC to cover the
  read/write/append surface (`GET`/`PUT {path, content, append}`) an editor needs
  without an `exec`. If a gap exists, close it on the existing transport — do not
  add a second file channel.
- [ ] **`mvmctl` thin verbs** exercising the protocol locally (`vm task …`,
  `vm files …`) so the surface is testable without mvmd.

**mvmd-side product leg:** `POST /tasks {prompt, agent}` + `GET …/events` (SSE)
+ `GET/PUT …/files` HTTP endpoints, tenant-authed, wrapping these vsock
primitives.

## WS-D — Install / uninstall DX

Match the sibling's "one command → working endpoint + copy-paste next steps" and
its respectful, graduated uninstall.

- [ ] **`curl | sh` installer** (folds the unowned Plan 159 WS-5 D item): detect
  prerequisites, print exactly what's missing with install hints (reuse
  `doctor`), be idempotent, never touch anything outside mvm's data/cache dirs.
- [ ] **"Next steps" output** after `env bootstrap` / `dev up` / `up`: print the
  control surface, the preview URL(s) (WS-A), and literal, runnable copy-paste
  commands — the README's first screen, emitted by the tool.
- [ ] **Graduated uninstall** on `env uninstall`: default removes only what mvm
  created and **keeps workspaces**; `--images` also drops built images;
  `--data` deletes workspaces + state; `--all` full removal. Mirror the flag
  surface, fail-safe defaults, and "removes only what it created" guarantee.

---

## Non-goals (deliberately rejected — do not relitigate)

These are the parts of the sibling's DX that buy convenience by discarding mvm's
reason to exist:

- **Container isolation / Docker-socket-mounted control plane.** mvm is microVM
  isolation; we do not mount a daemon socket or run workloads as containers.
- **Host-path bind mounts into a workload.** Violates claim 1 (no host-fs access
  beyond explicit shares). Workspaces are owned dirs surfaced *to the host*, not
  the host filesystem surfaced *into the guest*.
- **Auth-off / resource-caps-off defaults.** Beyond the existing localhost-dev
  scope, the product surface stays authed (mvmd) and capped (jailer/cgroups).
- **Baking specific coding agents into the base image.** The runner is opaque;
  agent tooling is a workload/SDK concern.
- **A multi-tenant HTTP listener or tenant auth in mvm.** Reserved for mvmd
  (ADR-070 §5 / Plan 33). mvm ships only the bridgeable primitives + a local
  single-machine dev ingress.

## Cross-repo dependency (mvmd)

mvmd consumes, in order of value: the published-ports model + per-port routing
label + wake-on-access hook (WS-A) for fleet preview URLs; the task/files vsock
protocol + SSE event shape (WS-C) for its HTTP API; the idle-TTL/keepalive
contract (WS-B) for its density loop (already owned there per Plan 170 WS-D).

## Success criteria

- [ ] `mvmctl up --flake <app>` with a published port prints a working
  `http://s-<id>-<port>.preview.localhost` URL on a single machine; hitting it
  after `vm stop` wakes the instance.
- [ ] `vm stop` / `vm rm` / `vm purge` / `vm keepalive` behave per the
  instance-vs-workspace split; `--json` reports workspace state; each emits its
  distinct audit event.
- [ ] A headless task runs over vsock with incremental events; `vm files`
  reads/writes a workspace file without `exec`; the event stream serializes
  SSE-ready.
- [ ] `curl | sh` install lands a working endpoint and prints runnable next
  steps; `env uninstall` graduated flags behave with workspace-preserving
  defaults.
- [ ] No claim regresses: `xtask check-claim-catalog` green; default-deny egress
  intact; only published ports routable.
- [ ] `cargo nextest run --workspace` + `cargo test --workspace --doc` green;
  `cargo clippy --workspace -- -D warnings` clean; `cargo fmt --all -- --check`
  clean.

## Phasing

WS-A is the headline and the largest; WS-B and WS-D are mostly CLI + lifecycle
plumbing on existing primitives and can land first as quick wins. WS-C extends
the agent-RPC transport and pairs naturally with mvmd work. Suggested order:
WS-D (DX, low risk) → WS-B (lifecycle) → WS-A (ingress) → WS-C (task/files).
