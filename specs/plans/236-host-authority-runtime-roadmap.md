# Plan 236 — Host-authority runtime roadmap

**Status:** IN PROGRESS (Phase 2A refresh active; broad prerequisite line still NO-GO)  
**Created:** 2026-07-09  
**Goal:** turn `mvm`'s current security and architecture lead into a simpler,
more competitive product by finishing the host-authority model, removing
remaining guest-NIC and guest-directed escape hatches, narrowing the secrets
story to explicit host-owned authorities, and shipping a developer-grade
lifecycle on top of that runtime.

**Execution note (2026-07-10):** the prerequisite picture changed after synced
`origin/main` advanced on July 10, 2026. The merged Plan 219 refresh
(`Refresh Plan 219 grant-delivery branch on main`, PR `#1605`) and the merged
Phase 2A registry closeout (`Finish vsock port-handler registry production
closeout`, PR `#1599`) are now satisfied directly on `origin/main`. The three
remaining stale prerequisite branches were then refreshed into dedicated Codex
worktrees:
`codex/plan-236-plan202-refresh`,
`codex/plan-236-vsock-egress-refresh`, and
`codex/plan-236-plan216-refresh`. All three currently rebase cleanly and
collapse to `origin/main`, so the checker now treats "clean + aligned with
main after refresh" as GO rather than forcing an artificial ahead-of-main
delta. That means the broad branch-staleness blocker is cleared; the remaining
honest production-readiness blockers for Plan 236 are live-proof and closeout
evidence, not stale prerequisite worktrees.

**Execution progress (2026-07-10):** the gate turned `GO` and the Phase 1 →
Phase 2A pivot largely landed on `main`. Shipped: §1 delivers the host-signer
verb-grant anchor over the kernel cmdline to the vsock-only backends
(libkrun/HVF), so sealed guests pin and *selectively* enforce plan-bound grants
instead of failing to deny-all (PR `#1615`); §3.1 renames `no_guest_nic` →
`no_routable_guest_nic` with honest reachability semantics (PR `#1616`); the
Phase 2A workload delta gates the HVF egress endpoint on admitted policy so a
deny-all workload spawns no endpoint and fails closed, matching libkrun
(PR `#1619`); and the dead `HostBoundRequest` surface is removed. The §4
negative-path matrix surfaced a real bypass — `re_pin_verb_grant` verified the
resume envelope against its own embedded key — fixed by verifying against the
boot-pinned host-signer anchor with a shared verification core (closes the
self-forgery bypass). The remaining sealed-image trust blocker is now narrower:
the OCI `--prod` run path gained a real builder-VM dm-verity seal fallback on
the active closeout branch, with focused fallback tests plus green host
validation (`cargo clippy --workspace --all-targets -- -D warnings`, `cargo
test --workspace`), so the old "production/verity OCI seal path does not
exist" statement is no longer true on that branch. Remaining honest blockers
are the live-proof closeout for that new production seal path, the macOS
vsock-only enforcement witness, and binding restore-time authority to a per-VM
identity (cross-VM replay of a genuinely host-signed grant). The branch now
also carries the missing live-proof harness for the new OCI path:
`tests/oci_image_runner_smoke.rs` adds a macOS-only disabled-by-default
`run --image --prod` witness that requires a signed digest-pinned ref, `cosign`
on `PATH`, and an admitted OCI policy, then asserts the booted image left real
`rootfs.verity` + `rootfs.roothash` sidecars in the OCI cache. Focused host
validation for that harness is green (`cargo test --test
oci_image_runner_smoke -- --nocapture`, `cargo clippy --test
oci_image_runner_smoke -- -D warnings`); the missing piece is the
environment-backed live run itself, not the test surface.

## Thesis

`mvm` already has the right base posture:

- signed admission
- chain-signed audit
- vsock-first direction
- host-services model
- builder/runtime split
- rootfs integrity work

The remaining gap is not core security architecture. It is **execution
consistency**:

1. the host-authority boundary is not yet the only production shape on every
   path;
2. the vsock-only no-guest-NIC path is not yet universal across workloads and
   builders;
3. the secret-egress story is promising but still broader and rougher than it
   should be;
4. the local client/runtime lifecycle is still more operator-shaped than
   developer-shaped.

This plan closes those gaps without turning `mvm` into a transparent network
appliance. The winning line is: **explicit host authorities, audited vsock/UDS
transport, no guest-directed upstream sockets, and a cleaner runtime UX than
the field.**

## Non-goals

- Do not make transparent TLS interception the primary runtime primitive.
- Do not add any new production path where the guest opens arbitrary upstream
  sockets directly.
- Do not reintroduce gvproxy-era or guest-NIC compatibility fallbacks to make
  a benchmark pass.
- Do not split security authority across multiple overlapping control planes.
- Do not let SDK convenience bypass signed admission, audit, or host policy.

## Priority order

### P0 — Must land first

- [ ] Finish the host-authority transport boundary.
- [ ] Finish the vsock-only, no-guest-NIC workload path.
- [ ] Finish the builder path's no-guest-NIC cutover with live evidence.

### P1 — High leverage, competitive

- [ ] Ship a narrow, explicit destination-bound secret-egress path.
- [ ] Ship caller-owned runtime lifecycle through the `MvmClient` facade.
- [ ] Add a host-only mutable runtime control socket.

### P2 — Hardening and scale-up

- [ ] Tighten runtime-share/filesystem semantics.
- [ ] Complete lifecycle parity features such as reconfigure/health/warm paths.
- [ ] Publish stronger operational evidence and benchmark claims.

## Start trigger

This plan starts when leadership makes one explicit call:

- [ ] `mvm` is standardizing on the host-authority, no-guest-NIC, vsock-only
      runtime line as the default architecture path.

That decision is usually justified by one or more concrete triggers:

- [ ] The active vsock-only transport branches need integration rather than more
      isolated branch work.
- [ ] Linux builder smoke is still blocking the claim that the runtime is
      honestly vsock-only end to end.
- [ ] Secret-egress work needs a product-scope decision before more
      implementation lands.
- [ ] SDK/runtime lifecycle work is expanding again and needs one owning
      integration roadmap.

## Go / No-go checklist

Start execution on this plan only when the following are true:

- [ ] The current top-level product priority is to finish the host-authority
      transport line rather than open a competing runtime direction.
- [ ] We are ready to treat the current no-guest-NIC / vsock-only branches as
      the mainline architecture path.
- [ ] We are willing to treat transparent-network work as exploratory unless it
      proves value inside the host-authority model.
- [ ] The next integration work will begin with Phase 1 and Phase 2 inputs:
      `fix/agent-verb-grant-delivery`,
      `feat/vsock-port-handler-registry`, and
      `worktree-vsock-only-egress-cutover`.

Do not start execution on this plan when any of the following are true:

- [ ] The team still wants to compare multiple competing transport end states in
      parallel.
- [ ] The active no-guest-NIC branches are still too early to integrate and
      need more isolated prototyping first.
- [ ] The current quarter's priority is elsewhere and this plan would only add
      coordination overhead without implementation follow-through.

## Existing work that already shrinks this plan

These branches and plans should be treated as direct inputs, not parallel
competing epics:

- `feat/plan-202-native-host-services`
  - Residual cleanup only.
  - Reuse as the host-only daemon/control-plane proof point.
  - Do not reopen the process-moat question.
- `feat/plan-216-s0-mvm-client`
  - Keep as the seed for the local/remote facade.
  - Shrinks Phase 4 materially; do not redesign the crate from scratch.
- `fix/agent-verb-grant-delivery`
  - Directly contributes to the host-authority boundary.
  - Fold into Phase 1; it is not optional polish.
- `feat/vsock-port-handler-registry`
  - Direct input to readiness-driven host I/O and libkrun runtime proof.
  - Fold into Phase 2 instead of leaving it a refactor-only branch.
- `worktree-vsock-only-egress-cutover`
  - Direct input to workload no-NIC cutover.
  - Reuse its host-vsock proxy and builder-vsock egress lessons.
- `feat/vsock-transparent-net`
  - Treat as exploratory, not as the architecture baseline.
  - Salvage only the useful pieces: tests, handler abstractions, and evidence
    about denied paths.

Related landed or in-flight plans that should be reused instead of duplicated:

- Plan 202 — host services daemon
- Plan 204 — resident builder control plane
- Plan 211 — VM host process convergence
- Plan 216 — `MvmClient` facade
- Plan 219 — out-of-band agent verb grant delivery
- Plan 221 — in-process rootfs materialize
- Plan 223 — virtiofs root
- Plan 224 / 225 — machine reconfigure
- Plan 227 — instant-resume vsock-only sandboxes
- Plan 230 — two-surface consolidation
- Plan 232 / 233 — workload healthcheck lifecycle
- Plan 237 — HVF density memory footprint reduction

## Source lessons reflected here

This roadmap is grounded in a full-codebase analysis of a peer sandbox runtime,
not only its networking path. The emphasis on transport and egress exists
because that is where `mvm` still has the largest integration gap, but the
phases below reflect lessons from the whole system:

- **Runtime and launch model**
  - Reflected in Phases 4 and 5.
  - Why: the child-runtime ownership model, launch-config hygiene, and
    host-only mutable controls were among the strongest ideas in the review.
- **Protocol and relay structure**
  - Reflected in Phases 1 and 5.
  - Why: the review reinforced that `mvm` should keep one explicit guest
    request surface and avoid smearing host-only controls across the guest
    protocol.
- **Guest agent scope**
  - Reflected in Phases 1 and 2.
  - Why: the analysis supported a narrower guest role: guest requests host
    services, but does not become a general network actor with its own
    upstream authority.
- **Networking and policy enforcement**
  - Reflected most strongly in Phases 2 and 3.
  - Why: this is the area where `mvm` most needs convergence around the
    no-guest-NIC, vsock-only, host-authority direction.
- **Filesystem and rootfs model**
  - Reflected in Phase 6.
  - Why: the review reinforced the value of a narrow runtime share, explicit
    rootfs layering semantics, and keeping host/guest file exchange bounded.
- **Observability, audit, and evidence**
  - Reflected in Phase 7.
  - Why: the review confirmed that strong runtime evidence should remain a
    differentiator, but separated from policy and transport authority.
- **Runtime density and helper-count discipline**
  - Reflected in Phases 2, 4, and 7.
  - Why: the review supported fewer long-lived helpers, tighter host-owned
    runtime roles, and honest capacity claims rather than invisible process
    sprawl.

## Guardrails

- Host-owned authorities remain the only source of network, secret, audit, and
  mutable-runtime power.
- Domain/SNI/hostname inference may inform policy, but it must not become the
  primary authorization model.
- The guest may request work; it may not define the trust boundary.
- Every new runtime affordance needs a clear owner:
  - guest protocol
  - host-only control socket
  - signed admission plan
  - builder control plane
- Every production transport claim needs a live witness on both macOS and
  Linux.

## Phase 0 — Align the execution line

**Goal:** freeze the architecture line before more implementation branches drift.

- [ ] Ratify this plan's core rules in the relevant ADRs and plans:
  - no guest-directed upstream sockets
  - no production guest NIC path
  - host-only mutable runtime controls
  - explicit destination-bound secret egress
- [ ] Mark which existing plans become direct dependencies versus which are
  superseded by this roadmap.
- [ ] Merge or close planning-only branches that restate the same direction in
  incompatible language.
- [ ] Update `specs/02-roadmap.md` to point at this plan as the integration
  roadmap for the current host-authority push.

**Exit criteria**

- One current plan is the integration source of truth.
- No active branch is still assuming a guest-NIC or transparent-net-first end
  state without calling it out as exploratory.

## Phase 1 — Finish the host-authority boundary

**Why first:** this is the architectural moat. If this stays fuzzy, later
runtime and secret work will duplicate authority or weaken policy.

- [ ] Land the remaining Plan 219 work so sealed guests receive and enforce
  plan-bound verb grants on the real boot path.
- [ ] Audit guest protocol verbs and classify each as:
  - host authority request
  - host-only control-socket operation
  - disallowed in production
- [ ] Remove or quarantine any production path that still lets the guest define
  mutable runtime state outside signed admission or host-owned control.
- [ ] Make backend capability descriptors the honest authority surface:
  `{ vsock, no_guest_nic, host_vsock_proxy }` must mean exactly that.
- [ ] Add negative-path tests proving production guests cannot regain forbidden
  verbs or widen their authority through reconnect, resume, or fallback paths.

**Primary reuse**

- Plan 202
- Plan 215 / 219
- Plan 230
- branch `fix/agent-verb-grant-delivery`

**Exit criteria**

- Every production guest-to-host privileged action is either a signed-plan
  consequence or an explicit host service call.
- No production path depends on guest-defined arbitrary external connectivity.

## Phase 2 — Make the data plane honestly vsock-only

**Why second:** the biggest competitive and security payoff is an audited
no-guest-NIC runtime that is actually true on both workload and builder paths.

### Phase 2A — workload path

- [ ] Fold `feat/vsock-port-handler-registry` into mainline and keep its
  readiness-driven host-I/O model.
- [ ] Finish the libkrun/HVF workload path so no workload boot depends on a
  guest NIC, gvproxy, or passt helper.
- [ ] Keep the port-handler registry and host-vsock proxy as explicit runtime
  infrastructure, not hidden compatibility paths.
- [ ] Make endpoint spawning an admitted-runtime decision, not a universal per-VM
  default:
  - fully deny-all, no-secret workloads should not pay for an unused endpoint
  - any admitted egress or secret authority keeps the endpoint fail-closed
- [ ] Add live workload witnesses for:
  - no guest NIC attached
  - no helper process drift into gvproxy-era behavior
  - successful host-mediated egress under admitted policy

### Phase 2B — builder path

- [ ] Finish the Stage 0 and builder-VM vsock egress path so the builder is a
  policy profile, not a networking exception.
- [ ] Close the remaining Linux builder smoke failures after the Stage 0
  CONNECT-over-vsock cutover.
- [ ] Remove silent qemu or guest-NIC fallback escapes from builder selection.
- [ ] Keep one explicit dev/test escape hatch only where it is named and
  operator-visible.

### Phase 2C — claim + gates

- [ ] Promote the no-guest-NIC vsock-only data plane into a claim with witnesses.
- [ ] Add CI/lint gates against new guest-NIC attach points and legacy helper
  spawn sites.
- [ ] Add `doctor` reporting that distinguishes:
  - workload transport truth
  - builder transport truth
  - unsupported legacy paths

**Primary reuse**

- Plan 227
- worktree `feat/vsock-port-handler-registry`
- worktree `worktree-vsock-only-egress-cutover`
- worktree `feat/vsock-transparent-net` for tests/evidence only

**Exit criteria**

- Workload boots and builder flows run with no production guest-NIC dependency.
- Live macOS and Linux smokes prove it.

## Phase 3 — Narrow the secret-egress feature into a product strength

**Why here:** after the transport boundary is honest, secret delivery can stay
host-owned without inheriting a packet appliance.

- [ ] Re-scope the secret-egress path to explicit host-owned authorities first:
  destination-bound HTTPS request classes before anything broader.
- [ ] Keep the placeholder-never-equals-secret invariant and audit guarantees.
- [ ] Bind every substitution to an admitted destination set and auth mode.
- [ ] Fail closed on:
  - destination mismatch
  - missing identity
  - downgrade to unsupported transport
  - protocol shapes outside the supported set
- [ ] Document what is intentionally unsupported in v1.
- [ ] Add end-to-end leak-gate tests covering:
  - guest never sees raw secret
  - audit never carries the raw secret
  - destination binding is enforced

**Primary reuse**

- ADR-067
- Plan 129
- current `mvm-substitution-endpoint`
- current `mvm-egress-proxy`

**Explicit rejection**

- [ ] Do not turn transparent TLS MITM into the default architecture.
- [ ] Do not promise arbitrary-protocol substitution before explicit authority
  routing is proven.

**Exit criteria**

- `mvm` has a production-ready, explicit, auditable secret-egress story that is
  narrower, easier to explain, and easier to defend than a transparent-net
  design.

## Phase 4 — Ship a caller-owned runtime lifecycle

**Why here:** once the runtime and transport seams are correct, the product can
feel simpler without weakening trust boundaries.

- [ ] Finish `mvm-client` S0/S1/S2 so local runtime lifecycle is driven through
  the facade rather than frontend-private logic.
- [ ] Make runtime child ownership explicit:
  - caller-owned by default
  - explicit detach when requested
  - parent-death cleanup
- [ ] Make the density path a real detached runtime shape:
  - no retained foreground CLI parent per long-lived VM
  - documented create/start/exec/stop or detached-run lifecycle for sustained
    waves
- [ ] Move sensitive runtime launch/config state off argv everywhere practical.
- [ ] Standardize one lifecycle contract across CLI and SDKs:
  - create
  - run
  - exec
  - stop
  - logs
  - inspect
  - snapshot/restore as they land
- [ ] Keep local and remote clients as couriers only; no enforcement authority
  moves into the facade.

**Primary reuse**

- Plan 204
- Plan 211
- Plan 216
- Plan 218
- branch `feat/plan-216-s0-mvm-client`

**Exit criteria**

- Local and future remote clients share one runtime contract.
- The runtime lifecycle feels developer-owned while still routing through host
  authorities and signed admission.

## Phase 5 — Add a host-only mutable runtime control plane

**Why here:** mutable runtime operations should not widen the guest protocol.

- [ ] Introduce one host-only local control socket per VM or per runtime owner.
- [ ] Move host-owned mutable operations onto that socket:
  - memory target/state
  - CPU target/state
  - secret map rotation
  - health/metrics probes
  - reconfigure hooks where permitted
- [ ] Keep the guest protocol focused on guest service requests, not host
  runtime mutation.
- [ ] Add negative tests proving guest traffic cannot invoke host-only controls.
- [ ] Align `machine reconfigure` and later warm-path controls with this socket
  instead of inventing another side channel.

**Primary reuse**

- Plan 204
- Plan 224 / 225

**Exit criteria**

- Mutable runtime state has one explicit host-only control surface.

## Phase 6 — Tighten runtime-share and filesystem semantics

**Why here:** host/guest file exchange needs the same narrowness as the network
boundary.

- [ ] Define one dedicated runtime share schema for bounded host/guest runtime
  coordination.
- [ ] Keep raw secrets off that share.
- [ ] Put quotas, ownership rules, and cleanup rules on every runtime share.
- [ ] Finish in-process rootfs materialization as the normal run path.
- [ ] Keep virtiofs-root as a deliberate tiered path with explicit integrity
  posture, not a silent production replacement.
- [ ] Document what belongs on:
  - immutable root
  - runtime share
  - explicit user volume
  - host-only state dir

**Primary reuse**

- Plan 221
- Plan 223

**Exit criteria**

- The filesystem model is as explicit as the network model.

## Phase 7 — Prove the product, not just the code

**Why last:** after the runtime shape is fixed, publish evidence and DX on top
of reality.

- [ ] Extend signed audit leadership with runtime evidence:
  - transport mode
  - secret-substitution events
  - snapshot lineage
  - health lifecycle transitions
- [ ] Publish density and helper-footprint evidence as part of runtime truth:
  - detached versus foreground process shape
  - endpoint-on versus endpoint-skipped footprint class
  - measured host-capacity guardrails before claiming high VM counts
- [ ] Split admission audit from runtime telemetry so metrics do not become
  pseudo-audit.
- [ ] Add live benchmark/proof runs for:
  - no-guest-NIC workload boot
  - no-guest-NIC builder path
  - local runtime lifecycle
  - detached high-density idle waves with honest process/RSS accounting
  - warm/health/reconfigure flows as they land
- [ ] Refresh docs so the product surface matches reality:
  - two surfaces
  - host-authority model
  - explicit secret-egress scope
  - current backend truth

**Primary reuse**

- Plan 200
- Plan 212
- Plan 232 / 233
- Plan 230

**Exit criteria**

- `mvm` can state its differentiators in a way that is both simpler and more
  defensible than the field:
  - explicit host authorities
  - audited vsock/UDS transport
  - no guest-direct upstream sockets
  - destination-bound secret handling
  - caller-owned runtime lifecycle

## Merge and sequencing rules

- [ ] Do not start broad Phase 3 secret work until Phase 2 workload truth is
  live-proven.
- [ ] Do not start broad SDK surface expansion until Phase 4 lifecycle routing
  is real on the local path.
- [ ] Do not make high-density claims from foreground or always-on-endpoint
  shapes when the product intent is detached host-authority runtime operation.
- [ ] Do not merge transparent-network experiments as the default runtime
  architecture.
- [ ] Prefer folding in-flight worktrees into the nearest matching phase over
  opening new overlapping plans.

## Success criteria

- [ ] Production `mvm` has no hidden guest-NIC dependency on the workload path.
- [ ] Builder networking is a host-mediated policy profile, not a special
  exception architecture.
- [ ] The guest has no production path for arbitrary direct upstream sockets.
- [ ] Secret egress is explicit, destination-bound, and auditable.
- [ ] The local client/runtime lifecycle is facade-driven and caller-owned.
- [ ] Mutable runtime controls are host-only and separated from guest protocol.
- [ ] The docs, sprint log, and rollup all describe the same runtime truth.
