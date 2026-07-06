# Plan 227 — Instant-resume sandboxes over a vsock-only auditable data plane

**Status: PROPOSED**
**Created: 2026-07-06**
**Depends on:** Plan 214 (clean replacement — S4/S6/S7 designs), Plan 206 (UFFD tail), Plan 209 (slim kernel), Plan 216 (MvmClient facade), Plan 223 (virtiofs-root)
**Coordinates with:** the reserved Plan 226 (LocalBackend net/allow_host parity, deferred out of Plan 225) — that item folds into WS-F2 here if 226 is never opened standalone.

## Product goal

A machine (OCI-built **or** nix-built) that can be:

1. **Snapshotted while running** (memory + disk) and **restored near-instantly** (sub-second target on warm paths), including **fork** (N clones from one snapshot);
2. Driven identically from **every frontend** — CLI, studio, mvmd, SDKs — through the **`MvmClient` facade**, never through frontend-private code paths;
3. Booted with **one slim kernel** shared by builder and workload tiers on every backend;
4. Run with **networking never enabled**: no NIC on any mvm-launched VM. **All data in and out crosses vsock** through the per-VM gating endpoint, making every flow *auditable and reviewable*, letting us **substitute secrets** (the workload never sees raw secret bytes — claims 12/13) and **mask PII** in flows.

The vsock endpoint is not an implementation detail; it is the product seam. Everything in this plan either moves data onto it or builds capability on top of it.

## Findings (2026-07-06 audit of main @ `db659875`)

### F1. Snapshot / resume capability today

| Backend | pause/resume | memory snapshot | restore | fork | warm resume |
|---|---|---|---|---|---|
| firecracker (Linux, Tier 1) | ✅ `vm pause`/`resume` | ✅ `vm_full` (vmstate+mem, HMAC envelope) | ✅ + template snapshots | ✅ `vm checkpoint fork` | ✅ `vm resume --warm` (~0.5 s live-proven KVM; UFFD ~1 s tail unshipped — Plan 206 T1) |
| **hvf (macOS 26 default)** | ❌ unimplemented (`pause_resume_report_unimplemented`) | ❌ | ❌ | ❌ | ❌ |
| vz (sunset) | ✅ SaveRestore (macOS 14+) | ✅ | ✅ | via `vm_full` | — |
| libkrun | ❌ | ❌ | ❌ | ❌ | image-agnostic warm pool only |
| qemu | dev/test only | — | — | — | — |

`fs_quick` (quiesced disk checkpoint) is backend-neutral since #1481. The **new macOS default backend is the only workload backend with zero snapshot support** — the headline gap.

### F2. Facade reachability today

- `MvmClient` (crates/mvm-client) has 10 methods; **none** of pause / resume / checkpoint / restore / fork / warm-claim / wait-ready exist on the trait. Those live only as backend-direct `vm` CLI verbs.
- `mvmctl` itself does **not** route through the facade (Plan 216 S2 deferred); SDKs pin the CLI argv via `sdks/machine-fixtures/*.argv`; `GatewayBackend` (REST → mvmd-gateway) exists but `--remote` isn't wired (S4 partial).
- `exec_machine` is stubbed on Local + Gateway; `create/start` error on Local + Gateway.

### F3. Cold start budget (per platform, warm caches)

- Dominant cost everywhere: **guest kernel boot + agent-up ≈ 1.0–1.5 s**; CoW clone is O(1) on APFS/FICLONE-capable hosts; hvf adds supervisor spawn + PID poll (50 ms cadence); FC adds a 15 ms pre-start sleep + API handshake. Totals ≈ 1.6–4 s cold; warm-start paths (claim / snapshot-restore) reduce to ~0.2–0.5 s.
- **Blocker on macOS:** the in-house guest agent receives the host's `ProtocolHello` (delivered into the RX queue — instrumented) but never replies, so non-interactive `machine run` fails at the 30 s gate. FC round-trip with the same agent works, isolating the defect to the in-house vsock device↔guest-driver interaction.

### F4. Network surfaces today

- **hvf workload path is already vsock-pure** — no virtio-net device exists in the in-house VMM; egress rides `egress_relay_socket` → gating endpoint (sole claim-10 gate).
- Violations of the no-network invariant: **libkrun workload NIC** (gvproxy/passt; vsock egress flag-gated `MVM_VSOCK_EGRESS`, inert), **firecracker workload TAP+nftables**, and **every builder VM** (vz/libkrun/FC Stage 0 + persistent) fetching over gvproxy/passt/TAP. Plan 214 S4/S6/S7 designs the cutover; none merged.
- Host-side listeners are localhost/UDS/vsock only. Guest `netinit` degrades gracefully with no NIC.

### F5. Kernel + nix path

- `machine run --flake` uses the same `auto_select()`/admission path as `--image`; flake-built images boot on hvf (shared kernel carries VIRTIO_PCI + VIRTIO_MMIO). No backend hardcoding.
- Kernel (Linux 6.12) is already aggressively slim; the remaining meaningful strips (`VIRTIO_NET`, builder-overlay netfilter) are **blocked on the vsock cutover**, after which builder and workload converge on **one config**.

## Workstreams

Ordering: **WS-A unblocks macOS. WS-B → WS-C → WS-D is the data-plane chain. WS-E/WS-F are the capability chain and can proceed in parallel with B–D. WS-G rides the endpoint after B.**

### WS-A — In-house vsock agent data path (prerequisite)

The hvf guest agent must answer host RPC. Root-cause the guest-no-reply (host delivery proven correct; suspect in-house virtio-vsock device ↔ guest driver semantics around host-initiated streams, e.g. rx-buffer/credit or `OP_RW`-before-driver-poll ordering).

- [ ] Live device+guest trace comparing `OP_REQUEST` (works) vs `OP_RW` (payload never reaches the agent socket).
- [ ] Fix + regression test at the device level (loopback guest-driver harness in `crates/mvm-backend/src/vmm/`).
- [ ] Send `OP_RST` to the guest when the host side of an agent stream closes (`agent_bridge::close()` today leaks guest half-open connections).
- [ ] Acceptance: `machine run --image alpine -- echo ok` and `-it` both green on macOS 26 defaults; conformance run in CI where HVF runners exist, else gated live-proof note.

### WS-B — Vsock-only cutover (workloads + builders)

Adopt Plan 214 S4/S6/S7 into execution, with the **builder as a policy profile, not a networking exception**:

- [ ] **B1 (libkrun workloads):** flip the built-but-inert guest vsock egress on by default (`MVM_VSOCK_EGRESS` becomes opt-out during bake-in, then removed); retire the workload NIC + gvproxy/passt spawn on the workload path.
- [ ] **B2 (firecracker workloads):** egress via vhost-vsock → gating endpoint; retire workload TAP + nftables enforcement (endpoint enforces `PlanFlowPolicy` uniformly). nftables remains only as belt-and-braces during transition, then removed.
- [ ] **B3 (builders):** builder VMs boot with **no NIC**. Nix egress rides `HTTP(S)_PROXY` → in-guest forward proxy (existing `127.0.0.1:18080` machinery + the already-embedded `mvm-egress-proxy` builder binary) → AF_VSOCK → host gating endpoint running a **builder profile**: fetch-host allowlist + **chain-signed audit entry per fetch (URL + content hash)**. Remove `host_gvproxy` spawn sites on the builder path.
- [ ] **B4 (supply-chain manifest):** the per-build fetch log + flake.lock forms a reviewable manifest; `mvmctl trust audit verify` covers it. Optional host-side content-addressed fetch cache at the endpoint (faster warm builds, offline replay).
- [ ] Acceptance: zero gvproxy/passt/TAP processes during `machine run` (all sources) **and** during `build image` / Stage 0, on macOS and Linux; egress verdicts + fetch audit entries present in the chain.

### WS-C — "No NIC, vsock-only" as a CI-enforced claim

- [ ] Claim doc `specs/claims/claim-vsock-only-data-plane.md`: *no mvm-launched VM carries a network device; all guest I/O crosses the audited vsock endpoint.*
- [ ] Witnesses: (1) per-backend device-config assertions (no virtio-net attach anywhere in `mvm-backend`); (2) `xtask` lint failing on gvproxy/passt/TAP spawn sites outside a grandfather list that must shrink to empty; (3) runtime doctor check.
- [ ] Wire into `specs/claims/catalog.md` + `xtask check-claim-catalog`; numbered-claim promotion queued per ADR-002 convention.

### WS-D — Single-kernel convergence (tightest kernel)

Blocked on WS-B completion (last NIC user gone):

- [ ] Drop `VIRTIO_NET` from the shared base config; drop netfilter from the builder overlay (endpoint replaced it).
- [ ] Merge builder and workload overlays into **one config**: base + DM_VERITY + VIRTIO_FS/FUSE + namespaces (nix sandbox) + VSOCKETS + VIRTIO_PCI/MMIO; keep INET for loopback proxy only.
- [ ] Re-run the Plan 209 boot-time/kworker measurements; document deltas. Acceptance: one kernel artifact boots builder + workload on hvf, firecracker, libkrun, qemu; claim 3 (verity) unaffected.

### WS-E — Snapshot / instant-resume capability

- [ ] **E1 (hvf pause/resume):** vCPU stop/start + device quiesce in the in-house VMM; `machine pause/resume` verbs (aliased from `vm`).
- [ ] **E2 (hvf memory snapshot/restore):** guest RAM + vCPU + device state serialization behind the existing `checkpoint::vm_full` envelope (HMAC, same crypto as FC); restore into a fresh supervisor (the Plan 175 fresh-VMM shape).
- [ ] **E3 (fork):** restore-to-new-identity on hvf via `fork_vm_full` + CoW rootfs clone (O(1) on APFS). Target: N sandboxes from one snapshot without re-boot.
- [ ] **E4 (Linux tail):** land Plan 206 T1 (UFFD lazy-restore) so FC warm resume drops its ~1 s tail; live-KVM proofs.
- [ ] **E5 (warm pools by default):** extend warm-pool claim (Plans 118/211) to `machine run` on both platforms once E1–E3 exist; snapshot-backed pools preferred over boot-backed where supported.
- [ ] Acceptance: p50 restore-to-ready < 1 s on both platforms (measured via `BootTimingReport`); snapshot tamper → refused (envelope verify negative tests); fork lineage recorded in the audit chain.

### WS-F — Facade completeness (every frontend, one surface)

- [ ] **F1 (trait):** add to `MvmClient`: `pause_machine`, `resume_machine`, `snapshot_machine(SnapshotSpec) -> SnapshotId`, `restore_machine(SnapshotId, RestoreOpts)`, `fork_machine(SnapshotId, n)`, `wait_machine_ready`, plus fix `exec_machine` (buffered exec) on Local + Gateway; `create/start` land on Local via the machine-spec registry.
- [ ] **F2 (impls):** LocalBackend delegates to `mvm_backend::checkpoint`/backend verbs; GatewayBackend maps to mvmd-gateway REST (`/snapshots`, `/pause`, `/resume`, …) — coordinate DTOs (Plan 216 S5).
- [ ] **F3 (CLI through facade):** revive Plan 216 S2 — `mvmctl machine` verbs consume LocalBackend, so CLI/SDK/studio/mvmd can no longer drift; the `vm pause/resume/checkpoint` family folds into `machine` verbs routed through the trait.
- [ ] **F4 (conformance):** extend `sdks/machine-fixtures/*.argv` + facade conformance tests to the new ops so all surfaces stay pinned.
- [ ] Acceptance: same snapshot/restore/fork flows green through (a) CLI, (b) LocalBackend unit path, (c) GatewayBackend against a mock gateway, with one shared fixture set.

### WS-G — PII masking on the audited endpoint

New capability on the seam WS-B consolidates (prior art: claim 13's S25 outbound-placeholder backstop):

- [ ] **G1:** masking stage in the gating endpoint's L7 path: pluggable matchers (structured detectors first: emails, phone numbers, card/PAN patterns, configured custom regexes) applied to reviewable flows; masked spans are **redacted in transit** and the *fact of masking* (rule id + count, never the payload) lands in the chain-signed audit log.
- [ ] **G2:** per-plan masking policy in `ExecutionPlan` (deny / mask / allow per destination class), enforced before dispatch like every other plan field; fail-closed default = mask on.
- [ ] **G3:** negative-path tests (mask evasion via chunked bodies / TLS-terminated streams), fuzz the matcher input path.
- [ ] Explicit non-goal: semantic/ML PII detection — out of scope; the seam supports upgrading detectors later.

### WS-H — Docs, claims, rollup

- [ ] ADR for the vsock-only data plane + builder policy profile (supersedes NIC-era egress ADol sections; cross-ref ADR-055/058/082 lineage).
- [ ] Update ADR-002 tier matrix once WS-B/C land; queue claim promotion.
- [ ] Keep `specs/REFACTOR-STATUS.md` + `specs/SPRINT.md` rows current per workstream (Definition of Done items 5–7).

## Dependency graph

```
WS-A ──────────────► WS-E1..E3 (hvf snapshot needs a working agent path)
WS-B ──► WS-C ──► WS-D
WS-B ──► WS-G
WS-E ◄─► WS-F (facade ops land as each capability lands; F1 trait first)
```

## Explicit non-goals

- Multi-tenant guests, cross-host snapshot migration, GPU — unchanged out-of-scope (ADR-002, ADR-087).
- Reintroducing any NIC-based egress mode, including "temporarily for the builder".
- Semantic PII inference (G is pattern/policy-based v1).

## Open questions

1. Snapshot-at-rest encryption: reuse `mvm-core::crypto::snapshot_*` for hvf envelopes as-is, or extend to per-tenant keys before E2 ships?
2. Warm-pool sizing policy (residency slider, Plan 205 heritage) — host-global or per-image?
3. mvmd-gateway REST shape for snapshot ops — align with existing `/api/v1/sandboxes/{id}` style in this repo's GatewayBackend, but the routes live in the mvmd repo (cross-repo coordination like Plan 216 S5).
