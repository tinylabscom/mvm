# Plan 146 — Cloud-hypervisor Tier-1 parity (Kuasar-referenced) + Wasm-sandbox note

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans /
> subagent-driven-development. Checkbox (`- [ ]`) steps track progress.
>
> **Save-only note:** captured plan, sequenced as a backend-parity refinement on
> top of the refactor (plans 120–132). It **does not stand alone or execute ahead
> of its prereqs** — Task 1's live bring-up waits on Plan 120's `core_demo_e2e`
> green; Task 2 waits on Plan 141's Rust-owned-shuffle trait; Task 3 feeds Plan
> 140's snapshot security gaps. Verify the `146` prefix against `main` + open PRs
> before merge (`cargo xtask check-spec-numbers` is CI-gated). Note: `145` is
> already double-used on disk (`145-microvm-fork-fanout-and-branch.md` +
> `145-portable-runnable-artifacts.md`) — that pre-existing collision is someone
> else's to resolve; this plan deliberately takes 146.

**Origin:** a comparison of mvm against **Kuasar** (https://github.com/kuasar-io/kuasar
— a CNCF multi-sandbox container runtime, Apache-2.0, mostly Rust: a node-level
*sandboxer* under containerd's Sandbox API, with microVM (cloud-hypervisor /
StratoVirt / QEMU), Wasm (WasmEdge), app-kernel, and runc sandboxers). Verdict:
most of Kuasar is **architecturally convergent** with mvm (one backend abstraction
over many VMMs; vsock-only guest channel) or **out of scope** (it's a k8s/CRI
node daemon — mvm is a dev tool and mvmd is the fleet plane). The transferable
value is narrow and sharp: Kuasar runs cloud-hypervisor *in production*, and mvm's
own CH backend is **fully written but unit-tested only**. Kuasar is the reference
that de-risks the CH bring-up mvm has already committed to in code.

**Goal:** Promote `CloudHypervisorBackend` from "complete-but-unbooted" to a
live-validated Tier-1 backend at parity with Firecracker, using Kuasar's CH
sandboxer as the production reference for device config, the snapshot/restore API
sequence, and TAP/virtio-net wiring. Plus: record the one cross-repo lesson
(single-daemon process model → mvmd) and park the Wasm-sandbox exploration.

**Architecture / framing:** mvm already owns the CH backend
(`crates/mvm-backend/src/cloud_hypervisor.rs` + `ch_runtime.rs`, all `VmBackend`
methods implemented, compat entry filled at `compat.rs:207-230`). Its module docs
scope out three items as follow-up: TAP networking (`tap_networking: false`),
snapshot/restore mechanics (declared `supports_snapshots: true` but orchestration
targets the Firecracker API shape), and dm-verity (claim 3) parity. None of these
are Kuasar-invented work — they're mvm's own roadmap — but Kuasar's CH integration
is the best open reference for the exact REST payloads and device JSON, which is
how this plan "pulls Kuasar in": as validation knowledge, **not a code copy**
(keeps the limit-dependencies posture; if any snippet is adapted, Apache-2.0 →
attribution in the file header).

**Reference to consult** (verify exact paths when network is available — captured
from prior knowledge, not read live): Kuasar's VMM sandboxer lives under
`vmm/sandbox/` with per-hypervisor modules incl. `cloud_hypervisor`; the guest
agent is `vmm-task` (vsock + ttRPC). Cross-check mvm's `build_vm_config`
(`ch_runtime.rs`) against Kuasar's `vm.create` payload, and mvm's gaps against
Kuasar's net-device + snapshot code. cloud-hypervisor's REST surface is the
ground truth either way (`vm.create`, `vm.boot`, `vm.pause`, `vm.resume`,
`vm.snapshot`, `vm.restore`, `vm.add-net`, `vm.info`, `vm.resize`).

**Dependency / sequencing:**
- **Task 1 (live bring-up) is GATED behind Plan 120 `core_demo_e2e` green** and
  needs a Linux + `/dev/kvm` + cloud-hypervisor host. CI lacks one; use the
  ADR-066 test-env exception (Lima as a virtual-KVM provider for CH/FC E2E — Lima
  is permitted *strictly* as a test-env KVM provider, never a backend/runtime).
- **Task 2 (CH TAP) is GATED behind Plan 141** — CH's net device must hand a data
  fd to `gateway_bridge::run_bridge_inner` exactly like Firecracker, so the
  Rust-owned-shuffle trait must land first. Until then CH stays vsock-only.
- **Task 3 (CH snapshot mechanics) FEEDS Plan 140** — this plan wires the CH
  `vm.snapshot`/`vm.restore` mechanics; Plan 140 owns the restore *security*
  gaps (seccomp/entropy/clock/admission), which apply to the CH arm unchanged.
- **Task 4 (CH builder VM)** is independent of Kuasar (reference is in-repo:
  `libkrun_builder.rs` / `vz_builder.rs`); lowest priority.
- **CI gates coordinate with Plan 128** (Stage D) — a CH smoke lane is added there
  alongside the other claim gates, same pattern as Plan 143 §Task 1 Step 4.

**Tech stack:** Rust (`mvm-backend`, `mvm-build`), cloud-hypervisor REST-over-Unix
API (already used in `ch_runtime.rs`), `gateway_bridge` (Plan 141), Lima KVM
test-env (ADR-066), `examples/agent_ping` as the boot→ping witness.

**Out of scope:** containerd Sandbox API / CRI integration, node-level sandboxer
daemon, ttRPC, virtiofs-shared snapshotter rootfs, Wasm runtime — see the
rejected/deferred tables.

---

## Task 1 — CH live bring-up + config validation vs Kuasar  *(gated on Plan 120 green; needs Linux+CH host)*

mvm's CH backend has never booted a real VM — its JSON builders and path helpers
are unit-tested, the API call sites reviewed against CH docs, but no live
boot→agent-ping exists (`cloud_hypervisor.rs` / `ch_runtime.rs`). Kuasar's CH
sandboxer is the production reference to diff against before trusting it.

- [ ] **Step 0 (gate):** confirm `core_demo_e2e` is green on macOS/libkrun (Plan
      120 Task 4 box ticked) so a CH boot failure is unambiguously a CH problem.
- [ ] **Step 1 (reference diff):** read Kuasar's `cloud_hypervisor` module; diff
      its `vm.create` payload + boot sequence against
      `ch_runtime.rs::build_vm_config` / `start_ch_daemon`. Record divergences
      (likely candidates: `rng` device for guest entropy, `console`/`serial`
      shape, `--seccomp` flag on the daemon, payload `cmdline` vs mvm's
      `console=ttyS0 reboot=k panic=1`). Write findings into this plan as a short
      table — no code yet.
- [ ] **Step 2 (live boot):** on a Lima KVM + cloud-hypervisor host, run a
      single-VM boot of the same artifact `core_demo_e2e` uses; capture
      `<vm_state_dir>/console.log` + `ch.log` (echo both paths up front per the
      launch-logging convention). Drive `examples/agent_ping` over vsock:5252.
- [ ] **Step 3 (fix to green):** apply only the divergences Step 1 found that the
      live boot proves necessary (no speculative fixes — Plan 120 Task 4
      discipline). Files: `ch_runtime.rs` (`build_vm_config`, `start_ch_daemon`),
      `cloud_hypervisor.rs` (`start`).
- [ ] **Step 4 (gate):** add a CH boot→ping smoke lane (Lima KVM) to the Plan 128
      gate set, marked Linux-only; `just lint`; commit.

## Task 2 — CH TAP networking via the Rust-owned shuffle  *(gated on Plan 141)*

CH advertises `tap_networking: false` and is vsock-only; `compat.rs` declares
`NetworkingModel::Tap` as *what CH can do*, not what `start` wires. To be a real
workload runtime (egress audit, claim 10) CH needs the same data-fd → bridge
handoff Firecracker has.

- [ ] **Step 1:** after Plan 141 lands `gateway_bridge::run_bridge_inner` + the
      `on_packet` observer trait, add a CH net device to `build_vm_config` (`net`
      with an fd/tap handle + mac), and a CH adapter that hands the data fd to the
      bridge (Firecracker is the in-repo pattern; Kuasar's CH net JSON is the
      external cross-check). Reference `libkrun.rs:73-96` for the gvproxy/passt
      gateway-config shape on the macOS side, though CH is Linux-only here.
- [ ] **Step 2:** flip `capabilities().tap_networking` → true and confirm the
      egress redactor / hostname filter / rate limiter observers run on CH
      identically to FC/libkrun/Vz (Plan 141's parity assertion).
- [ ] **Step 3:** extend the Task 1 smoke lane with an egress-policy assertion
      (default-deny holds; an admitted destination passes). `just lint`; commit.

## Task 3 — CH snapshot/restore mechanics  *(feeds Plan 140)*

`compat.rs` declares `supports_snapshots: true` for CH and `capabilities()`
returns `snapshots: true`, but the snapshot orchestration in
`mvm/src/vm/instance/{lifecycle,snapshot}.rs` targets the Firecracker snapshot
API shape. Wire the CH equivalent.

- [ ] **Step 1:** implement the CH `vm.pause` → `vm.snapshot` → (new VM)
      `vm.restore` → `vm.resume` sequence and the on-disk snapshot layout in
      `ch_runtime.rs` + the CH arm of the lifecycle path; Kuasar's CH snapshot
      code is the reference for the API ordering and file set.
- [ ] **Step 2:** hand off to **Plan 140** — its four restore *security* gaps
      (seccomp-on-restore #1 is FC-jailer-specific and **N/A to CH's own seccomp**;
      entropy reseed #2, clock resync #3, and wake re-admission #4 all apply to the
      CH arm unchanged). Record in Plan 140 that CH now joins FC/Vz in scope.
- [ ] **Step 3:** snapshot/restore round-trip test on the Lima KVM host;
      `just lint`; commit.

## Task 4 — CH builder VM path  *(independent; lowest priority; not Kuasar-derived)*

`crates/mvm-build/src/builder_vm.rs` returns `NotYetImplemented`; only libkrun
(`libkrun_builder.rs`) and Vz (`vz_builder.rs`) have a `VmBackendForBuilder` impl.
A CH builder gives Linux contributors a KVM-native `nix build` path without
libkrun.

- [ ] **Step 1:** implement `VmBackendForBuilder` for CH following the
      `libkrun_builder.rs` pattern — spawn the builder VM, mount `/work` + `/nix`
      + `/out`, run `nix build`, extract results. Reference is in-repo, not Kuasar.
- [ ] **Step 2:** wire it into `builder_backend_select.rs` (a third
      `BuilderBackendChoice`); `--builder ch` / `MVM_BUILDER_BACKEND=ch`; keep
      auto-detect unchanged (macOS 26+ AS → Vz; else libkrun). `just lint`; commit.

## Task 5 — positioning note + mvmd cross-repo note  *(independent)*

- [ ] **Step 1:** one paragraph in `specs/adrs/002-microvm-security-posture.md`
      (§Threat model, positioning prose — *not* a new claim, per the out-of-scope
      discipline) recording that CH joins Firecracker as a Tier-1 KVM backend and
      why mvm tracks an external production CH reference (Kuasar) rather than a CRI
      sandboxer integration. Reconcile the CH row in the per-backend tier matrix.
- [ ] **Step 2:** file an mvmd note (`../mvmd/specs/notes/`) capturing the one
      genuinely transferable *fleet* lesson: Kuasar's headline win is collapsing
      the one-shim-process-per-sandbox model into a single node-level sandboxer
      daemon. mvm is per-VM by design (one supervisor per VM — `start_enter`
      `exit()`); the daemon-vs-process-per-VM tradeoff at fleet scale is **mvmd's**
      call, not mvm's. Record, don't implement here.

## Acceptance (Plan 146 is done when)

- [ ] CH boots a real VM on a Lima KVM host and answers `agent_ping` over
      vsock:5252; the boot→ping smoke lane is green in the Plan 128 gate set
      (Task 1).
- [ ] CH workloads route egress through `gateway_bridge` with the Plan 141
      observers, default-deny enforced; `tap_networking == true` (Task 2).
- [ ] CH snapshot/restore round-trips; Plan 140 scopes CH into its restore
      security gaps (Task 3).
- [ ] (Optional) `--builder ch` builds an image on a Linux KVM host (Task 4).
- [ ] ADR-002 records CH Tier-1 positioning; mvmd note filed (Task 5).
- [ ] `just lint` + `cargo test --workspace` green.

## Considered and rejected (Kuasar features NOT adopted)

| Kuasar feature | Verdict for mvm |
|---|---|
| **ttRPC over vsock** (vmm-task RPC) | **Reject** — mvm uses minimal JSON + `#[serde(deny_unknown_fields)]` + Ed25519 `AuthenticatedFrame`, and *fuzzes* the parsers (ADR-002 W4.1/W4.2). ttRPC adds a protobuf attack surface needing its own fuzzing + a new dependency, against the limit-dependencies posture. The hand-rolled protocol is a deliberate security choice, not an accident. |
| **Node-level single sandboxer daemon** (collapse process-per-sandbox) | **Defer to mvmd** — mvm is per-VM by design; fleet process-model is mvmd territory (see Task 5 Step 2). |
| **containerd Sandbox API / CRI integration** | **Reject for mvm** — mvm is a dev tool, not a k8s node component. If ever relevant it's mvmd's call. |
| **virtiofs-shared snapshotter rootfs** (live host rootfs into guest) | **Reject** — mvm's Nix-built immutable rootfs + dm-verity (claim 3) + sealed dep volumes (claim 11) is a stronger supply-chain posture than mounting a mutable host tree. |
| **App-kernel (syscall-interception) sandboxer** | **Reject** — same hardware-boundary-beats-application-kernel rationale already recorded in ADR-002 by Plan 143. Cross-ref, don't re-argue. |
| **Wasm (WasmEdge) sandboxer** | **Defer** — see §Deferred below (owner wants to explore later). |

## Deferred — Wasm sandbox exploration  *(future; needs its own brainstorm + ADR/plan)*

Owner intent: explore supporting Wasm sandboxes later. Kuasar's Wasm sandboxer
(WasmEdge) is the prior art. Open architectural tension to resolve in a dedicated
brainstorm before any plan:

- [ ] mvm's artifact model is **microVM-shaped** — `MicrovmBackend` enum,
      kernel+rootfs `MicrovmArtifact`, `BackendCompat` over arch/kernel-format
      (`crates/mvm-backend/src/artifacts/`, `compat.rs`). A Wasm runtime has no
      kernel/rootfs, so it does not slot into the current `VmBackend` abstraction
      cleanly. Decide: (a) a parallel `SandboxBackend` abstraction above
      `VmBackend`, or (b) run WasmEdge *inside* a microVM for hardware-boundary
      defense-in-depth (keeps the security claims, loses the lightweight-cold-start
      win that motivates Wasm in the first place).
- [ ] Security claims (ADR-002) assume a VMM boundary — a host-process Wasm
      runtime has a fundamentally different threat model and would need its own
      claim lineage or an explicit out-of-scope carve-out. This is the gating
      decision; resolve it first.
- [ ] Sequence after the refactor (plans 120–132) settles. Do **not** start until
      the abstraction question above is answered in an ADR.

## Self-review

- Real symbols only for the in-repo claims: CH backend completeness, `compat.rs`
  entry, `builder_vm.rs` `NotYetImplemented`, `gateway_bridge`/Plan 141 handoff,
  Plan 140 restore gaps — all read during research.
- Kuasar specifics are flagged as not-read-live (network blocked at authoring):
  module paths are prior-knowledge and carry a verify-when-available caveat; the
  CH REST endpoints cited are cloud-hypervisor's documented API, the ground truth
  regardless of Kuasar's exact layout.
- Dependencies are explicit and one-directional: T1 waits on Plan 120; T2 waits on
  Plan 141; T3 feeds Plan 140; CI gates route through Plan 128 (Stage D), matching
  Plan 143's pattern.
- Kuasar is referenced as prior art (not a competitor; cf. gvisor-tap-vsock); the
  per-pod-shim model it improves on is named obliquely, not by product.
