# Plan 234 — WSL2-first Windows support

**Status: IN PROGRESS**
**Created: 2026-07-08**
**Depends on:** Plan 214 (clean replacement direction), Plan 216 (`MvmClient` facade), Plan 223 (virtiofs-root), the existing libkrun workload path, and the current platform/doctor/backend-selection surfaces.
**Supersedes:** the stale "WSL2 works as Linux" assumption recorded in older cross-platform roadmap docs; this plan is the concrete, current-surface implementation path.

## Goal

Make Windows support real by supporting **WSL2 as a first-class host path**
for mvm workloads, with an honest security posture and no silent fallback to a
weaker runtime.

The first shipped target is:

1. **WSL2 + nested KVM + libkrun** as the supported workload backend;
2. clear detection, diagnostics, and docs for unsupported WSL2 shapes;
3. live-smoke-backed confidence for boot, guest agent, exec, egress, ports,
   and cleanup;
4. no claim that native Windows is supported yet.

This is intentionally **not** a native-Windows hypervisor plan. Native Windows
support is tracked separately in
[`plans/235-native-windows-whp-backend.md`](235-native-windows-whp-backend.md)
so the WSL2 slice stays narrow and honest.

## Why this plan exists

Today the repo already recognizes WSL2, but only as a future/experimental host:

- `Platform::Wsl2` exists in
  `crates/mvm-core/src/platform/platform.rs`, but
  `supports_native_runner()` is `false`, nested-KVM detection is not used to
  make WSL2 workload-capable, and `has_libkrun()` is hard-disabled there.
- `AnyBackend::auto_select()` explicitly refuses to auto-select Firecracker on
  WSL2 even when nested KVM is present.
- `mvmctl doctor` currently tells operators that WSL2 needs nested `/dev/kvm`
  and otherwise only QEMU dev/test is available.

That is a sensible starting point, but it leaves Windows users in an
unresolved state. The smallest honest improvement is to make one existing
backend work on WSL2 well before attempting a new native-Windows backend.

## Scope decision

This plan chooses **WSL2 + libkrun first**.

### Why libkrun first

- It is already an in-tree workload backend with real lifecycle, guest-agent,
  and egress wiring.
- It avoids the first-wave complexity in the Firecracker path: TAP/bridge,
  nftables, jailer, and other Linux-host assumptions that are more likely to
  diverge under WSL2.
- It gives Windows users a hardware-isolated microVM path sooner while keeping
  Firecracker as the Tier-1 Linux baseline.

### Why not Firecracker first

Firecracker on WSL2 with nested KVM may become viable later, but it is not the
fastest route to a supportable Windows story. Treating "WSL2 looks like Linux"
as sufficient would hide real host-environment differences and produce a brittle
support story.

### Why not native Windows in this plan

The portable VMM seam already names **WHP on Windows later** as a target.
That is valuable, but it is a separate project:

- new hypervisor driver implementation,
- new backend registration and security profile,
- new install/doctor/fix flows for Windows host features,
- a broader CI and support tail.

Conflating that work with WSL2 enablement would slow the first real Windows
path and make the rollout harder to reason about.

## Non-goals

- Do **not** add a native-Windows workload backend in this plan.
- Do **not** claim Firecracker is supported on WSL2.
- Do **not** silently fall back from a failed microVM launch to QEMU or any
  weaker path.
- Do **not** weaken claim-10 or the workload-backend bar just to make WSL2
  appear supported.
- Do **not** bless DrvFs-mounted workspaces or state dirs (`/mnt/c/...`) as
  equivalent to the WSL ext4 filesystem for runtime use in the first release.
- Do **not** expand builder-VM scope here beyond what is required for workload
  support and honest diagnostics.

## Current code reality (2026-07-08 audit)

### Host/platform detection

- `Platform::Wsl2` is a first-class enum variant.
- `Platform::has_kvm()` returns true on WSL2 only if `/dev/kvm` exists.
- `Platform::supports_native_runner()` returns true only for `LinuxNative`.
- `Platform::has_libkrun()` returns false for `Windows`, `Wsl2`, and
  `LinuxNoKvm`, even though WSL2-with-KVM is exactly the shape we want to
  enable here.

### Backend selection

- `AnyBackend::auto_select()` prefers Firecracker only on native Linux KVM,
  then HVF on macOS, then libkrun if installed.
- WSL2 is explicitly called out as future/experimental and is not auto-selected
  onto any workload backend today.

### Workload permission boundary

- `LibkrunBackend` already implements `WorkloadBackend`.
- The workload-backend bar is load-bearing and must remain so: the admitted
  launch path accepts `&dyn WorkloadBackend` only.

### Portable VMM direction

- `crates/mvm-backend/src/vmm/mod.rs` and `vmm/hv.rs` explicitly describe the
  portable device model as targeting HVF today and KVM/WHP later.
- That makes a future native-Windows `whp` backend compatible with the current
  architecture, but it is not needed to ship WSL2-first support.

## Product shape after this plan

### Supported host shapes

- **Supported:** WSL2 on Windows with nested KVM exposed as `/dev/kvm`,
  workspace + state on the WSL filesystem, and libkrun installed in the distro.
- **Unsupported, with explicit diagnosis:** WSL2 without `/dev/kvm`.
- **Unsupported, with explicit diagnosis:** WSL2 with runtime state or project
  paths on DrvFs when that shape breaks the microVM path or its tests.

### Backend posture

- WSL2 support is **Tier 2 / libkrun-backed**, not Tier 1.
- Firecracker remains the security/performance baseline for native Linux KVM.
- QEMU stays a dev/test carve-out, never a silent fallback workload backend.

## Workstreams

## WS-A — Platform model and availability truthfulness

**Goal:** make WSL2 with nested KVM an honest, selectable workload host shape
without lying about unsupported cases.

- [x] Add an explicit platform capability helper for "WSL2 can run a workload
      microVM" instead of overloading `supports_native_runner()`, which today
      means native Linux + Firecracker.
- [x] Stop hard-disabling `Platform::has_libkrun()` for WSL2 when `/dev/kvm`
      is present and the library exists.
- [x] Keep `Platform::Windows` and `Platform::Wsl2` distinct; WSL2 support must
      not imply native-Windows support.
- [x] Add unit tests covering:
      - WSL2 with `/dev/kvm` present;
      - WSL2 without `/dev/kvm`;
      - native Windows still not workload-capable;
      - no regression to native Linux/macOS selection behavior.

**Files:**

- `crates/mvm-core/src/platform/platform.rs`
- any new focused tests in that module

## WS-B — Backend selection and explicit user choice

**Goal:** WSL2 selects a supported workload backend when possible, and fails
closed otherwise.

- [x] Update `AnyBackend::auto_select()` so WSL2 with nested KVM and libkrun
      installed selects `LibkrunBackend`.
- [x] Keep Firecracker out of WSL2 auto-selection in this plan.
- [x] Ensure `AnyBackend::select_capable_available()` and any relevant CLI
      selection paths surface `unavailable` / capability shortfalls clearly on
      WSL2 rather than drifting into generic Linux behavior.
- [x] Add tests that pin:
      - WSL2 + KVM + libkrun → `libkrun`;
      - WSL2 without KVM → no workload backend auto-selection;
      - native Linux KVM still prefers Firecracker;
      - macOS behavior is unchanged.

**Files:**

- `crates/mvm-backend/src/backend.rs`
- `crates/mvm-backend/src/selection.rs`
- any related tests

## WS-C — WSL2 runtime constraints and filesystem safety

**Goal:** define and enforce the minimal host constraints that make WSL2 support
real rather than flaky.

- [x] Decide and document the first-release filesystem rule:
      runtime state and project worktrees must live on the WSL filesystem, not
      under `/mnt/<drive>/...`.
- [x] Add a doctor check for the effective workspace / state-dir location on
      WSL2, with a clear warning or refusal when the host path shape is known to
      be unsupported.
- [x] Audit libkrun state, socket, pidfile, and helper-binary paths for any
      assumptions that break specifically under WSL2 or DrvFs.
- [x] Add focused tests for path-shape validation where the logic is pure.

**Files:**

- `crates/mvm-cli/src/doctor.rs`
- `crates/mvm-core/src/config.rs` or the narrowest path/helper module that owns
  the relevant path logic
- any related docs listed in WS-F

## WS-D — Live-smoke-backed workload validation

**Goal:** prove the WSL2 path can do real workload work, not just compile.

- [x] Add a gated live smoke suite for the WSL2 + libkrun shape covering:
      - boot;
      - guest-agent readiness;
      - simple exec;
      - network egress under the existing policy path;
      - published localhost port reachability;
      - clean stop/cleanup.
- [x] Reuse the narrowest existing live-test harnesses where possible; do not
      invent a second style of lifecycle smoke if the repo already has one that
      fits.
- [x] Mark these tests opt-in and environment-gated, like the existing live
      backend proofs elsewhere in the repo.
- [x] Add a short operator runbook describing how to execute the WSL2 live
      proof locally.
- [x] Document what counts as acceptable live-proof evidence:
      a real Windows host running WSL2, not a macOS integration layer or a
      generic non-WSL Linux VM.

**Files:**

- `crates/mvm-backend/tests/` and/or the smallest existing live-smoke home that
  matches the libkrun workload path
- `scripts/` only if a dedicated WSL2 smoke wrapper is required
- docs in WS-F

## WS-E — CLI/doctor/operator UX

**Goal:** Windows users on WSL2 see a coherent supported-path story.

- [x] Change `mvmctl doctor` WSL2 output from "future/experimental" to:
      - supported when nested KVM + libkrun + supported filesystem shape are
        present;
      - explicit refusal/recovery guidance otherwise.
- [x] Update any workload-backend help text that still says WSL2 is unsupported
      or "only qemu".
- [x] Ensure unsupported native Windows messaging remains accurate: WSL2 is the
      supported Windows path, native Windows microVMs are not shipped yet.
- [x] If `bootstrap` or install helpers mention Windows/WSL2, align them to the
      WSL2-first story without claiming native-Windows runtime support.

**Files:**

- `crates/mvm-cli/src/doctor.rs`
- `crates/mvm-cli/src/bootstrap.rs`
- any CLI help/doc strings in `mvm-cli`

## WS-F — Documentation and status surfaces

**Goal:** the repo's current docs say exactly what is implemented.

- [x] Add a focused WSL2 support guide covering:
      - prerequisites;
      - supported backend (`libkrun`);
      - required nested KVM;
      - filesystem/location constraints;
      - how to run the live smoke;
      - what is not supported yet.
- [x] Update contributor/developer docs and current-surface platform references
      to reflect WSL2-first Windows support.
- [x] Update any older roadmap text that still says "WSL2 works as Linux" or
      implies Firecracker-first WSL2 support.
- [x] Keep the sprint log and refactor rollup in sync with this plan.

**Files:**

- `public/src/content/docs/` WSL2 install/troubleshooting pages as needed
- `public/src/content/docs/contributing/development.md`
- `specs/SPRINT.md`
- `specs/REFACTOR-STATUS.md`

## WS-G — Native-Windows backend follow-up (deferred, not this plan)

This is recorded so WSL2 support does not get mistaken for "Windows solved."

- Future work is now recorded explicitly in
  [`plans/235-native-windows-whp-backend.md`](235-native-windows-whp-backend.md)
  as the deferred native-Windows `whp` plan over the portable VMM seam.
- That future plan would cover host feature detection/fix flows, backend
  registration, capability reporting, security profile, and Windows CI/story
  independently of WSL2.

No implementation work for WS-G lands under Plan 234.

## Tests and verification gates

Before this plan can be marked complete:

- [x] Focused unit tests for platform detection / backend selection / doctor
      messaging are green.
- [ ] The WSL2 live-smoke proof passes on a real supported WSL2 host.
- [x] `cargo check --workspace` is green.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` is green.
- [x] The relevant docs are updated in the same change(s) as behavior changes.

## Risks

1. **WSL2 looks Linux-like but is not Linux-identical.**
   Socket, filesystem, and helper-binary behavior can differ in ways that do
   not show up on native Linux. This is why WS-C and WS-D exist as first-class
   workstreams rather than assumptions.

2. **DrvFs path support may be a support trap.**
   If the first release pretends `/mnt/c/...` is supported and it is not, the
   operator experience will be worse than a clear refusal. Start narrow.

3. **Firecracker pressure can derail the first shipment.**
   Trying to support both libkrun and Firecracker on WSL2 in one plan is
   likely to delay the first real Windows path.

4. **Native Windows expectations may expand implicitly.**
   Every doctor/help/doc string must keep WSL2 and native Windows separate.

## Exit criteria

Plan 234 is complete when:

1. WSL2 with nested KVM is a documented, supported host shape for the
   libkrun workload backend;
2. unsupported WSL2/native-Windows cases fail closed with actionable guidance;
3. live-smoke evidence exists for the supported WSL2 path;
4. the repo's current docs, sprint log, and refactor rollup reflect that
   shipped state accurately.
