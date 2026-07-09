# Plan 235 — Native Windows WHP backend

**Status: PROPOSED / DEFERRED**
**Created: 2026-07-09**
**Depends on:** ADR-099 (multi-backend hypervisor abstraction), ADR-102 (VMM driver seam role), the in-tree portable VMM/device model, and the existing workload-backend admission boundary.
**Related:** Plan 234 (WSL2-first Windows support), issue [#428](https://github.com/tinylabscom/mvm/issues/428).

## Goal

Define the native-Windows path as a separate backend:

1. a `whp` workload backend running on a real Windows host;
2. explicit host-feature detection and operator guidance for Windows-only prerequisites;
3. no dependence on WSL2 for the native-Windows story;
4. no weakening of the workload-backend / admission / audit bar.

This plan is intentionally separate from Plan 234. WSL2 is the first shipped
Windows path; `whp` is the native-Windows follow-up.

## Why this plan exists

Plan 234 gives Windows users one honest path quickly: WSL2 with nested KVM and
libkrun. That does not solve native Windows.

The architecture already leaves room for a native Windows hypervisor driver:

- ADR-099 names KVM/HVF/WHP as the intended portable VMM targets.
- ADR-102 keeps the higher-level workload/backend seam separate from the
  hypervisor-driver implementation detail.
- the workload launch path already requires a real `WorkloadBackend`; that bar
  must remain intact for Windows too.

The `whp` path is therefore plausible, but it is not a small "toggle Windows
on" change. It needs its own plan so the repo does not conflate:

- `WSL2 support`;
- `native Windows support`; and
- `generic future Windows ideas`.

## Scope decision

This plan explores and sequences a **native Windows backend over Windows
Hypervisor Platform (WHP)**.

### Driver posture

The default assumption is:

- prefer reusing the existing in-tree VMM/device model;
- add a Windows-specific hypervisor driver under that seam;
- keep backend registration/capability reporting at the existing
  `VmBackend`/`WorkloadBackend` layer.

The `whpx` crate may be a useful FFI layer over WHP, but it is not assumed to
be sufficient by itself. The plan must verify:

- API coverage for guest memory, vCPU run-loop, interrupts, exits, and device
  needs;
- maintenance quality and Windows support surface;
- whether direct `windows` bindings are needed for gaps or long-term control.

### What this plan does not assume

- It does **not** assume Cloud Hypervisor is the right answer.
- It does **not** assume WSL2 and WHP should both ship in one implementation
  burst.
- It does **not** assume a macOS-hosted test surface like OrbStack is
  meaningful proof for Windows behavior.

## Non-goals

- Do **not** implement `whp` as part of Plan 234.
- Do **not** replace the supported WSL2 path with native Windows before WHP is
  real.
- Do **not** add a "Windows but weaker" fallback that bypasses the
  workload-backend admission bar.
- Do **not** silently route Windows hosts into QEMU, Docker, or another dev
  tier and call that native support.
- Do **not** require WSL2 for the native-Windows backend once `whp` exists.

## Current constraints and findings

### What is already true in-tree

- The portable VMM seam is intentionally broader than HVF and names WHP as a
  later target.
- Backend selection, doctor messaging, and workload admission are already split
  cleanly enough that a new backend can be added without reopening the whole
  launch model.
- The repo now has a concrete WSL2 path (Plan 234), so native Windows can be
  planned independently instead of being overloaded into WSL2 work.

### What is not solved yet

- There is no native Windows backend implementation.
- There is no Windows-specific doctor/install/bootstrap path for hypervisor
  features such as Hyper-V / WHP / virtualization prerequisites.
- There is no Windows CI or live validation lane that proves workload boot,
  guest agent reachability, egress, and cleanup on a native Windows host.
- There is no repo decision yet on `whpx` crate versus direct bindings.

### Testing reality

Native Windows validation requires a **real Windows host**.

What we know from the current hosting investigation:

- Hetzner Cloud is not a viable Windows-native or nested-virt validation target.
- Hetzner dedicated/root servers appear viable for Windows Server + Hyper-V/WHP
  validation, but that still needs host-by-host confirmation.
- OrbStack is not a meaningful test surface for WHP or WSL2 validation.

## Product shape after this plan

### Supported host shape

- **Supported:** native Windows host with the required WHP/Hyper-V
  prerequisites present, using the `whp` backend.

### Unsupported host shapes

- native Windows hosts missing the required hypervisor features;
- Windows environments where WHP exists but the backend cannot meet the
  workload-backend bar honestly;
- "pretend Windows" host surfaces that only approximate Linux integration.

### Backend posture

- `whp` is a first-class workload backend, not a dev/test escape hatch.
- WSL2 remains a separate backend-selection story (`libkrun` on WSL2) even if
  both paths eventually ship.
- Backend auto-selection must stay honest: WSL2 and native Windows are
  different host shapes and must be diagnosed separately.

## Workstreams

## WS-A — Feasibility and driver choice

**Goal:** prove that a native Windows `whp` backend is technically credible
before implementation starts.

- [ ] Audit the existing portable VMM seam against WHP needs:
      - guest memory mapping;
      - vCPU creation/run loop;
      - exit handling;
      - interrupt injection;
      - timing/clock expectations;
      - virtio/MMIO/PCI assumptions that may be Linux/HVF-specific today.
- [ ] Decide whether the backend uses:
      - the `whpx` crate as the primary FFI layer;
      - direct `windows` bindings;
      - or a mixed approach.
- [ ] Record the gaps explicitly if the current VMM seam needs refactoring
      before WHP can fit cleanly.
- [ ] Write down the minimum host requirements for a supported native-Windows
      shape.

**Files:**

- `specs/adrs/099-multi-backend-hypervisor-abstraction.md` if the seam decision changes
- a focused investigation note under `specs/notes/` if needed
- this plan

## WS-B — Backend shape and crate layout

**Goal:** define how `whp` fits the existing backend surface without muddying
WSL2 or Linux behavior.

- [ ] Decide whether `whp` lives as:
      - a new `crates/mvm-whp-supervisor/` binary + backend module;
      - a backend module plus a shared host supervisor pattern;
      - or another layout that still matches the current host-process model.
- [ ] Specify the capability surface `whp` must advertise to qualify as a
      workload backend.
- [ ] Define availability checks and backend-selection rules:
      - native Windows + supported WHP shape → candidate `whp`;
      - WSL2 remains separate;
      - unsupported Windows shapes fail closed.
- [ ] Define the security profile and operator-facing tier language.

**Files:**

- `crates/mvm-backend/src/`
- `crates/mvm-core/src/platform/`
- docs/specs as needed

## WS-C — Windows host detection, install, and doctor UX

**Goal:** make native Windows diagnosable and supportable rather than "try it
and see."

- [ ] Add explicit platform helpers for native Windows host capabilities.
- [ ] Teach `mvmctl doctor` to report:
      - Windows host type;
      - WHP/Hyper-V prerequisite presence;
      - actionable fix guidance when unsupported.
- [ ] Define bootstrap/install guidance for Windows host prerequisites.
- [ ] Keep WSL2 messaging separate from native Windows messaging everywhere.

**Files:**

- `crates/mvm-core/src/platform/platform.rs`
- `crates/mvm-cli/src/doctor.rs`
- `crates/mvm-cli/src/bootstrap.rs`
- Windows install/troubleshooting docs

## WS-D — Backend implementation

**Goal:** implement a real native-Windows workload backend over WHP.

- [ ] Add the WHP hypervisor-driver layer.
- [ ] Adapt the portable VMM run loop and device wiring as needed for WHP.
- [ ] Implement host-side supervisor/lifecycle management for the backend.
- [ ] Thread the backend through workload launch, exec, egress, and cleanup.
- [ ] Keep unsupported capability combinations refused rather than degraded.

**Files:**

- `crates/mvm-backend/src/vmm/`
- `crates/mvm-backend/src/backend.rs`
- any new Windows-specific backend/supervisor crates

## WS-E — Testing and live validation

**Goal:** prove native Windows behavior on real hardware or a real hosted
Windows machine.

- [ ] Add focused unit tests for Windows platform detection and backend
      selection logic.
- [ ] Add backend/integration tests for WHP-specific launch and lifecycle code
      wherever they can run in CI.
- [ ] Add an opt-in live smoke for native Windows covering:
      - boot;
      - guest-agent readiness;
      - simple exec;
      - policy-shaped egress;
      - localhost forwarding if supported;
      - clean stop/cleanup.
- [ ] Validate the smoke on at least one real supported Windows host.
- [ ] Record the minimum acceptable hosted test lane:
      - self-hosted Windows machine;
      - or dedicated rented Windows hardware;
      - not an approximation layer.

**Files:**

- `crates/mvm-backend/tests/`
- `tests/`
- `scripts/`
- docs/specs as needed

## WS-F — Documentation and support posture

**Goal:** document the native-Windows story precisely and keep it separate from
WSL2.

- [ ] Add or update Windows install/troubleshooting docs for the native `whp`
      path.
- [ ] Update platform-support/current-surface docs to distinguish:
      - native Windows via `whp` if shipped;
      - WSL2 via `libkrun`;
      - unsupported Windows shapes.
- [ ] Update sprint/refactor rollups alongside any implementation movement.

**Files:**

- `public/src/content/docs/install/windows.md`
- `public/src/content/docs/guides/windows-troubleshooting.md`
- `public/src/content/docs/reference/platform-support.md`
- `specs/SPRINT.md`
- `specs/REFACTOR-STATUS.md`

## WS-G — Hosted Windows validation lane

**Goal:** settle where real Windows validation runs before implementation is
treated as shippable.

- [ ] Decide the primary live-test environment for native Windows:
      - owned hardware;
      - self-hosted CI runner;
      - or a rented dedicated Windows-capable host.
- [ ] Capture a host checklist for any rented Windows target:
      - Windows edition;
      - virtualization feature availability;
      - WSL2 relevance or irrelevance for the test;
      - repeatable provisioning steps.
- [ ] Keep cost/ops burden explicit in the plan before implementation starts.

## Deferred execution note

This plan is intentionally **not active implementation work yet**.

The current repo priority remains:

1. close the WSL2 live-host proof from Plan 234; and
2. keep native-Windows `whp` work planned, investigated, and scoped so it can
   start cleanly later.

## Tests and verification gates

Before Plan 235 can be marked complete:

- [ ] WHP feasibility and driver choice are documented explicitly.
- [ ] Native Windows platform/doctor/backend-selection tests are green.
- [ ] A real native-Windows live smoke passes on a supported host.
- [ ] `cargo check --workspace` is green on the implementation branch.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is green on the
      implementation branch.
- [ ] Docs are updated in the same change(s) as behavior changes.

## Risks

1. **WHP may fit the current portable VMM seam imperfectly.**
   If the seam assumes HVF/KVM behavior too narrowly, implementation will turn
   into a refactor, not a backend add.

2. **`whpx` may help but not finish the job.**
   A thin crate over WHP syscalls is useful only if it covers the exit-loop and
   device-model needs we actually have.

3. **Windows feature UX can become the real project.**
   Hypervisor prerequisites, permissions, editions, and operator guidance may
   be the dominant support burden even if the backend itself works.

4. **Testing availability can gate progress.**
   Without a real Windows host, the backend can compile and still be
   operationally unproven.

5. **WSL2 and native Windows can become conflated again.**
   Every selection, doctor, and support string must keep them separate.

## Exit criteria

Plan 235 is complete when:

1. native Windows has a real `whp` workload backend;
2. unsupported Windows shapes fail closed with actionable guidance;
3. backend selection and docs clearly distinguish native Windows from WSL2;
4. live-smoke evidence exists on a real supported Windows host.
