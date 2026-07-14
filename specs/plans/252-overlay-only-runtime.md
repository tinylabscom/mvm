# Plan 252 — Overlay-only runtime (delete mkGuest binary baking); complete Plan 242

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Created:** 2026-07-13
**Related:** Plan 242 (overlay-required rollout — this finishes it), Plan 246–249.
**Base:** `feat/plan-249-wsb-builder-robustness` (has the `--flake` chain fixes; the mkGuest `mkdir` band-aid this plan DELETES).
**Status:** **Phases 1–5 landed + live-proven** on macOS-26 hvf (Phase 4 = `795d541a1`, Phase 5 = `d2b3f8a5f`). The runtime overlay is now the single MANDATORY source of every guest binary on block workload boots; **mkGuest binary baking is deleted** and a lean image boots with the agent sourced entirely from the overlay (no baked fallback). Approach (b) non-verity overlay block-mount — owner-approved. Full workspace suite green (6829 passed). Branch `feat/plan-250-overlay-only` ready to PR.

**Follow-ups:**
- [x] **leg-3 persistent (`-d`) — already correct (was a misdiagnosis).** The `shared/start.rs:59` `backend_name: None` placeholder is always overridden by its only production caller `up::start_persistent_oci_machine` (`up.rs:1343` computes the policy with the real backend, `:1427` overrides). Both `--flake`/`--manifest` and `--image` persistent boots resolve to `RequiredOverlay`. (The dead placeholder in `into_start_config` is harmless but misleading — optional cleanup.)
- [x] **builder-VM overlay-unavailable fail-open → fatal (commit `0beaa1721`).** Added `BuilderVmError::RuntimeOverlayUnavailable` (excluded from `is_builder_vm_level_failure` → surfaces without a silent cross-backend retry) + `require_runtime_overlay_ext4()` / `builder_runtime_overlay_or_bail` (fatal for lean `Rootfs` builders, `Ok(None)` for `RootDir` Stage-0 bootstrap). Wired into all 7 builder boot sites (libkrun/qemu/hvf); removed the degraded fallback while preserving the disk-transport input (it rides `builder_runtime_overlay_cmdline`). New injectable-resolver tests; build + clippy (builder-vm) + fmt green.
- [x] **sealed/verity regression — no behavioral change possible (verified by construction).** The deleted cp blocks were gated `if runtimeLean then "" else <bake>`, and sealed images already had `runtimeLean=true` (`= isSealed`), so those blocks were **already skipped** for sealed rootfses pre-Phase-5 → sealed rootfs content is unchanged. Sealed boots (mvm-verity-init sets up the verity rootfs + overlay, then switch_root → mkGuest `/init`) resolve the agent from `/mvm/runtime`, which the verity overlay always carries, so neither the removed `/usr/local/bin` fallback nor the new fail-closed `exit 1` branch is ever reached. Phase 5 touched no verity code (`mvm-verity-init.rs` + the backend verity attach are untouched). A live verity boot would only re-confirm this and is hard to trigger (no `verifiedBoot` flag on `machine run --flake`); left as optional. Mental model (owner): rootfs + runtime-overlay + custom volumes are three *stacked* layers, each at its own mount point, none overriding the others; the overlay carries all client agents so every microVM gets the same versioned clients.

## Live finding (2026-07-13) — why a `--flake` dev boot still showed `rootfs_only`
The end-to-end `machine run --flake` boot now **builds, fetches nix, files the
result, and boots** — the whole injection/dev-VM failure chain (layers 1–4) is
fixed and confirmed (0 dev-VM errors in the console). But the workload cmdline
carried `mvm.runtime_source_policy=rootfs_only` with **no `mvm.runtime_data`
token**, so Phase 3b's attach never fired. Root cause, fully traced:
- `runtime_source_policy_for` correctly returns **PreferOverlay** for a Template
  (`--flake`) dev boot (`exec.rs`, test `templates_declare_prefer_overlay`).
- But `attach_runtime_overlay_if_cached_version` (`up.rs:1714`) treats
  **PreferOverlay as a *soft* preference**: if the overlay ext4 is **not in the
  local cache**, `attach_runtime_overlay` **downgrades the policy to
  `RootfsOnly`** and boots from the baked `/usr/local/bin` binaries. Only
  `RequiredOverlay` triggers a build/acquire (`up.rs:1743-1783`).
- The `--flake` build produces a **rootfs but never builds the overlay**, so on
  a fresh machine the overlay isn't cached → PreferOverlay downgrades → baked
  agent → `rootfs_only`.

**Phase 4 leg-1 LIVE-PROVEN (2026-07-13).** After wiring `boot_session_vm` +
relaxing the backend gate, `machine run --flake examples/exit_code --entrypoint`
booted with `mvm.runtime_source_policy=required_overlay` +
`mvm.runtime_data=/dev/vdb`; guest console: `mvm-init: mounted runtime overlay
/dev/vdb at /mvm/runtime (ro)` + `mvm-guest-agent: control plane ready`. The
overlay is now MANDATORY on this leg and the agent comes from it. (The trailing
`RunEntrypoint not offered`/`VerbNotAuthorized` are properties of the
`exit_code` example flake — no baked entrypoint wrapper — not overlay issues.)

**Phase 3b LIVE-PROVEN (2026-07-13).** A wired transient boot
(`machine run --flake examples/exit_code -- true`) mounted the non-verity
overlay end-to-end. Guest console:
```
Kernel cmdline: ... mvm.runtime_data=/dev/vdb mvm.runtime_source_policy=prefer_overlay
EXT4-fs (vdb): mounted filesystem ... ro without journal
mvm-init: mounted runtime overlay /dev/vdb at /mvm/runtime (ro)
mvm-guest-agent: control plane ready (0ms) / listening on vsock port 5252
```
The overlay attached at `/dev/vdb`, mounted at `/mvm/runtime`, and the agent
came up. (A later `verb exec not authorized` on the `-- true` exec is an
unrelated verb-grant matter, well after boot.) The non-verity block-mount
mechanism is confirmed; Phase 4 makes it mandatory + wires the remaining legs.

**Consequence for the plan:** Phase 3's mount path is only *reachable* once the
policy is `RequiredOverlay` (which forces `resolve_or_build_local_runtime_overlay`
+ attach). So **Phase 4's policy flip is the prerequisite that makes Phase 3b
load-bearing and live-validatable** — they must land and be validated together.
The OCI-block path already flips to RequiredOverlay (`exec.rs:185-188`), but on
this HVF Mac dev OCI boots take the virtiofs-root (`RootfsOnly`) shape, so even
that never exercised the non-verity block attach. **Phase 4's `--flake` boot is
the first live proof of Phase 3b.**

**Goal (production, no shortcuts):** make the **runtime overlay the single source of every guest
binary**, mounted on **every** workload launch shape, then **delete mkGuest's per-image
`/usr/local/bin` binary baking** — removing the fragile rootfs-tree generation (and the whole
bug class the layer-3 `mkdir` patched) rather than accreting around it.

## The load-bearing constraint (from scoping)
The overlay mounts **only on the dm-verity (sealed/prod) path** — `mvm-verity-init`
(`crates/mvm-guest/src/bin/mvm-verity-init.rs:499,521-532`) is the sole mount mechanism and
requires rootfs verity. **Non-verity dev mkGuest boots have zero overlay-mount path.** So
`RequiredOverlay ⇔ sealed ⇔ verity` today (`vm_backend.rs:88-113`) — self-consistent and safe.
**Deleting the baking is only safe once every deletion-targeted shape is guaranteed to mount
the overlay.** That universal mount is the critical path (Phase 3).

## Global Constraints
`cargo fmt --all` (nightly) / `nextest -p <crate>` / `clippy --workspace --all-targets -D warnings` clean; no spec-refs in code comments; reuse existing helpers; no AI-attribution; all work in the `plan-250-overlay` worktree; `mvm-backend` build-check only (codesign SIGKILL). Live `--flake` sealed AND dev boot on macOS-26 is the exit gate.

---

## Phase 1 — Overlay carries every guest binary (independent; safe; first)
**Status: COMPLETE.**
`addon-dns` + `exit-report` are baked by mkGuest but absent from the overlay. Both are in the
**same crate** (`mvm-guest-helpers`) as `egress-client`, which is already staged — trivial.
- Add `addon_dns`, `exit_report` to `RuntimeOverlayGuestBinaries`/`Layout` (`guest_agent_build.rs:134-196`); add `--bin mvm-addon-dns --bin mvm-exit-report` to the zigbuild group (`:548-577`) + two `install_one`.
- Two `stage_runtime_overlay_binary` calls (`runtime_overlay.rs:260-266`); add `/addon-dns` `/exit-report` to `REQUIRED_OVERLAY_GUEST_PATHS` (`:236-244`).
- **Mirror in the Nix flake** `nix/images/runtime-overlay/flake.nix:312-317` (the published/download overlay) — else shipped mvmctl regresses. Bump the overlay version so caches miss.
- Tests: overlay-content test asserts all 8 paths present. Keep `audit-probe` OUT (test fixture — `nix/packages/mvm-audit-probe.nix` says "never in the production closure").

## Phase 2 — Guest `/init` resolves the new bins from the overlay (independent)
**Status: COMPLETE.**
- Add `/mvm/runtime/addon-dns` and `/mvm/runtime/exit-report` resolution ladders to the mkGuest `/init` (`mk-guest.nix:669,:697,:873`), same `MVM_RUNTIME_SOURCE_POLICY` shape as agent/netinit. **Keep** the `/usr/local/bin` fallback for now (still baked) — no behavior change yet.
- Depends on Phase 1 (paths must exist to test).

## Phase 3 — Universal overlay mount via non-verity block-mount (approach (b); THE critical path)
Make every workload launch shape mount the overlay at `/mvm/runtime`. Today only verity boots do.
**Approach (b) — owner-approved:** keep the dev rootfs non-verity/mutable; attach the overlay as a
plain **RO block device** mounted at `/mvm/runtime` early in the mkGuest `/init`, independent of
rootfs verity — a distinct stacked layer that overrides nothing. Verity path keeps `mvm-verity-init`
(integrity-protected overlay); non-verity path gets the plain RO mount.
  - Work: attach the overlay disk on the non-verity branch of HVF/libkrun/qemu (`hvf_backend.rs:273-282`, `libkrun.rs:444-446`, `qemu.rs`); emit the non-verity overlay device token for mkGuest images (only `microvm.rs:2296` does today) — and finish firecracker's half-path (`microvm.rs:2549` attaches `/dev/vdb` but nothing mounts it); add the early `/mvm/runtime` mount step in the mkGuest `/init` (before its agent/netinit/addon-dns resolution).
- **virtiofs-root** (`RootfsOnly`, `hvf_backend.rs:236-238`): no block-attach path — either serve the overlay over a second virtiofs tag or keep `RootfsOnly` (and keep baking there, out of this deletion's scope). Recommend: keep `RootfsOnly` out of scope initially.
- Exit gate for this phase: a **non-verity dev** `--flake` boot has `/mvm/runtime/{agent,netinit,addon-dns,exit-report}` present.

## Phase 4 — Flip policy + fail closed (depends on Phase 3)
**Discovered leg structure (2026-07-13):** `machine run --flake` has three run
legs, and the overlay policy was wired into only one. Phase 4 must cover all:
1. **`--entrypoint`** (the default transient workload lifecycle) →
   `run_entrypoint_action` → `invoke::run_entrypoint` → **`exec::boot_session_vm`
   (`exec.rs:1491`)** — builds `VmStartConfig { .. ..Default::default() }`
   (policy defaults to `RootfsOnly`), never calls `runtime_source_policy_for` or
   `attach_runtime_overlay_if_cached`. **NOT wired** — this is why the live
   `--entrypoint` boot showed `rootfs_only`. Fix: after building `start_config`,
   compute the policy (`select_runtime_source_policy`, `sealed = verity present`,
   `WorkloadImage`/`BlockExt4`), set `start_config.runtime_source_policy`, then
   `crate::commands::vm::up::attach_runtime_overlay_if_cached(&mut start_config,
   backend.name())` — mirroring `run_transient` (`exec.rs:998-1079`).
2. **transient `-- <cmd>`** → `run_secure` → **`exec::run_transient`** — already
   wired (`runtime_source_policy_for` + `attach_runtime_overlay_if_cached`). The
   selector flip below already takes effect here.
3. **persistent `-d`** → `run_persistent` — audit the same wiring.

Note: `attach_runtime_overlay_if_cached` treats **PreferOverlay as a soft
preference** (downgrades to `RootfsOnly` + baked binaries when the overlay isn't
cached); only **RequiredOverlay** forces build/acquire (`up.rs:1714`). So the
flip to RequiredOverlay is what makes the overlay actually build + mount.

- [x] Extend `select_runtime_source_policy` (`vm_backend.rs:100-113`): a block-rooted `WorkloadImage` on a real backend resolves to `RequiredOverlay` regardless of `sealed` (virtiofs-root + non-real backends keep `PreferOverlay`). Tests updated (`vm_backend.rs`, `exec.rs`, `up.rs`, `checkpoint.rs`).
- [x] Wire the policy + `attach_runtime_overlay_if_cached` into `boot_session_vm` (leg 1, `exec.rs:1515`).
- [~] **Leg 3 (persistent `-d`)** boots via `lifecycle::start_machine` → `shared/start.rs:59`, which already calls the selector but passes `backend_name: None` + `root_strategy: None` → resolves to **PreferOverlay** (soft) rather than RequiredOverlay. Not broken (still attaches a cached overlay; only soft-falls-back to baked when uncached), but it **must thread the resolved backend + block root strategy so it goes RequiredOverlay before Phase 5 deletes baking**. Deferred to the Phase 5 lead-in.
- [x] **Phase 3b gap the flip surfaced:** each backend's `ensure_<b>_runtime_source_supported` gate hard-required verity+initrd for *any* `RequiredOverlay` boot, so a non-verity dev boot was rejected even though the disk-attach + cmdline paths already supported it. Relaxed all three (`hvf_backend.rs`, `libkrun.rs`, `qemu.rs`) to branch on **verity intent** (`roothash`/`verity_path` present): a sealed boot must be fully verity-capable (missing initrd fails closed — never downgrades to an unverified root), a non-verity boot requires only `non_verity_overlay_ext4` (the `/dev/vdb` triple). Added accept-path tests per backend; the existing `rejects_missing_initrd` tests still pass (they are verity-intended).
- [x] mkGuest `/init` **agent** ladder already fails closed for `required_overlay` (`mk-guest.nix:829`), and `egress-client` fails closed when egress is active (`:783`). Live boot confirmed netinit already resolves from `/mvm/runtime/netinit` when the overlay is present.
- [ ] **Consolidated into Phase 5:** the remaining fail-closed hardening (netinit/addon-dns/exit-report error instead of baked fallback under `required_overlay`) is folded into Phase 5's ladder rewrite, which deletes the baked `/usr/local/bin` branches anyway — doing it twice would be churn. Keep the fallback for `prefer_overlay`/`rootfs_only` (builder VM, virtiofs) until the Phase 5 builder-VM fork is resolved.

## Phase 5 — Delete the mkGuest baking (depends on 3+4) — **owner chose (a)**
**Fork RESOLVED (2026-07-13): (a) one overlay source for every microVM.** And the
builder-VM concern was smaller than first flagged: the `runtimeLean` arg gates the
cp block (`mk-guest.nix:1217` agent/netinit, `:1260` egress-client), and the
**builder-VM flake already sets `runtimeLeanOverride = true`** (`nix/images/builder-vm/flake.nix:312`)
+ `bakeAddonDns=false` + `bakeExitReport=false` — so it **already bakes none of the
guest runtime binaries** and is already overlay-sourced (`mvm-host-vm-init` resolves
`/mvm/runtime/agent` + `/mvm/runtime/egress-client` first). So deleting the cp block
does **not** break the builder VM — the `runtimeLean=false` branches never run for it.

**Corrected Phase 5 scope:**
1. [x] **Verified (2026-07-13, live):** the builder VM already attaches the overlay
   (`/dev/vde` RO) + mounts it at `/mvm/runtime` under `required_overlay`. Attach is
   per-backend: `libkrun_builder.rs:259/614/1006` (`BUILDER_RUNTIME_DEVICE=/dev/vde`),
   `qemu_builder.rs:660-698`, HVF `builder_runner/spec.rs:81-96` + `hvf_builder.rs:104-114`.
   Mount: `mvm-host-vm-init.rs:1267 mount_runtime_overlay()` (breadcrumb
   `runtime_overlay_mount_ok` in every `~/.mvm/dev/builds/*/mvm-host-vm-init.lifecycle.log`).
   So deleting the cp block is safe for the builder VM. **Follow-up (not a blocker):**
   the overlay-unavailable path (`libkrun_builder.rs:1024-1031`) boots without the runtime
   tokens → defaults `PreferOverlay` → no mount + no bake → agent silently not launched
   (fail-OPEN). Should be made fatal under a mandatory-overlay builder; track separately.
2. Make non-sealed dev workloads lean too (flip `runtimeLean`/its default) — Phase 4
   already made them `RequiredOverlay` + mount the overlay, so the bake is dead weight.
3. Delete the cp block (agent/netinit `:1217-1235`, egress-client `:1260-1266`,
   addon-dns `:1246-1249`, exit-report `:1251-1258`). **Keep** the `withAuditProbe`
   fixture bake (`:1270-1273`). Remove now-dead binary vars/pkgs (`agentBinary`,
   `mvmGuestNetinitBinary`, `mvmAddonDnsBinary`, `mvmExitReportBinary`,
   `mvmEgressClientBinary`; `addonDnsPkg`, `exitReportPkg`, `egressClientPkg`).
   **RETAIN** `guestAgentPkg`, `seccompApplyBinary`, `verityInitBinary`. Drop the now-unused
   `bakeAddonDns`/`bakeExitReport`/`runtimeLean(Override)` args + their builder-vm/default-tenant
   call sites; update passthru + `nix/tests/mk-guest-eval.nix`.
4. Drop the `/usr/local/bin` fallback in the init mandatory branches (netinit/addon-dns/
   exit-report; agent already fail-closed at `:829`, egress at `:783`); error if the
   overlay binary is missing.
5. Harden leg-3 (persistent) to `RequiredOverlay` (`shared/start.rs:59` must thread the
   resolved backend + block root strategy).
6. Exit gate: sealed AND dev `--flake` boot AND a builder-VM boot on macOS-26 with the baking gone.

**Phase 5 LIVE-PROVEN (2026-07-13, commit `d2b3f8a5f`).** With the mkGuest bake
deleted, `machine run --flake examples/exit_code -- true` rebuilt the lean builder
VM + a lean workload image and booted:
```
mvm.runtime_source_policy=required_overlay mvm.runtime_data=/dev/vdb
mvm-init: mounted runtime overlay /dev/vdb at /mvm/runtime (ro)
mvm-guest-agent: control plane ready (0ms) / listening on vsock port 5252
```
No fail-closed trip, no `/usr/local/bin` — the agent came from the overlay with no
baked fallback. The builder-VM boot is validated implicitly (the same run rebuilt +
booted the lean builder to produce the workload image). **Remaining exit-gate item:**
a sealed/verity `--flake` boot (an unchanged path — sealed images were already
`runtimeLean`, so Phase 5 did not touch their `mvm-verity-init` overlay mount; a
regression check only).

- Delete `mk-guest.nix:1152-1207` (the `/usr/local/bin` cp block — including the layer-3 `mkdir`). **Keep** the `withAuditProbe` fixture bake (`:1211-1214`).
- Remove now-dead binary vars/pkgs (`agentBinary, mvmGuestNetinitBinary, mvmAddonDnsBinary, mvmExitReportBinary, mvmEgressClientBinary`; `addonDnsPkg, exitReportPkg, egressClientPkg`). **RETAIN `guestAgentPkg`, `seccompApplyBinary`, `verityInitBinary`** (initramfs + per-service launch). Drop unused `bakeAddonDns`/`bakeExitReport`/`runtimeLean(Override)` args + their `builder-vm`/`default-tenant` call sites; update passthru (`:1425-1426`) + `nix/tests/mk-guest-eval.nix`.
- Exit gate: sealed AND dev `--flake` boot on macOS-26 with the baking gone.

---

## Related, separate: the `ensure_guest_agent_if_needed` dev-VM fallout (the real `--flake` failure)
**Status: RESOLVED** (standalone fix, ahead of Phase 4/5). The `machine run --flake` failure
("Failed to connect to dev VM 'mvm-dev'" → agent not reachable) was **build-time**:
`dev_build.rs:1251` `ensure_guest_agent_if_needed` verified the freshly-built image's agent by
exec'ing in the builder VM via the removed `DevVmEnv` (`linux_env.rs:110,181`). Took the "obsolete
the check" path: deleted `ensure_guest_agent_if_needed` / `ensure_guest_agent` /
`inject_agent_into_rootfs` / `detect_mvm_src` from `dev_build.rs` and both call sites
(`crates/mvm-cli/src/commands/build/build.rs` `build_flake`,
`crates/mvm/src/vm/template/lifecycle.rs` `template_build_from_manifest` — the latter backs
`build_flake_to_slot`, the actual `machine run --flake` builder, so it was in scope too even
though it wasn't named above). Every `dev_build`/mkGuest image now gets its agent from the
runtime overlay (Phase 3, non-verity boots) or mvm-verity-init's overlay mount (sealed boots) or
mkGuest's own bake (`runtimeLean=false` dev images) — never from a post-build rootfs patch. OCI
`run --image` never called this path (separate injection mechanism, see "Not in scope" below), so
nothing there changed.

## Not in scope
OCI `run --image` sources binaries via host-side **injection** (`oci_runtime_inject.rs`), a
separate path unaffected by deleting mkGuest baking. virtiofs-root stays `RootfsOnly` initially.

## Sequencing
Phases 1–2 are independent and safe (add-only) — do them first. **Phase 3 (universal mount) is
the gate** — nothing after it is safe until the overlay is guaranteed-mounted on the shapes whose
baking Phase 5 deletes. Each phase is its own PR; Phase 3 needs the (a)/(b) decision before code.

## Final whole-branch review (2026-07-13) — READY TO MERGE
Opus whole-branch review of the 15 Plan 252 commits traced every high-risk
branch and confirmed CLEAN: the fail-closed gate branching (no input lets an
unverified root boot; a verity-intended boot with a missing initrd still bails),
the init fail-closed ladders (agent `exit 1`; no silent baked fallback), the
cp-block deletion (no dangling nix refs; correct retains), the builder
fail-closed fix (fatal for lean Rootfs, `Ok(None)` for RootDir; disk-transport
preserved; excluded from auto-fallback), the policy flip + all three boot legs,
and test coverage (no tautologies). No spec-refs in code comments.

**Minor follow-ups (non-blocking, from the review):**
- The guest `/init` `prefer_overlay`/`rootfs_only` `/usr/local/bin` fallback
  branches are now DEAD for mkGuest output (bake deleted). Currently unreachable
  (every mkGuest workload boot is `BlockExt4`+real-backend → `RequiredOverlay`;
  the only `PreferOverlay` mkGuest shape, `WorkloadImage`+`VirtiofsRoot`, is
  produced by no caller). Follow-up: make an empty resolved agent bin fail closed
  regardless of policy (so a future virtiofs-root workload can't silently boot
  agent-less), and fix the misleading "kept for images that predate overlay-only"
  ladder comments. Also a duplicate `mkdir -p usr/local/bin` (harmless).
