# Plan 246 Phase 2 — `mvmctl dev` removal (done) + deferred follow-ups

**Date:** 2026-07-11
**Branch/PR:** `feat/plan-246-phase2`
**Design:** `specs/notes/2026-07-11-oci-run-builder-vm-demotion-design.md`

## Done

Deleted the `mvmctl dev` interactive command surface — a useless interactive shell
over the builder VM. The builder VM is now purely a headless nix build engine
(bootstrapped by `mvmctl bootstrap`, or lazily on first `build`/`machine run`); the
only interactive console left is the workload console (`mvmctl console`,
`machine run -it`), which is a separate, `dev-shell`-feature-gated, claim-15-compliant
path (never interactive access to a sealed prod microVM).

- Removed: `env/dev.rs`, `env/linux_native.rs`, `env/dev_vz/status.rs`, dev-only
  functions in `env/dev_vz/image_ops.rs` (777→78 lines) + `stage0_cache.rs`
  (`build_image_via_libkrun`), the clap `Dev` surface, `ops bench first-use`, a
  `dev-up`-based e2e test, and all dev tests. `DEV_VM_NAME`/`mvm-dev` gone.
- Kept (verified, shared): `console_interactive`/`pick_console_transport`/
  `DevConsoleTransport`/`VmStartConfig.dev_console`, `sweep_orphaned_vm_helpers_on_startup`,
  and the headless build engine (`bootstrap_builder_vm_image`, `ensure_workload_kernel`,
  `build_kernel_via_stage0`, `verify_stage0_rootfs_has_init`, `persistent_builder`).
- Repointed 29 live user-facing hints from `mvmctl dev up` → `mvmctl bootstrap` /
  `mvmctl cache repair` (dev up was also the canonical "populate the builder VM" action).
- Updated `CLAUDE.md` + `public/src/content/docs/reference/cli-commands.md`.
- Whole-branch reviewed (top-tier): shared internals intact, stub honest, no over-deletion.

## Deferred follow-ups

1. **`run_in_vm` → headless-builder migration.** `mvmctl dev up` was also the macOS
   auto-boot vehicle for `run_in_vm` (host-side Linux shell ops used by
   `mvm/src/security/*`, `vm/template/lifecycle.rs`, `build_env.rs`).
   `DevVmEnv::start_dev_daemon` (`mvm-backend/src/base/linux_env.rs`) is now **stubbed
   to fail loudly** instead of spawning the removed command. So on macOS 26+, any op
   that routes through `run_in_vm` without an already-running VM hard-fails. The real
   fix: route those ops to the headless builder (`persistent_builder`) or move them
   in-process. Aligns with the vsock-only / in-process direction — worth its own plan.

2. **Public docs reframe.** `CLAUDE.md` + the CLI reference are updated, but the
   getting-started guides and `public/src/content/docs/guides/**` still narrate a
   "`mvmctl dev` drops you into a dev shell" workflow. Reframe to the headless flow
   (`mvmctl bootstrap` → `mvmctl build` / `mvmctl machine run`; debug builds via logs).

3. **Air-gapped image import.** `mvmctl dev import-image` (the air-gapped builder-image
   populate path) was removed with no named successor (`BuilderVmBootstrapArgs` is an
   empty struct). If air-gapped operators are supported, provide a headless
   air-gapped populate command; otherwise record the capability as intentionally dropped.
