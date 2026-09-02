# Resume Boot — live witness and defect fixes

Date: 2026-08-19
Plan: `specs/plans/2026-08-19-resume-boot.md`

## What was witnessed

A resumed durable agent session booted a real Firecracker microVM on real KVM
hardware (Hetzner AX102, Ubuntu 24.04, kernel 6.8.0-137-generic, Firecracker
v1.14.1). The lifecycle executed end to end:

1. `mvmctl agent-session open witness-resume-boot --resume-point <digest> --member bootprobe3`
2. `mvmctl agent-session park witness-resume-boot --reason retention-demotion`
3. `mvmctl agent-session resume witness-resume-boot --boot --backend firecracker ...`

The resume path advanced the session record to generation 2, staged the resume
point's blobs into the session's own state directory, admitted a fresh signed
plan, configured Firecracker, and started the VM. The guest kernel
(`6.12.103 #1-NixOS`) reached userspace in 56 ms.

## Result

**The resume machinery worked.** Every host-side stage — admit, transition,
stage, launch — executed against real hardware. The VM failed in guest
userspace because the cold-boot config did not attach the runtime overlay or
the dm-verity roothash tokens, so a runtime-lean rootfs booted with
`rootfs_only` policy and `mvm-oci-init` exited with status 1.

## Defects closed in this follow-up

### 8.1 — Cold boot now attaches the runtime overlay and verity sidecars

`cold_boot_config` in `crates/mvm-hostd/src/session_resume.rs` previously built
its `VmStartConfig` from five fields and `..Default::default()`, dropping the
runtime-source policy, the overlay, and any dm-verity binding. It now:

- preserves the checkpoint's recorded `runtime_source_policy` (falling back to
  the same workload-image rule a fresh run uses);
- attaches the runtime overlay from the host cache via the same
  `attach_runtime_overlay_from_cache` helper the CLI run path uses;
- stages and threads `verity_path` and `roothash` when the resume point carries
  a complete `rootfs.verity` + `rootfs.roothash` sidecar set, refusing an
  incomplete set by name.

Tests added:

- `cold_boot_config_uses_recorded_runtime_source_policy`
- `cold_boot_config_falls_back_to_workload_image_policy_for_legacy_checkpoint`
- `cold_boot_config_stages_and_names_verity_sidecars`
- `cold_boot_config_refuses_incomplete_verity_sidecar_set`

### 8.3 — The audit chain now records `session.resumed` before the boot attempt

`resume_and_boot` previously relied on the CLI to emit `session.resumed` only
after a successful boot. A boot failure therefore left the chain saying the
session was still parked while the on-disk record said it was active at the new
generation. The emission is now done in `resume_and_boot` immediately after
`resume_session` transitions the record, before `cold_boot_config` or
`start_admitted` can fail. A chain-write failure is logged but does not stop the
boot, matching the existing best-effort audit posture.

Test added:

- `a_booting_resume_records_session_resumed_before_the_boot`

## Known defect not closed here

### 8.2 — x86 Firecracker kernel digest pin covers the source, not the loaded ELF

On x86 Firecracker, `mvm_vmm::host::fc_kernel::ensure_fc_loadable_kernel`
extracts an uncompressed ELF sibling (`vmlinux.elf`) from the bzImage the caller
passes. The admitted-environment gate verifies the digest of the caller's
`vmlinux`, but Firecracker loads the `.elf`. The derivation tracks freshness by
source size+mtime, not by content hash, so the plan's kernel pin does not cover
the bytes that execute. This is pre-existing across all Firecracker x86 boots,
not specific to resume, and is documented in the updated
`ColdBootParams::kernel_path` doc comment. A proper fix belongs in the kernel
admission path rather than the resume boot slice.

## Verification

- macOS host: `cargo nextest run -p mvm-runtime -p mvm-hostd -p mvm-cli` —
  4900 passed, 20 skipped.
- macOS host: `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- Linux KVM host (previous witness run): `cargo nextest run -p mvm-hostd -p
  mvm-runtime -p mvm-cli` — 4936 passed, 21 skipped.

The Linux-gated Firecracker path is only exercised on the KVM host; the macOS
runs validate the rest of the workspace.

## Files changed

- `crates/mvm-hostd/src/run.rs` — made `attach_runtime_overlay_from_cache`
  `pub(crate)` so the resume path can reuse it.
- `crates/mvm-hostd/src/session_resume.rs` — cold-boot overlay/verity attachment,
  `session.resumed` emission before boot, tests.
- `crates/mvm-cli/src/commands/agent_session.rs` — pass the chain emitter into
  `resume_and_boot` instead of recording after the boot.
- `specs/plans/2026-08-18-durable-agent-sessions.md` — D5 state update.
- `specs/plans/2026-08-19-resume-boot.md` — all checkboxes ticked.
- `specs/REFACTOR-STATUS.md` — durable agent sessions status update.
- `specs/sprint/delivery/resume-boot.md` — this file.
