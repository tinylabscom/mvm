# Plan 325 — SDK sidecar reserved mount

**Status:** IN PROGRESS — implementation, hermetic regressions, and native HVF
acceptance are green; native libkrun acceptance remains.

## Problem

`machine run --host-service ...` attached the SDK sidecar as a dedicated
read-only block device and named it with `mvm.sdk_dev`, but also encoded it in
the generic `mvm.uvols` manifest. The generic user-volume policy correctly
rejects `/mvm/sdk`, so the OCI init exited and the kernel panicked before the
guest agent could register. HVF and libkrun then surfaced only the downstream
30-second readiness timeout.

## Scope

- [x] Reproduce the failure from the guest console and identify the rejected
      `/mvm/sdk` generic volume.
- [x] Keep the SDK disk physically attached while excluding it from legacy and
      universal generic-volume activation.
- [x] Mount the device named by `mvm.sdk_dev` at the fixed `/mvm/sdk` path with
      read-only, nosuid, and nodev flags.
- [x] Exclude the dedicated SDK device when legacy init discovers trailing
      virtio block devices for ordinary user volumes.
- [x] Validate the SDK device against the narrow `/dev/vd[a-z]` policy.
- [x] Add regressions for cmdline partitioning, activation partitioning,
      device discovery, and device-path validation.
- [x] Add hermetic BDD coverage for the corrected `/mnt/wheels` plus
      SDK-sidecar attachment shape and prove the SDK mount bypasses
      `mvm.uvols`.
- [x] Refuse directory-share guest paths outside `/data`, `/work`, and `/mnt`
      during host preflight so invalid mounts never become readiness timeouts.
- [x] Keep an explicitly invoked worktree `mvmctl` paired with guest binaries
      from that worktree even when the shell is inside another checkout.
- [x] Isolate Cargo cross-build targets by source key and invalidate guest/OCI
      caches that may contain outputs reused from another checkout.
- [x] Pre-create `/mvm/sdk` before sealing OCI roots so PID 1 never has to
      mutate a dm-verity-protected root to mount the sidecar.
- [x] Preserve a bounded, PII-redacted guest-console tail in agent-readiness
      errors before transient teardown removes the VM state directory.
- [x] Build `mvm-host-agent` and `mvm-signer-helper` beside source-built
      `mvmctl`, pass exact admitted service bindings to the broker, and serve
      `host.time.v1::now` without widening the registry to unbound services.
- [x] Add hermetic BDD coverage across the real framed broker server and typed
      SDK time client.
- [x] Prove the original Python `host.time.v1` command on native HVF.
- [ ] Prove the same command with `--hypervisor libkrun`.
- [x] Complete workspace tests, check, and all-target Clippy gates.

## Acceptance

The guest reaches authenticated agent readiness, `/mvm/sdk` is mounted only
through its dedicated read-only contract, and `mvm.host.time()` succeeds on
both native HVF and libkrun.
