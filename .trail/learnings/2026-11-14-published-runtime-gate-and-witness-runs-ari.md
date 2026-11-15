# The published-runtime gate and issue-witness runs

**Date:** 2026-11-14

## What unblocked when

The `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=download` launch path requires the **published** OCI guest runtime (release-proof verified). Pre-release trees whose runtime archive is not yet published refuse at launch ("the published OCI guest runtime is not prepared"), and source-built or cache-copied runtimes carry no release proof. This blocked two witnesses on 2026-11-13/14:

- #4184's protected-capture native HVF witness (box 6) — blocked at rc.3.
- Faster runs generally — the lane falls back to a ~20 min source build.

**v0.28.0-rc.4 published (2026-11-14)**: trees at rc.4 can download the runtime. The #4184 witness is re-runnable at rc.4 without the fixture-owner workaround — assemble the witness lane the same way (integration mvmctl + entitled supervisor + the compiled `protected_capture_live_hvf` binary from an rc.4 tree, isolated /tmp fixture home) and the download path should now verify the published proof.

## Reusable recipes established

- **GCP disposable KVM runs** (`scripts/run-gcp-kvm-test.sh`): pass the bare command only. The remote script (`run-gcp-kvm-test-remote.sh:166-191`) already creates the unprivileged `mvm-test` user with the kvm group, linger, and the systemd user-manager bus Firecracker needs. Wrappers that add their own useradd/runuser/session-bus dance run INSIDE that unprivileged context and fail (useradd PATH, /etc/passwd lock, mkdir perms). Launch the outer script under `nohup ... &` — a local task-runner heartbeat kill drops the ssh and the remote job dies with it (exit 101, no results).
- **HVF warm-claim lane on a fresh home** (`just bdd::live-warm-claim`): needs `just payload::supervisors --profile release-witness` + ad-hoc codesign with `assets/mvm-supervisor.entitlements` (the recipe only builds KVM helpers), and the guest runtime seeded into the worktree's effective cache (`.mvm-test/cache` under `scripts/dev-env.sh`, NOT the pair home) or a source build via `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build`.
- Both lanes' long builds: run detached with logs to /tmp and poll; agent/task timeouts keep killing foreground attempts mid-compile.
