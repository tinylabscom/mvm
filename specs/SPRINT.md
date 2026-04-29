# Sprint 42 — TBD

**Goal:** TBD — pick the next slice once Sprint 41's live smoke validates
on a real Linux/KVM host.

**Branch:** `main`

## Current Status (v0.11.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 7 + root facade + xtask  |
| Total tests      | 1 008                    |
| Clippy warnings  | 0                        |
| Edition          | 2024 (Rust 1.85+)        |
| MSRV             | 1.85                     |
| Binary           | `mvmctl`                 |

## Completed Sprints

- [01-foundation.md](sprints/01-foundation.md)
- [02-production-readiness.md](sprints/02-production-readiness.md)
- [03-real-world-validation.md](sprints/03-real-world-validation.md)
- Sprint 4: Security Baseline 90%
- Sprint 5: Final Security Hardening
- [06-minimum-runtime.md](sprints/06-minimum-runtime.md)
- [07-role-profiles.md](sprints/07-role-profiles.md)
- [08-integration-lifecycle.md](sprints/08-integration-lifecycle.md)
- [09-openclaw-support.md](sprints/09-openclaw-support.md)
- [10-coordinator.md](sprints/10-coordinator.md)
- Sprint 11: Dev Environment
- [12-install-release-security.md](sprints/12-install-release-security.md)
- [13-boot-time-optimization.md](sprints/13-boot-time-optimization.md)
- [14-guest-library-and-examples.md](sprints/14-guest-library-and-examples.md)
- [15-real-world-apps.md](sprints/15-real-world-apps.md)
- [16-production-hardening.md](sprints/16-production-hardening.md)
- [17-resource-safety-release.md](sprints/17-resource-safety-release.md)
- [18-developer-experience.md](sprints/18-developer-experience.md)
- [19-observability-security.md](sprints/19-observability-security.md)
- [20-production-hardening-validation.md](sprints/20-production-hardening-validation.md)
- [21-binary-signing-attestation.md](sprints/21-binary-signing-attestation.md)
- [22-observability-deep-dive.md](sprints/22-observability-deep-dive.md)
- [23-global-config-file.md](sprints/23-global-config-file.md)
- [24-man-pages.md](sprints/24-man-pages.md)
- [25-e2e-uninstall.md](sprints/25-e2e-uninstall.md)
- [26-audit-logging.md](sprints/26-audit-logging.md)
- [27-config-validation.md](sprints/27-config-validation.md)
- [28-config-hot-reload.md](sprints/28-config-hot-reload.md)
- [29-shell-completions.md](sprints/29-shell-completions.md)
- [30-config-edit.md](sprints/30-config-edit.md)
- [31-vm-resource-defaults.md](sprints/31-vm-resource-defaults.md)
- [32-vm-list.md](sprints/32-vm-list.md)
- [33-template-init-preset.md](sprints/33-template-init-preset.md)
- [34-flake-check.md](sprints/34-flake-check.md)
- [35-run-watch.md](sprints/35-run-watch.md)
- [36-fast-boot-minimal-images.md](sprints/36-fast-boot-minimal-images.md)
- [37-image-insights-dx-guest-lib.md](sprints/37-image-insights-dx-guest-lib.md)
- [38-multi-backend-abstraction.md](sprints/38-multi-backend-abstraction.md)
- [39-developer-experience-dx.md](sprints/39-developer-experience-dx.md)
- [40-apple-container-dev.md](sprints/40-apple-container-dev.md)
- [41-microvm-one-shot-exec.md](sprints/41-microvm-one-shot-exec.md)

---

## Open Follow-ups (carryover from Sprint 41)

Tracked as GitHub issues so they're individually grabbable:

- [ ] [#3](https://github.com/tinylabscom/mvm/issues/3) — Live smoke for `mvmctl exec` on Linux/KVM and Lima dev VM (boot+exec+teardown, `--add-dir`, SIGINT, `nix build` of `nix/default-microvm/`). _Needs real hardware._
- [x] [#4](https://github.com/tinylabscom/mvm/issues/4) — Release artifacts for the bundled default microVM image. Release workflow now builds `nix/default-microvm/` per-arch and uploads `default-microvm-vmlinux-{arch}` / `default-microvm-rootfs-{arch}.ext4` / `default-microvm-{arch}-checksums-sha256.txt`. `ensure_default_microvm_image()` falls back to `download_default_microvm_image()` when Nix is unavailable or the local build fails. Cosign scope unchanged (artifacts unsigned, mirroring `dev-image`).
- [x] [#5](https://github.com/tinylabscom/mvm/issues/5) — mvmforge `launch.json` consumption: `ExecTarget::LaunchPlan` + entrypoint parser + `--launch-plan` flag. Image-from-launch-plan remains a future variant (mvmforge v0 `apps[].source` is itself "deferred").
- [ ] [#6](https://github.com/tinylabscom/mvm/issues/6) — Writable `--add-dir` (virtio-fs or 9p) — separate design / ADR required.
- [x] [#7](https://github.com/tinylabscom/mvm/issues/7) — Snapshot restore for `mvmctl exec` (easy branch: registered template, no `--add-dir`). The harder branch (parameterized snapshots for the `--add-dir` case) stays open under the same issue.
