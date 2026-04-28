# Sprint 41 — MicroVM One-Shot Exec

**Goal:** Add `mvmctl exec --template <name> -- <cmd>` — boots a transient
Firecracker microVM, runs a single command (with stdio + exit code wired through),
and tears down on exit. Includes `--add-dir host:guest` (read-only via ext4
image) for sharing host directories into the sandbox. Inspired by [cco](https://github.com/nikvdp/cco)'s
sandbox-wrapper UX, but with a microVM as a strictly stronger isolation boundary.

Dev DX only. Inherits the existing `policy.access.debug_exec` gate (dev-mode
only). No production policy changes.

**Branch:** `feat/microvm-one-shot-exec`

**Plan:** [specs/plans/24-microvm-one-shot-exec.md](plans/24-microvm-one-shot-exec.md)

## Current Status (v0.11.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 7 + root facade + xtask  |
| Total tests      | 987                      |
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

---

## Rationale

`mvmctl` already has every primitive needed to run a single command in a
microVM: `cmd_run` boots a VM headlessly, `cmd_console <vm> --command "..."`
runs one command over vsock and propagates the exit code, templates+snapshots
give fast boot, and `cmd_down` tears the VM down. What's missing is the
**orchestration**: a single command that does boot → run → teardown atomically
with stdio wired through.

[cco](https://github.com/nikvdp/cco) ships exactly this UX for OS-level
sandboxes (`sandbox-exec` / `bubblewrap` / Docker). A microVM is a strictly
stronger isolation boundary, and offering the same one-command UX makes that
boundary cheap to reach for.

A future companion: [mvmforge](https://github.com/tinylabscom/decorationer)
emits a `launch.json` with an `entrypoint` block (`command`, `working_dir`,
`env`). The eventual goal is for `mvmctl exec` to consume that block directly.
**That work is out of scope for this sprint**, but the orchestrator's internal
`ExecTarget` enum reserves the slot so it can be added without churning the
inline-command surface.

---

## Phase 1: Orchestrator Skeleton ✓

### 1a. Image source decoupled from boot path ✓

- [x] `crates/mvm-cli/src/exec.rs` — new module owns the orchestrator and
      doesn't share state with the long-blocking `cmd_run`. Cold-boot only
      (snapshot path skipped in v1; extra drives change the layout).
- [x] No behavior change for existing `mvmctl up` / `mvmctl run` callers.
- [x] `read_only` field added to `VmVolume` / `RuntimeVolume`; Firecracker
      drive emit honors it (`crates/mvm-runtime/src/vm/microvm.rs`).

### 1b. `ExecRequest` + `ExecTarget` + `ImageSource` types ✓

- [x] `ExecRequest` struct in `crates/mvm-cli/src/exec.rs`.
- [x] `ExecTarget` is `#[non_exhaustive]` with one variant `Inline { argv }`;
      future `LaunchPlan` / `TemplateEntrypoint` variants reserved by comment.
- [x] `ImageSource` is `#[non_exhaustive]` with `Template(String)` and
      `Prebuilt { kernel_path, rootfs_path, … }`. The CLI selects `Prebuilt`
      with the cached exec-default image when `--template` is omitted.

---

## Phase 2: CLI Surface ✓

### 2a. `Commands::Exec` Clap variant ✓

- [x] `crates/mvm-cli/src/commands.rs` — new `Commands::Exec` variant with
      `--template` (optional), `--cpus`, `--memory`, `--env`, `--add-dir`
      flags and a trailing `-- <argv>...`.
- [x] CLI dispatch routes `Exec` to `run_oneshot`, which builds the
      `ExecRequest` and calls `crate::exec::run`.
- [x] Parsing tests for happy paths, defaults, and the requires-argv guard
      live in `commands.rs::tests` (`exec_default_template_argv_only`,
      `exec_with_template_and_resources`, `exec_with_add_dir_and_env`,
      `exec_requires_argv`).

### 2b. `run_oneshot` orchestrator ✓

- [x] Resolves the image: registered template via
      `template::lifecycle::template_artifacts`, OR cached exec-default image
      via the new `ensure_exec_default_image()`.
- [x] Allocates transient instance name `exec-<pid>-<rand>`.
- [x] Boots via `backend.start(&VmStartConfig)` (cold boot — snapshot path
      skipped in v1 because extra `--add-dir` drives don't match the
      snapshot's recorded drive layout).
- [x] Waits for the guest agent (vsock UDS or Apple Container vsock).
- [x] Sends `GuestRequest::Exec { command, stdin, timeout_secs }` with a
      wrapper script that mounts each `--add-dir` by ext4 label and exports
      `--env` vars before `exec`-ing the user's argv.
- [x] SIGINT handler that calls `backend.stop` so Ctrl-C tears the VM down.
- [x] Teardown on every exit path (success, failure, signal); staging dir is
      cleaned up best-effort.

---

## Phase 3: `--add-dir` Read-Only Host Mount ✓

### 3a. Build a read-only ext4 image from a host directory ✓

- [x] `crates/mvm-runtime/src/vm/image.rs` — new `build_dir_image_ro` helper
      sizes ext4 (du + 8 MiB headroom, 4 MiB-rounded), `mkfs.ext4`s with a
      caller-provided label, mounts/copies/unmounts via `shell::run_in_vm`.
      Validates label (1–16 ASCII alphanumeric/dash chars).
- [x] Orchestrator stages the image at
      `<vms_dir>/<vm_name>/extras/extra-N.ext4` and attaches it as an extra
      drive with `read_only=true`.

### 3b. Guest-side mount ✓

- [x] No guest-init or agent protocol change required. The orchestrator
      prepends `mount LABEL=mvm-extra-N <guest_path> -o ro` to the wrapper
      script the guest agent runs (agent runs as root via PID 1 init).

### 3c. Parsing tests ✓

- [x] `AddDir::parse` covers happy path, missing colon, empty host/guest,
      relative guest path, `~` expansion, and extra colons in guest path.
- [x] `build_guest_wrapper` test asserts the mount + export + exec lines
      compose correctly with shell-quoted values.
- [x] `build_dir_image_ro` rejects oversized, invalid-char, and empty labels.
- [ ] Live integration test booting a real microVM and reading
      `--add-dir /tmp:/host -- cat /host/foo` is deferred — requires a Linux
      host with KVM in CI; tracked separately.

---

## Phase 4: Verification

- [x] `cargo test --workspace` clean (1 008 tests pass; +21 new).
- [x] `cargo clippy --workspace -- -D warnings` clean.
- [x] CLI parses correctly:
      `mvmctl exec -- uname -a`,
      `mvmctl exec --template my-tpl -- /bin/true`,
      `mvmctl exec --add-dir /tmp:/work -e FOO=bar -- ls /work`.
- [ ] Live boot+exec+teardown smoke test on Linux/KVM and macOS/Lima
      (deferred — needs a real host environment).
- [ ] CLI reference doc page updated
      (`public/src/content/docs/reference/cli-commands.md`).

---

## Phase 5: Bundled Default microVM Image ✓

(Added during implementation in response to user request.)

- [x] `nix/default-microvm/flake.nix` — minimal `mkGuest` with no extra
      packages (busybox + the auto-included guest agent are sufficient).
- [x] `find_default_microvm_flake()` locates the bundled flake via
      `CARGO_MANIFEST_DIR`.
- [x] `ensure_default_microvm_image()` builds via Nix on first use, caches at
      `~/.cache/mvm/default-microvm/`, and emits a clear error pointing at
      `--template`/`--flake` if Nix is unavailable. **No download fallback** —
      release artifacts for this image will be added in a follow-up sprint.
- [x] **`mvmctl exec`** uses this image when `--template` is omitted (boots
      a fresh transient microVM each invocation; never reuses the dev VM).
- [x] **`mvmctl up`/`run`/`start`** drop `required(true)` from the
      `--flake`/`--template` group and use this image when neither is
      supplied. CLI test `test_run_without_source_uses_default_microvm`
      replaces the prior `test_run_requires_source`.

---

## Out of Scope (explicitly)

- Writable `--add-dir` / virtio-fs / 9p — separate design needed.
- Persistent sessions (`cco --persist=...`).
- Auto-snapshot warming.
- Runtime package install (`cco --packages`). Bake into the template instead.
- mvmforge `launch.json` consumption — `ExecTarget` enum reserves the slot.

---

## Platform Caveats

- **Linux/KVM:** Full support. Snapshot restore should give sub-second boot.
- **macOS / Lima (QEMU):** Vsock snapshots fail with `os error 95`
  (EOPNOTSUPP). Cold boot path still works; orchestrator must fall back
  gracefully when snapshot restore fails on this backend.
- **macOS / Apple Container:** Inherits the existing boot-model blocker
  (`memory/project_apple_container_boot_model.md`) — `mvmctl exec` won't work
  there until that lands.

---

## Key Files

| File | Changes |
|------|---------|
| `crates/mvm-cli/src/exec.rs` | New module: `ExecRequest`, `ExecTarget`, `ImageSource`, `AddDir`, orchestrator `run` |
| `crates/mvm-cli/src/commands.rs` | New `Commands::Exec` Clap variant; `run_oneshot` wrapper; `ensure_default_microvm_image()` + `find_default_microvm_flake()`; `Commands::Up` source group no longer required; `cmd_run` falls back to the default image |
| `crates/mvm-cli/src/lib.rs` | `pub mod exec` |
| `crates/mvm-runtime/src/vm/image.rs` | `RuntimeVolume.read_only` + `build_dir_image_ro` helper |
| `crates/mvm-runtime/src/vm/microvm.rs` | Honor `vol.read_only` when emitting Firecracker drive JSON |
| `crates/mvm-runtime/src/vm/backend.rs` | Propagate `read_only` through `FirecrackerConfig::from_start_config` |
| `crates/mvm-core/src/vm_backend.rs` | `VmVolume.read_only` + `Default` impl |
| `nix/default-microvm/flake.nix` | New: bundled default image used by `mvmctl exec` and `mvmctl up`/`run`/`start` when no source is given |
| `public/src/content/docs/reference/cli-commands.md` | _(deferred — follow-up)_ document `mvmctl exec` |

---

## Verification

```bash
cargo test --workspace                       # all green
cargo clippy --workspace -- -D warnings      # zero warnings

# CLI parses (host-only sanity, no VM boot):
mvmctl exec --help
mvmctl up   --help

# End-to-end (requires a Linux/KVM host or Lima dev VM):
mvmctl exec -- uname -a                                       # uses bundled default microVM
mvmctl exec --template minimal -- /bin/true                   # exit 0
mvmctl exec --template minimal -- /bin/false                  # exit 1
echo hello > /tmp/foo
mvmctl exec --add-dir /tmp:/host -- cat /host/foo             # prints "hello"

mvmctl up                                                     # boots a long-running default microVM
mvmctl up --template minimal                                  # registered template
mvmctl up --flake .                                           # local flake (existing behavior)
```
