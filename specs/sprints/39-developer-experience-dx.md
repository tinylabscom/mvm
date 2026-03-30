# Sprint 39 — Developer Experience & DX Features

**Goal:** Borrow the best DX patterns from AlanD20/mvmctl — XDG-compliant
directories, named network management, Nix-based image catalog, enhanced audit
logging, and PTY-over-vsock console — while keeping Nix, vsock-only security,
and Rust.

**Branch:** `main`

**Plan:** [cuddly-enchanting-lollipop.md](~/.claude/plans/cuddly-enchanting-lollipop.md)

## Current Status (v0.8.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 7 + root facade + xtask  |
| Total tests      | 956                      |
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

---

## Rationale

AlanD20/mvmctl (Python) proves a Firecracker CLI can feel as approachable as
Docker. Our Rust project is more powerful (Nix images, vsock-only, fleet
orchestration) but has a steeper onboarding curve. This sprint borrows the best
DX ideas while keeping our architecture.

---

## Phase 1: Foundation Types & XDG Directories ✓

### 1a. XDG-compliant directory functions ✓

- [x] `mvm_cache_dir()` → `$XDG_CACHE_HOME/mvm` or `~/.cache/mvm`
- [x] `mvm_config_dir()` → `$XDG_CONFIG_HOME/mvm` or `~/.config/mvm`
- [x] `mvm_state_dir()` → `$XDG_STATE_HOME/mvm` or `~/.local/state/mvm`
- [x] `mvm_share_dir()` → `$XDG_DATA_HOME/mvm` or `~/.local/share/mvm`
- [x] Env overrides: `MVM_CACHE_DIR`, `MVM_CONFIG_DIR`, `MVM_STATE_DIR`, `MVM_SHARE_DIR`
- [x] `user_config.rs` updated to prefer XDG with legacy `~/.mvm/` fallback
- [x] `audit.rs` updated to prefer `mvm_state_dir()` with legacy fallback
- [x] Tests for all XDG resolution paths (env override, XDG var, default)

### 1b. DevNetwork type ✓

- [x] `DevNetwork` struct in `mvm-core/src/dev_network.rs` (name, bridge_name, subnet, gateway, created_at)
- [x] `DevNetwork::default_network()` matches legacy hardcoded `br-mvm`
- [x] `DevNetwork::new(name, slot)` with auto-assigned 172.16.X.0/24 subnets
- [x] `gateway_cidr()` helper
- [x] `validate_network_name()` reusing `validate_id()`
- [x] `networks_dir()` and `network_path()` helpers using `mvm_share_dir()`
- [x] Serde roundtrip tests

### 1c. VM Name Registry ✓

- [x] `VmNameRegistry` in `mvm-runtime/src/vm/name_registry.rs`
- [x] `VmRegistration` struct (vm_dir, network, guest_ip, slot_index, registered_at)
- [x] `register()`, `deregister()`, `lookup()`, `names()` operations
- [x] Atomic save via `mvm_core::atomic_io::atomic_write()`
- [x] `registry_path()` using `mvm_share_dir()`
- [x] `generate_vm_name()` for auto-generated VM names
- [x] Load/save roundtrip tests

---

## Phase 2: Image Catalog & Audit Extensions ✓

### 2a. Nix-based Image Catalog ✓

- [x] `CatalogEntry` and `Catalog` types in `mvm-core/src/catalog.rs`
- [x] `Catalog::search()` — case-insensitive search by name, description, tags
- [x] `Catalog::find()` — exact name lookup
- [x] Bundled catalog with 5 presets: minimal, http, postgres, worker, python
- [x] CLI: `mvmctl image list`, `mvmctl image search <q>`, `mvmctl image fetch <name>`, `mvmctl image info <name>`
- [x] `image fetch` designed as sugar for template create + build (not yet wired)
- [x] Serde roundtrip, search, and schema version default tests

### 2b. Audit Logging Extensions ✓

- [x] 9 new `LocalAuditKind` variants: NetworkCreate, NetworkRemove, ImageFetch, TemplateBuild, TemplatePush, TemplatePull, ConfigChange, ConsoleSessionStart, ConsoleSessionEnd
- [x] `audit::emit()` calls in network create/remove and image fetch commands
- [x] Updated test to cover all variants

---

## Phase 3: PTY-over-Vsock Console Protocol ✓

### 3a. Protocol extensions ✓

- [x] `GuestRequest::ConsoleOpen { cols, rows }` — open interactive PTY session
- [x] `GuestRequest::ConsoleClose { session_id }` — close PTY session
- [x] `GuestRequest::ConsoleResize { session_id, cols, rows }` — resize PTY window
- [x] `GuestResponse::ConsoleOpened { session_id, data_port }` — session opened, connect to data port
- [x] `GuestResponse::ConsoleExited { session_id, exit_code }` — shell exited
- [x] `GuestResponse::ConsoleResized { session_id }` — resize acknowledged
- [x] `CONSOLE_PORT_BASE = 20000` constant for data channel vsock ports
- [x] Guest agent stub handler (returns "not yet implemented" error)
- [x] Serde roundtrip tests for all new variants

### 3b. CLI command ✓

- [x] `mvmctl console <name>` — interactive PTY session (stub, prints not-yet-implemented)
- [x] `mvmctl console <name> --command <cmd>` — one-shot command execution (wired to existing Exec path)
- [x] CLI integration tests

### 3c. Guest agent PTY implementation ✓

- [x] `console.rs` module in mvm-guest — PTY allocation, shell fork, vsock data relay
- [x] `open_session(cols, rows)` — openpty + fork + exec /bin/sh
- [x] `run_console_relay(session)` — bind vsock data port, accept connection, bidirectional relay
- [x] `close_session(session)` — kill shell, wait, cleanup
- [x] `resize_pty(master_fd, cols, rows)` — TIOCSWINSZ ioctl
- [x] Single-session enforcement via atomic flag
- [x] Guest agent wired: ConsoleOpen spawns relay thread, ConsoleClose/Resize handled
- [x] Supports both Firecracker and Apple Container backends

### 3d. Host CLI interactive console ✓

- [x] `console_interactive(name)` — full interactive PTY flow
- [x] Backend detection: Apple Container (direct vsock) or Firecracker (UDS)
- [x] `enter_raw_mode()` / `restore_terminal()` — termios raw mode via libc
- [x] `get_terminal_size()` — TIOCGWINSZ ioctl
- [x] `run_console_relay()` — bidirectional stdin/stdout ↔ vsock relay
- [x] Audit events: ConsoleSessionStart / ConsoleSessionEnd
- [x] Made `connect_to()` and `send_request()` public in vsock.rs

### 3e. Console polish ✓

- [x] SIGWINCH handler on host — polls atomic flag, sends ConsoleResize via control channel
- [x] Global `CONSOLE_MASTER_FD` atomic in guest for resize ioctl dispatch
- [x] `resize_active_session(cols, rows)` in console.rs, wired into guest agent
- [x] `AccessPolicy.console` field (default false, enabled in `dev_defaults()`)
- [x] Guest agent checks `access.console` before opening PTY session
- [x] 15-minute idle timeout via `set_read_timeout()` on vsock data channel

---

## Phase 4: Init Wizard & Security DX ✓

### 4a. Init Wizard ✓

- [x] `mvmctl init` — unified first-time setup wizard
- [x] Platform detection with human-readable label
- [x] Apple Container detection (macOS 26+)
- [x] Dependency check (package manager, Lima)
- [x] Lima VM creation via `run_setup_steps()`
- [x] Auto-create default network if missing
- [x] Create XDG data directories
- [x] Show available catalog images
- [x] Print next-steps guidance
- [x] `--non-interactive` flag for scripted use
- [x] `--lima-cpus` and `--lima-mem` flags

### 4b. Security Status ✓

- [x] `mvmctl security status` — security posture evaluation
- [x] Checks: audit log, XDG dirs, default network, seccomp, vsock auth, no-SSH, Nix builds
- [x] Human-readable summary with score (passed/total)
- [x] `--json` flag for machine-readable output
- [x] Shows uncovered security layers

---

## Phase 5: Gap Closing & Polish ✓

### 5a. Image catalog wiring ✓

- [x] `image fetch` calls `template_cmd::create_single()` + `template_cmd::build()`
- [x] Full pipeline: catalog entry → template creation → Nix build

### 5b. VM name registry wiring ✓

- [x] `mvmctl up` registers VM name in `vm-names.json` via `VmNameRegistry`
- [x] `mvmctl down <name>` deregisters VM name from registry
- [x] Stale entries cleared on re-registration

### 5c. Network flag ✓

- [x] `--network <name>` flag on `Up` command (default: "default")
- [x] Network name threaded through `RunParams` → `VmNameRegistry`

### 5d. Console Apple Container support ✓

- [x] `console --command` detects backend (Apple Container vs Firecracker)
- [x] Apple Container uses `vsock_connect` + `send_request` directly
- [x] Firecracker falls back to UDS-based `exec_at`

### 5e. Config extensions ✓

- [x] `catalog_url: Option<String>` in `MvmConfig`
- [x] `mvmctl config set catalog_url <url>` support
- [x] Backward-compatible serde (defaults to None)

### 5f. Cache management ✓

- [x] `mvmctl cache info` — show cache path and disk usage
- [x] `mvmctl cache prune` — remove stale temp files
- [x] `--dry-run` flag for safe preview

### 5g. Documentation ✓

- [x] CLI reference updated: network, image, console, cache, security, init commands
- [x] `--network` flag documented on Up command
- [x] CLAUDE.md updated: new module locations, new commands, console access note

---

## CLI Command Summary (New)

```
mvmctl init                                      # First-time setup wizard
mvmctl network create <name>                      # Create named dev network
mvmctl network list                               # List all networks
mvmctl network inspect <name>                     # Show network details
mvmctl network remove <name>                      # Remove a network
mvmctl image list                                 # Browse catalog
mvmctl image search <query>                       # Search by name/tag
mvmctl image fetch <name>                         # Build image from catalog
mvmctl image info <name>                          # Show image details
mvmctl console <name>                             # Interactive PTY shell
mvmctl console <name> --command <cmd>             # One-shot exec
mvmctl cache info                                 # Cache disk usage
mvmctl cache prune [--dry-run]                    # Clean stale files
mvmctl security status [--json]                   # Security posture
mvmctl up --network <name>                        # Attach VM to named network
```

---

## Key Files

| File | Changes |
|------|---------|
| `crates/mvm-core/src/config.rs` | XDG directory functions (cache, config, state, share) |
| `crates/mvm-core/src/dev_network.rs` | New: `DevNetwork` type for named networks |
| `crates/mvm-core/src/catalog.rs` | New: `CatalogEntry` and `Catalog` types |
| `crates/mvm-core/src/audit.rs` | Extended `LocalAuditKind` with 9 new variants |
| `crates/mvm-core/src/user_config.rs` | XDG config dir with legacy fallback, `catalog_url` |
| `crates/mvm-core/src/security.rs` | `AccessPolicy.console` field |
| `crates/mvm-runtime/src/vm/name_registry.rs` | New: `VmNameRegistry` for name-based VM lookups |
| `crates/mvm-guest/src/vsock.rs` | Console protocol variants, `connect_to()` + `send_request()` public |
| `crates/mvm-guest/src/console.rs` | New: PTY allocation, shell fork, vsock data relay |
| `crates/mvm-guest/src/bin/mvm-guest-agent.rs` | Console session handler with `access.console` policy check |
| `crates/mvm-cli/src/commands.rs` | Network, Image, Console, Cache, Init, Security CLI subcommands |
| `public/src/content/docs/reference/cli-commands.md` | All new commands documented |
| `CLAUDE.md` | New module locations, command examples, console access note |

---

## Verification ✓

```bash
cargo test --workspace   # 964 tests, 0 failures
cargo clippy --workspace -- -D warnings  # 0 warnings
```
