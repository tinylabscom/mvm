# Sprint 18 — Developer Experience & Polish

**Goal:** Fix stale binary name references, enhance `mvmctl doctor` with smarter checks, improve watch mode, and add quality-of-life CLI improvements.

**Roadmap:** See [specs/plans/19-post-hardening-roadmap.md](plans/19-post-hardening-roadmap.md) for full post-hardening priorities.

## Current Status (v0.5.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 688                      |
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

---

## Phase 1: Fix Stale Binary Name References **Status: COMPLETE**

The binary was renamed from `mvm` to `mvmctl` but 20+ user-facing messages still referenced `mvm`. Internal identifiers (Lima VM name `mvm`, bridge `br-mvm`, paths `/var/lib/mvm/`) stay unchanged — only CLI-facing strings were updated.

### 1.1 User-facing error/info messages

- [x] `crates/mvm-cli/src/commands.rs` — "Run with: mvm run" → "mvmctl run"
- [x] `crates/mvm-cli/src/commands.rs` — "mvm development shell" → "mvmctl"
- [x] `crates/mvm-cli/src/commands.rs` — "mvm up --flake" → "mvmctl up --flake"
- [x] `crates/mvm-cli/src/bootstrap.rs` — "mvm bootstrap" → "mvmctl bootstrap"
- [x] `crates/mvm-cli/src/ui.rs` — "mvm status" header → "mvmctl status"
- [x] `crates/mvm-runtime/src/ui.rs` — "mvm status" header → "mvmctl status"
- [x] `crates/mvm-runtime/src/vm/lima.rs` — "Run 'mvm start' or 'mvm setup'" → "mvmctl"
- [x] `crates/mvm-runtime/src/vm/lima_state.rs` — "Run 'mvm setup' or 'mvm bootstrap'" → "mvmctl"
- [x] `crates/mvm-runtime/src/vm/microvm.rs` — All "Use 'mvm stop/start/status/shell'" → "mvmctl" (8 instances)
- [x] `crates/mvm-runtime/src/vm/image.rs` — "Run 'mvm setup'" → "mvmctl setup"
- [x] `crates/mvm-runtime/src/vm/instance/lifecycle.rs` — "Run 'mvm pool build'" → "mvmctl pool build"
- [x] `crates/mvm-runtime/src/security/certs.rs` — "Run 'mvm agent certs init'" → "mvmctl"

### 1.2 Doctor messages

- [x] `crates/mvm-cli/src/doctor.rs` — "Run 'mvm dev'" → "mvmctl dev"
- [x] `crates/mvm-cli/src/doctor.rs` — "Run 'mvm setup' or 'mvm bootstrap'" → "mvmctl"
- [x] `crates/mvm-cli/src/doctor.rs` — "Run 'mvm setup'" (KVM check) → "mvmctl setup"

### 1.3 Code quality test

- [x] Added `no_stale_binary_name_in_user_facing_strings` test to `tests/code_quality.rs` — greps for patterns like `Run 'mvm `, `Use 'mvm ` in production code and fails if any are found

---

## Phase 2: Doctor Enhancements **Status: COMPLETE**

### 2.1 Nix version validation

- [x] `nix_version_check()` parses `nix --version` output (e.g., "nix (Nix) 2.18.1" → 2.18.1)
- [x] Fails if Nix version < 2.4 (minimum for `nix build` with flakes)
- [x] Warns if Nix version < 2.13 (recommended for best flake support)
- [x] `nix_flakes_check()` verifies `experimental-features` includes `nix-command` and `flakes`
- [x] 7 tests: version parsing (standard, suffix, old, garbage, empty), threshold checks

### 2.2 Lima VM health check

- [x] `lima_disk_check()` reports Lima VM disk usage, warns at 80%+, fails at 90%+
- Lima VM memory check deferred (requires parsing Lima config YAML — low value for effort)
- Lima VM command execution already covered by existing `check_vm_cmd` checks

### 2.3 Nix store health

- [x] `nix_store_check()` runs `nix store ping` to verify store accessibility
- [x] Reports store URL (e.g., "Store URL: daemon") on success
- Nix store size reporting deferred (requires `nix store info` which may not be available on all versions)

---

## Phase 3: Watch Mode Improvements **Status: COMPLETE**

Replaced the 2-second polling loop on `flake.lock` with native filesystem events via the `notify` crate, watching all `.nix` and `.lock` files recursively.

### 3.1 Watch source files

- [x] Use `notify` crate for filesystem events (replaces 2s polling)
- [x] Watch `flake.nix`, `flake.lock`, and Nix source files (`.nix` in flake directory)
- [x] Debounce rapid changes (500ms window) to avoid redundant builds
- `--watch-path` flag deferred (low priority — recursive watch already covers flake directory)

### 3.2 Watch UX

- [x] Show "watching for changes..." status message
- [x] Show which file triggered the rebuild
- Clear terminal on rebuild (`--clear` flag) deferred — low priority

---

## Phase 4: CLI Quality of Life **Status: PLANNED**

### 4.1 Better error messages with suggestions

- [ ] When `mvmctl run` fails because Lima VM is not running, suggest `mvmctl dev` or `mvmctl setup`
- [ ] When `mvmctl build` fails with Nix error, extract the relevant error lines and suggest common fixes
- [ ] When `mvmctl template build` fails, suggest `--force` if template already exists

### 4.2 Command aliases

- [ ] `mvmctl ps` as alias for `mvmctl status` (familiar to Docker users)
- [ ] `mvmctl logs <vm>` to tail Firecracker logs for a running VM
- [ ] `mvmctl rm <vm>` as alias for `mvmctl vm stop --cleanup`

---

## Verification

After each phase:
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```
