# Sprint 16 — Production Hardening

**Goal:** Close critical production readiness gaps in error handling and test coverage, and document remaining hardening work.

**Error policy:** Cleanup failures use **log-and-continue** — `tracing::warn!` the error but don't propagate. Prevents cascade failures during teardown.

## Current Status (v0.4.1)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 630                      |
| Clippy warnings  | 0                        |
| Edition          | 2024 (Rust 1.85+)        |
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

---

## Gap Analysis Summary

### Critical
1. 83+ `let _ =` error swallows (silent failures in VM cleanup, LUKS, cgroups)
2. 32 `.unwrap()` in production code (crash risk, violates AGENTS.md)
3. mvm-runtime — zero organized tests (most complex crate)
4. mvm-guest — zero tests (37 unsafe blocks untested)
5. No signal handling (Ctrl-C doesn't cleanup)

### High
6. 33+ `.ok()` silent failures
7. No concurrent access protection (file-based state, no locking)
8. SecurityPolicy defaults to unauthenticated
9. 135 `println!/eprintln!` bypassing tracing
10. No config/input validation

### Medium
11. Metrics collected but not exported
12. No state versioning/migration
13. Missing Drop impls for VM resources
14. Snapshot encryption reads via shell
15. No binary signing or SBOM
16. No MSRV specified

---

## Phase 1: Error Handling & Robustness **Status: COMPLETE**

### 1.1 Replace `.unwrap()` with `.expect()` in production code (~32 instances)

- [x] `crates/mvm-cli/src/update.rs` — 11 unwraps replaced with `.expect()`
- [x] `crates/mvm-runtime/src/shell_mock.rs` — 6 unwraps replaced with `.expect()`
- [x] `crates/mvm-runtime/src/config.rs` — 4 unwraps replaced with `.expect()`
- [x] `crates/mvm-runtime/src/vm/image.rs` — 2 unwraps replaced with `.expect()`
- [x] `crates/mvm-core/src/retry.rs` — 1 unwrap replaced with `.expect()`
- [x] `crates/mvm-core/src/config.rs` — 1 unwrap replaced with `.expect()`

### 1.2 Replace `let _ =` error swallowing with log-and-continue (~83 instances)

Pattern: `let _ = op();` → `if let Err(e) = op() { tracing::warn!("description: {e}"); }`

- [x] `crates/mvm-runtime/src/vm/instance/lifecycle.rs` — 14 instances replaced with warn logging
- [x] `crates/mvm-runtime/src/vm/template/lifecycle.rs` — 9 instances replaced with warn logging
- [x] `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — 7 instances replaced with eprintln logging
- [x] `crates/mvm-guest/src/bin/mvm-builder-agent.rs` — 8 instances replaced with eprintln logging
- [x] `crates/mvm-runtime/src/vm/microvm.rs` — 7 instances replaced with warn logging
- [x] `crates/mvm-cli/src/update.rs` — 7 instances replaced with warn logging

Note: Some `let _ =` may be intentionally ignored (e.g., removing a file that may not exist). Add `// intentionally ignored: <reason>` comment for those cases.

### 1.3 Replace `.ok()` silent failures with logging (~33 instances)

Pattern: `.parse().ok()` → `.parse().map_err(|e| tracing::warn!("parse failed: {e}")).ok()`

- [x] `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — 4 logged (CLI args + config parse), 6 skipped (idiomatic optional chains)
- [x] `crates/mvm-runtime/src/vm/microvm.rs` — 3 logged (PID + config parse), 6 skipped (idiomatic `.ok()?` chains)
- [x] `crates/mvm-cli/src/commands.rs` — 0 changed, all 8 reviewed as idiomatic best-effort patterns
- [x] `crates/mvm-runtime/src/security/certs.rs` — 3 logged (cert queries), 4 skipped (`filter_map` patterns)

### 1.4 Add signal handling for graceful shutdown

- [x] Add `ctrlc` crate dependency
- [x] Install SIGINT/SIGTERM handler in CLI entry point
- [x] Log "interrupted, cleaning up..." and exit cleanly
- [x] Cleanup spawned port-forwarding processes (socat PIDs tracked in global registry, killed by signal handler)

---

## Phase 2: Test Coverage **Status: COMPLETE**

### 2.1 mvm-runtime unit tests

- [x] `config.rs` — 25+ tests: config loading, defaults, serde roundtrip, Lima template rendering, VmSlot
- [x] `shell.rs` — 6 tests: run_host success/failure/nonexistent, run_host_visible, inside_lima
- [x] `vm/network.rs` — functions are shell scripts (not unit-testable); VmSlot tested in config.rs
- [x] `vm/image.rs` — 12+ tests: config parsing, service generation, host_init generation, runtime config
- [x] `vm/template/` — 11 tests: integration health checks (8), Checksums serde roundtrip (3)

### 2.2 mvm-guest unit tests

- [x] `vsock.rs` — 30+ tests: all enum variants serde, authenticated frames, handshake, replay detection, error paths
- [x] `integrations.rs` — 12 tests: manifest serde, status enums, health results, backward compat, drop-in loading

### 2.3 Verification tests

- [x] Grep-based CI check: `tests/code_quality.rs` — no `.unwrap()` in production code
- [x] Mock-based test: `test_log_and_continue_pattern_does_not_propagate_errors` in microvm.rs — verifies cleanup errors don't propagate

---

## Phase 3: Observability & Logging Hygiene **Status: COMPLETE**

### 3.1 Replace diagnostic `eprintln!` with tracing (3 instances)

Audit found 110 total `println!/eprintln!` — 94 are correct user-facing CLI output, 24 are
guest agent binaries (appropriate as-is). Only 3 diagnostic instances need replacing:

- [x] `crates/mvm-build/src/vsock_builder.rs` — 3 instances (builder log, readiness, waiting) → `tracing::debug!`/`tracing::info!`

**Keep as-is:**
- CLI output via `ui::` module (94 instances) — correct user-facing output
- Guest agent binaries (`mvm-guest-agent`, `mvm-builder-agent`) — headless services, `eprintln!` appropriate
- `crates/mvm-guest/src/integrations.rs` — 4 instances (drop-in config loading, runs inside microVM, no tracing dep)
- `crates/mvm-guest/src/probes.rs` — 4 instances (drop-in config loading, runs inside microVM, no tracing dep)

### 3.2 Add tracing spans to critical paths (~40 functions)

Pattern: `#[instrument(skip_all, fields(key_field = value, ...))]`
Reference: `crates/mvm-runtime/src/vm/instance/lifecycle.rs` (6 functions already instrumented)

**Tier 1 — Shell execution (10 functions):**
- [x] `shell.rs` — `run_in_vm`, `run_in_vm_stdout`, `run_in_vm_visible`, `run_in_vm_capture`, `run_on_vm`, `run_on_vm_visible`, `run_on_vm_stdout`, `run_on_vm_capture`, `run_host`, `run_host_visible`

**Tier 2 — VM lifecycle (15 functions in microvm.rs):**
- [x] Boot: `run_from_build`, `restore_from_template_snapshot`, `start_firecracker_daemon`, `start_vm_firecracker`
- [x] Configure: `configure_microvm`, `configure_flake_microvm`, `configure_flake_microvm_with_drives_dir`, `api_put_socket`, `api_patch_socket`
- [x] Stop: `stop`, `stop_vm`, `stop_all_vms`
- [x] Health: `diagnose_vm`, `read_vm_run_info`, `write_vm_run_info`, `list_vms`

**Tier 3 — Template operations (16 functions in template/lifecycle.rs):**
- [x] CRUD: `template_create`, `template_load`, `template_list`, `template_delete`, `template_init`
- [x] Build: `template_build`, `template_build_with_snapshot`, `update_fod_hash`
- [x] Registry: `template_push`, `template_pull`, `template_verify`, `registry_download_revision`
- [x] Health: `wait_for_healthy`, `wait_for_integrations_healthy`
- [x] Utilities: `template_artifacts`, `current_revision_id`

**Tier 4 — Build pipeline (3 functions in dev_build.rs):**
- [x] `dev_build`, `cleanup_old_dev_builds`, `ensure_guest_agent_if_needed`

---

## Phase 4: State Safety **Status: PLANNED**

### 4.1 Atomic state writes

- [ ] Write to temp file, then `rename()` for atomicity
- [ ] Applies to: `instance.json`, `template.json`, `run-info`

### 4.2 File-based locking

- [ ] Use `flock()` or `fs2::FileExt` for exclusive access during state mutations
- [ ] Document concurrent access limitations

### 4.3 State version fields

- [ ] Add `schema_version: u32` to persisted structs
- [ ] Add migration path for future schema changes

---

## Phase 5: Security Hardening **Status: PLANNED**

### 5.1 Invert SecurityPolicy default

- [ ] `require_auth: true` by default in `mvm-core/src/security.rs`
- [ ] Explicit opt-out for dev/testing mode

### 5.2 File permission enforcement

- [ ] Ensure key files at `/var/lib/mvm/keys/*.key` are chmod 0600
- [ ] Validate permissions on load, warn if too permissive

### 5.3 Config validation

- [ ] Add bounds checking for CPU, memory, rate limits
- [ ] Validate flake refs against safe pattern
- [ ] Reject unknown config keys (`#[serde(deny_unknown_fields)]` where missing)

---

## Verification

After each phase:
```bash
limactl shell mvm -- cargo test --workspace
limactl shell mvm -- cargo clippy --workspace -- -D warnings
limactl shell mvm -- cargo check --workspace
```
