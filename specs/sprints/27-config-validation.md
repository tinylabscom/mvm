# Sprint 27 — Config Validation & Input Sanitisation

**Goal:** Reject bad input at the CLI boundary with helpful error messages, not deep in the stack.

**Branch:** `feat/sprint-27`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 800+                     |
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

---

## Rationale

Several CLI inputs are validated late (inside command handlers or even inside the Lima VM)
producing cryptic errors.  Validating at parse time with `clap` value parsers gives the
user a clear, actionable message before any work is done.

Validators already exist in `mvm-core::naming` — they just need to be wired into Clap
value parsers so they run at argument parse time.

---

## Phase 1: Wire validators into Clap value parsers **Status: COMPLETE**

### 1.1 VM name validation

- [x] `--name` in `Run`, `Stop`, `Remove`, `Logs`, `Forward`, `vm ping/status/inspect/exec/diagnose`
  — use `value_parser = clap::value_parser!(String)` + a `fn parse_vm_name(s: &str) -> Result<String>` that calls `validate_vm_name`
- [x] Add `fn parse_vm_name` in `commands.rs` using `validate_vm_name` from `mvm_core::naming`

### 1.2 Flake ref validation

- [x] `--flake` in `Run`, `Up`, `Build`, `Template Create/CreateMulti`
  — `fn parse_flake_ref(s: &str) -> Result<String>` calling `validate_flake_ref`

### 1.3 Port spec validation

- [x] `--port / -p` in `Run`, `Forward`
  — `fn parse_port_spec(s: &str) -> Result<String>` validates format `HOST:GUEST` or `PORT`
  — valid: `"8080"`, `"8080:80"`, `"127.0.0.1:8080:80"`; invalid: `"abc"`, `"8080:abc:80"`

### 1.4 Volume spec validation

- [x] `--volume / -v` in `Run`
  — `fn parse_volume_spec_str(s: &str) -> Result<String>` validates `host:/guest` or `host:/guest:size`

---

## Phase 2: Unit tests **Status: COMPLETE**

### 2.1 Tests in `mvm-core/src/naming.rs` (extend existing)

- [x] `test_validate_vm_name_valid` — alphanumeric + hyphens accepted
- [x] `test_validate_vm_name_invalid` — rejects empty, spaces, uppercase, leading hyphens
- [x] `test_validate_flake_ref_valid` — `.`, `path:./foo`, `github:org/repo`, `http://...`
- [x] `test_validate_flake_ref_invalid` — rejects empty string

### 2.2 Tests for new parsers in `commands.rs`

- [x] `test_parse_port_spec_valid` — `"8080"`, `"8080:80"` parse OK
- [x] `test_parse_port_spec_invalid` — `"abc"`, `"8080:abc"` return Err
- [x] `test_parse_volume_spec_valid` — `"/host:/guest"`, `"/host:/guest:1G"` parse OK
- [x] `test_parse_volume_spec_invalid` — `"nocolon"` returns Err

---

## Verification

```bash
cargo test --workspace
cargo test --test e2e
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 28: Config File Hot-Reload & Watch Mode

**Goal:** Let operators change `~/.mvm/config.toml` without restarting long-running commands.

- [ ] Add `--watch-config` flag to `mvmctl dev` / `mvmctl run`
- [ ] Use the existing `notify` watcher infrastructure to detect config file changes
- [ ] On change: reload `MvmConfig` and apply updates if the VM is not yet started
- [ ] 3 unit tests: file-change detection, partial override, invalid TOML graceful error
