# Sprint 26 — Audit Logging

**Goal:** Provide an immutable audit trail for security-sensitive local mvmctl operations.

**Branch:** `feat/sprint-26`

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade + xtask  |
| Total tests      | 780+                     |
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

---

## Rationale

`mvmctl` performs privileged local operations (boot VMs, install binaries, manage
volumes) but currently leaves no record of what was done or when. An append-only
audit log at `/var/log/mvm/audit.jsonl` gives operators an immutable trail for
debugging and compliance.  The existing `mvm-core/src/audit.rs` covers fleet events
(tenant/pool/instance lifecycle for mvmd); this sprint adds a simpler
`LocalAuditEvent` model for single-host mvmctl operations.

---

## Phase 1: Extend `audit.rs` with local event model and log writer **Status: COMPLETE**

### 1.1 Add `LocalAuditEvent` to `mvm-core/src/audit.rs`

- [x] `LocalAuditKind` enum: `VmStart`, `VmStop`, `KeyLookup`, `VolumeCreate`,
  `VolumeOpen`, `UpdateInstall`, `Uninstall`
- [x] `LocalAuditEvent` struct: `timestamp: String`, `kind: LocalAuditKind`,
  `vm_name: Option<String>`, `detail: Option<String>`
- [x] `impl LocalAuditEvent { pub fn now(kind, vm_name, detail) -> Self }`

### 1.2 Add `LocalAuditLog` writer in `mvm-core/src/audit.rs`

- [x] `pub struct LocalAuditLog { path: PathBuf }`
- [x] `pub fn open(path: &Path) -> Result<Self>` — creates parent dirs
- [x] `pub fn append(&self, event: &LocalAuditEvent) -> Result<()>` — appends
  one JSONL line; rotates to `audit.jsonl.1` when file exceeds 10 MiB
- [x] Default log path constant: `pub const DEFAULT_AUDIT_LOG: &str = "/var/log/mvm/audit.jsonl"`

### 1.3 Unit tests in `audit.rs`

- [x] `test_local_audit_event_serializes` — roundtrip JSON check
- [x] `test_local_audit_log_append` — writes to tempdir, reads back line
- [x] `test_local_audit_log_rotation` — exceeds 10 MiB, verifies rotation file created
- [x] `test_local_audit_kind_all_variants_serialize` — all kinds produce valid JSON

---

## Phase 2: `mvmctl audit tail` command **Status: COMPLETE**

### 2.1 Add `Audit` subcommand to `Commands` enum

- [x] `Commands::Audit { action: AuditCmd }`
- [x] `AuditCmd::Tail { lines: usize, follow: bool }` — default 20 lines

### 2.2 Implement `cmd_audit_tail`

- [x] Read last N lines from `/var/log/mvm/audit.jsonl`
- [x] Pretty-print: `<timestamp>  <kind>  [<vm_name>]  <detail>`
- [x] `--follow` / `-f`: poll for new lines every 500 ms (Ctrl-C to stop)
- [x] Graceful message when log file does not exist

---

## Phase 3: Emit audit events **Status: COMPLETE**

### 3.1 Emit from key commands (best-effort — log-and-continue on error)

- [x] `cmd_run` / `cmd_up` — emit `VmStart` after VM boot
- [x] `cmd_stop` / `cmd_down` — emit `VmStop`
- [x] `cmd_update` — emit `UpdateInstall`
- [x] `cmd_uninstall` — emit `Uninstall`

---

## Verification

```bash
cargo test --workspace
cargo test --test e2e
cargo clippy --workspace -- -D warnings
cargo check --workspace
mvmctl audit tail          # shows recent events (or "no audit log" message)
mvmctl audit tail --follow  # streams events
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 27: Config Validation & Input Sanitisation

**Goal:** Reject bad input at the boundary, not deep in the stack.

- [ ] Validate all user-supplied VM names against `validate_vm_name()` at CLI parse time
- [ ] Validate flake refs against `validate_flake_ref()` at CLI parse time
- [ ] Validate port specs (HOST:GUEST or PORT) with helpful error messages
- [ ] Validate volume specs (host_dir:/guest/path) with helpful error messages
- [ ] Add 6 unit tests covering valid/invalid paths for each validator
