# Sprint 20 — Production Hardening: Validation, Safety & Release Pipeline

**Goal:** Close the most impactful production-readiness gaps identified in the Sprint 19 gap analysis: input validation on user-facing identifiers, update checksum verification, stale-PID cleanup, and a hardened release pipeline with SBOM + smoke tests. Phases 21+ are fully planned for future sprints.

**Branch:** `feat/sprint-20`

**Roadmap:** See [specs/plans/19-post-hardening-roadmap.md](plans/19-post-hardening-roadmap.md) for full post-hardening priorities.

## Current Status (v0.5.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 700+                     |
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

---

## Rationale

**Why these four themes?**

1. **Input validation**: VM names, template names, and flake refs pass directly into shell commands and filesystem paths. There is no sanitisation today — a name like `my-vm; rm -rf /` would be passed verbatim. The `validate_shell_id` function added in Sprint 19 covers tenant IDs inside the runtime; this sprint extends the same protection to every CLI entry point that accepts a name.

2. **Update checksum verification**: `update.rs` downloads a binary and installs it without verifying the SHA256 digest against the published checksum file. A compromised CDN or MITM could deliver a tampered binary silently. Adding checksum verification is a one-function change that eliminates the risk.

3. **Stale PID cleanup**: `RunInfo` stores the Firecracker PID in a JSON file. If the process crashes without writing a tombstone, `mvmctl status` reports a "running" VM that no longer exists. A `check_stale_pid()` helper and a `mvmctl cleanup-orphans` subcommand let operators recover without manual filesystem surgery.

4. **Release pipeline hardening**: The current `release.yml` produces binaries with SHA256 checksums but no SBOM, no binary signing, and no smoke test. Adding `cargo-cyclonedx` for SBOM generation, a minimal smoke test (binary boots + `--help` exits 0), and bumping to v0.6.0 makes the release artifact trustworthy for enterprise adoption.

---

## Phase 1: Input Validation at CLI Entry Points **Status: COMPLETE**

All user-supplied identifiers that flow into shell commands or filesystem paths must be validated before use.

### 1.1 `validate_vm_name(name: &str) -> Result<()>` in `mvm-core`

- [x] Add `pub fn validate_vm_name(name: &str) -> Result<()>` to `mvm-core/src/naming.rs`
- [x] Accepts `[a-z0-9][a-z0-9-]*` up to 63 chars (RFC 1123 hostname-compatible)
- [x] Rejects empty, leading hyphen, uppercase, special chars, too-long names
- [x] 8 unit tests: valid names, empty, leading hyphen, uppercase, special chars, 64-char name

### 1.2 `validate_template_name(name: &str) -> Result<()>` in `mvm-core`

- [x] Add `pub fn validate_template_name(name: &str) -> Result<()>` to `mvm-core/src/naming.rs`
- [x] Accepts `[a-z0-9][a-z0-9-_]*` up to 63 chars
- [x] 6 unit tests: valid names, empty, leading hyphen, special chars, too-long

### 1.3 `validate_flake_ref(s: &str) -> Result<()>` in `mvm-core`

- [x] Add `pub fn validate_flake_ref(s: &str) -> Result<()>` to `mvm-core/src/naming.rs`
- [x] Rejects empty; rejects shell metacharacters (`; | & $ ( ) \` ! < > \n`)
- [x] Accepts `.` (current dir), local paths, `github:org/repo`, `git+https://...`
- [x] 8 unit tests: dot, local path, github ref, git+https, empty, semicolon injection, pipe injection, newline injection

### 1.4 Wire guards into CLI dispatch in `commands.rs`

- [x] `cmd_run()` — validate `name` (if provided) and `flake` / `template` before dispatch
- [x] `cmd_stop()` — validate `name` (if provided)
- [x] `cmd_logs()` — validate `name`
- [x] `cmd_forward()` — validate `name`
- [x] `template build/start/stop/delete` — validate template name
- [x] `Build { flake }` — validate flake ref

---

## Phase 2: Update Checksum Verification **Status: COMPLETE**

### 2.1 `verify_checksum()` in `update.rs`

- [x] After downloading the binary archive, fetch `<asset_url>.sha256` (or the release's `.sha256sums` file)
- [x] Compute SHA256 of the downloaded bytes using `sha2` crate
- [x] Compare digest; bail with actionable error on mismatch
- [x] `sha2` added to `mvm-cli/Cargo.toml`
- [x] 3 unit tests: correct digest passes, tampered bytes fail, hex format parse

---

## Phase 3: Stale PID Detection & Cleanup **Status: COMPLETE**

### 3.1 `check_stale_pid()` in `microvm.rs`

- [x] After loading `RunInfo`, check if `run_info.pid` is actually alive via `/proc/<pid>/status` (Linux) or `kill -0` (fallback)
- [x] If process is gone: log warning, return `VmState::Stopped` instead of `VmState::Running`
- [x] 2 unit tests: pid=1 (init, always alive) passes, pid=999999999 (impossible) detected as stale

### 3.2 `Commands::CleanupOrphans` in `commands.rs`

- [x] Add `CleanupOrphans { dry_run: bool }` subcommand
- [x] Scans `~/.mvm/vms/*/run_info.json` for entries where PID no longer exists
- [x] In dry-run mode: list orphaned entries; in normal mode: delete the `run_info.json` and log each removal
- [x] Integration test: `mvmctl cleanup-orphans --help` output

---

## Phase 4: Release Pipeline Hardening **Status: COMPLETE**

### 4.1 SBOM generation in `release.yml`

- [x] Add `cargo install cargo-cyclonedx` step to the release workflow
- [x] Run `cargo cyclonedx --format json --all` to produce `sbom.cdx.json`
- [x] Upload `sbom.cdx.json` as a release asset alongside the binaries
- [x] No new runtime dependencies

### 4.2 Smoke test in `release.yml`

- [x] After building the Linux x86_64 binary, run:
  ```bash
  ./mvmctl --version
  ./mvmctl --help
  ./mvmctl metrics --json
  ```
- [x] Gate the release upload on smoke-test success

### 4.3 Version bump to v0.6.0

- [x] Bump version in `Cargo.toml` (workspace) to `0.6.0`
- [x] `cargo check --workspace` passes with new version

---

## Verification

After each phase:
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo check --workspace
```

---

## Future Sprints (Planned, Not Yet Implemented)

### Sprint 21: Binary Signing & Attestation

**Goal:** Sign release binaries with `cosign` so users can verify provenance.

- [ ] Add Sigstore/cosign signing step to `release.yml` (keyless OIDC signing via GitHub Actions OIDC token)
- [ ] Publish `.sig` and `.pem` files as release assets
- [ ] Update install script to verify signature before executing binary
- [ ] Document `cosign verify` command in `docs/guides/install.md`
- [ ] 1 CI test: verify that the signature verification command succeeds on the built artifact

### Sprint 22: Observability Deep Dive

**Goal:** Make the runtime inspectable in production without adding a monitoring sidecar.

- [ ] Add `tracing::Span` instrumentation to `cmd_run`, `cmd_stop`, `build_image` critical paths
- [ ] Add timing histograms for: `build_image` duration, `vm_start` duration, `vsock_handshake` RTT
- [ ] Expose `GET /metrics` HTTP endpoint (bind to `127.0.0.1:9090` by default) using `tiny_http`
- [ ] Add `--metrics-port` flag to `mvmctl run` and `mvmctl up`
- [ ] 4 unit tests: histogram buckets, metric name format, HTTP response body is valid Prometheus text

### Sprint 23: Global Config File

**Goal:** Replace scattered flags with a persistent operator config.

- [ ] Define `MvmConfig` struct in `mvm-core/src/config.rs`:
  - `default_cpus: u32`, `default_memory_mib: u32`, `default_hypervisor: String`
  - `lima_cpus: u32`, `lima_mem_gib: u32`
  - `log_format: Option<String>`, `metrics_port: Option<u16>`
- [ ] Load from `~/.mvm/config.toml` (create with defaults if absent)
- [ ] CLI flags override config values (existing `default_value` annotations replaced by config lookup)
- [ ] Add `mvmctl config show` — print active config as TOML
- [ ] Add `mvmctl config set <key> <value>` — write single key to `~/.mvm/config.toml`
- [ ] 4 unit tests: default config, override from file, CLI flag overrides file, unknown key error

### Sprint 24: Man Pages & Shell Completions

**Goal:** Make `mvmctl` feel like a first-class Unix citizen.

- [ ] Add `clap_mangen` to `mvm-cli/Cargo.toml`
- [ ] Add `xtask` crate (or build.rs) that generates `man/mvmctl.1` and one page per subcommand
- [ ] Add `mvmctl completions <shell>` subcommand (bash, zsh, fish) via `clap_complete`
- [ ] Ship man pages and completions in the release tarball
- [ ] Update install script to copy man pages to `/usr/local/share/man/man1/`
- [ ] CI check: man page generation does not fail on clean build

### Sprint 25: E2E Test Framework & `mvmctl uninstall`

**Goal:** Catch regressions before they reach users.

- [ ] Create `tests/e2e/` directory with a test harness that:
  - Spawns a `mvmctl` subprocess for each test case
  - Captures stdout/stderr, checks exit codes
  - Runs against the actual binary (not library functions)
- [ ] Implement `mvmctl uninstall` — removes Lima VM, Firecracker binary, `/var/lib/mvm/` (with `--all` flag for aggressive cleanup)
- [ ] E2E tests for: `bootstrap --help`, `status` on clean system, `cleanup-orphans` on empty dir
- [ ] Add `e2e` CI job that runs after `build-linux` in `ci.yml`

### Sprint 26: Audit Logging

**Goal:** Provide an immutable audit trail for security-sensitive operations.

- [ ] Define `AuditEvent` struct in `mvm-core/src/audit.rs` (already partially exists — extend it)
- [ ] Emit audit events for: `vm_start`, `vm_stop`, `key_lookup`, `volume_create`, `volume_open`, `update_install`
- [ ] Append-only audit log at `/var/log/mvm/audit.jsonl` (rotate at 10 MiB)
- [ ] Add `mvmctl audit tail` — stream recent audit events
- [ ] 4 unit tests: event serialization, append-only write, rotation trigger, `audit tail` output format
