# Sprint 22 — Observability Deep Dive

**Goal:** Make the runtime inspectable without adding a monitoring sidecar. Add timing metrics for the critical paths (`build_image`, `vm_start`, `vsock_handshake`), instrument those paths with `tracing` spans, and expose an opt-in HTTP `/metrics` endpoint for long-running commands.

**Branch:** `feat/sprint-22`

**Roadmap:** See [specs/plans/19-post-hardening-roadmap.md](plans/19-post-hardening-roadmap.md) for full post-hardening priorities.

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 744                      |
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

---

## Rationale

The existing `mvmctl metrics` command already exposes Prometheus-format counters for requests and instance lifecycle events. What's missing:

1. **Timing data** — operators can't see how long builds or VM starts take. Adding `build_image_duration_ms`, `vm_start_duration_ms`, and `vsock_handshake_rtt_ms` gauges closes that gap.
2. **Tracing spans** — `tracing::info_span!` on critical paths lets structured log consumers (e.g. `RUST_LOG=mvm=trace`) correlate timing with context without code changes.
3. **HTTP scrape endpoint** — `mvmctl metrics` is point-in-time and requires shell access. An opt-in `--metrics-port` flag on long-running commands (`run`, `dev`) lets Prometheus scrape metrics without interrupting the workflow.

The HTTP server uses only `std::net::TcpListener` (no new deps) to keep the dependency footprint minimal.

---

## Phase 1: Timing Gauges in `mvm-core` **Status: COMPLETE**

### 1.1 Add timing fields to `Metrics`

- [x] Add to `crates/mvm-core/src/observability/metrics.rs`:
  ```rust
  // ── Timing gauges (last observed, milliseconds) ─────────────────
  pub build_image_duration_ms: AtomicU64,  // last build_image() duration
  pub vm_start_duration_ms: AtomicU64,     // last vm_start / run_from_snapshot() duration
  pub vsock_handshake_rtt_ms: AtomicU64,   // last vsock auth handshake RTT
  ```
- [x] Initialize all three to `0` in `Metrics::new()`
- [x] Add to `MetricsSnapshot` and `prometheus_exposition()`:
  - `mvm_build_image_duration_milliseconds` (gauge)
  - `mvm_vm_start_duration_milliseconds` (gauge)
  - `mvm_vsock_handshake_rtt_milliseconds` (gauge)
  - Use `# TYPE ... gauge` (not counter) in Prometheus output
- [x] 3 unit tests: each new field stores correctly; prometheus output contains `gauge` type lines

### 1.2 Instrument `build_image` in `mvm-build`

- [x] In `crates/mvm-build/src/dev_build.rs`, wrap the nix build with `std::time::Instant` and record to `build_image_duration_ms`
- [x] Add `tracing::info_span!("build_image", flake = %flake_ref)` around the build

### 1.3 Instrument `vm_start` in `mvm-runtime`

- [x] In `crates/mvm-runtime/src/vm/microvm.rs`, time the `start()` call and record to `vm_start_duration_ms`
- [x] Add `tracing::info_span!("vm_start")` around the start sequence

### 1.4 Instrument vsock handshake in `mvm-guest`

- [x] In `crates/mvm-guest/src/vsock.rs`, time the auth handshake and record to `vsock_handshake_rtt_ms`
- [x] Add `tracing::info_span!("vsock_handshake")` around the handshake sequence

---

## Phase 2: HTTP Metrics Endpoint **Status: COMPLETE**

### 2.1 `MetricsServer` in `mvm-cli`

- [ ] Create `crates/mvm-cli/src/metrics_server.rs`:
  ```rust
  pub struct MetricsServer { port: u16, handle: Option<std::thread::JoinHandle<()>> }

  impl MetricsServer {
      /// Bind to 127.0.0.1:<port> and serve GET /metrics in a background thread.
      pub fn start(port: u16) -> Result<Self>
      /// Stop the background thread gracefully.
      pub fn stop(self)
  }
  ```
- [ ] Implementation: `TcpListener::bind("127.0.0.1:<port>")`, accept loop in background thread
- [ ] On each connection: read first line of request (ignore rest), respond with:
  - Status `200 OK`, `Content-Type: text/plain; version=0.0.4`
  - Body: `metrics::global().prometheus_exposition()`
- [x] Set non-blocking accept so shutdown flag is checked promptly
- [x] 2 unit tests: server binds successfully; `GET /metrics` response body contains `mvm_requests_total`

### 2.2 Wire `--metrics-port` into long-running commands

- [x] Add `--metrics-port <PORT>` flag to `Commands::Run` and `Commands::Dev`:
  ```
  /// Bind a Prometheus metrics endpoint on this port (0 = disabled)
  #[arg(long, default_value = "0")]
  metrics_port: u16,
  ```
- [x] In `cmd_run` and `cmd_dev`: if `metrics_port > 0`, call `MetricsServer::start(metrics_port)?`; stop on exit
- [x] Log: `tracing::info!("Metrics available at http://127.0.0.1:{port}/metrics")`
- [x] 2 unit tests: `--metrics-port 0` parses as 0; `--metrics-port 9090` parses as 9090

---

## Phase 3: Tracing Span Instrumentation in `mvm-cli` **Status: COMPLETE**

### 3.1 Add spans to `cmd_run` and `cmd_stop`

- [x] In `crates/mvm-cli/src/commands.rs`:
  ```rust
  fn cmd_run(...) -> Result<()> {
      let _span = tracing::info_span!("cmd_run", name = ?name, cpus = ?cpus, memory_mib = ?memory).entered();
      // ...
  }
  fn cmd_stop(name: ...) -> Result<()> {
      let _span = tracing::info_span!("cmd_stop", name = ?name, all).entered();
      // ...
  }
  ```

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
