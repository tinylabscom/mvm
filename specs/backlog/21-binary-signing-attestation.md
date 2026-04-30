# Sprint 21 — Binary Signing, Attestation & Upgrade Safety

**Goal:** Make release artifacts cryptographically verifiable using Sigstore/cosign keyless signing, and add upgrade safety guardrails: a pre-install signature check in the `update` command and a rollback mechanism if the new binary fails a basic smoke test.

**Branch:** `feat/sprint-21`

**Roadmap:** See [specs/plans/19-post-hardening-roadmap.md](plans/19-post-hardening-roadmap.md) for full post-hardening priorities.

## Current Status (v0.6.0)

| Metric           | Value                    |
| ---------------- | ------------------------ |
| Workspace crates | 6 + root facade          |
| Total tests      | 739                      |
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

---

## Rationale

**Why binary signing and upgrade safety?**

Sprint 20 added SHA256 checksum verification to the `update` command, which protects against accidental corruption. But a compromised GitHub Releases page could serve a binary *with a matching checksum* if the attacker controls the release. Sigstore cosign keyless signing ties the binary's provenance to the GitHub Actions OIDC token used at release time — verification requires the artifact to have been signed by *this specific workflow* on *this specific commit*. That closes the remaining supply-chain gap.

The upgrade safety guardrail (smoke test + rollback) prevents a defective release from bricking an installation. Currently, if the new binary fails to start (e.g., a broken dependency), the old binary has already been replaced. Adding a pre-swap smoke test keeps the existing binary alive until the new one proves it can run.

---

## Phase 1: Cosign Signing in `release.yml` **Status: COMPLETE**

### 1.1 Sign each release binary

- [x] Add `cosign` install step to the `release` job in `release.yml`
- [x] After all binaries are built and staged, run for each tarball:
  ```bash
  cosign sign-blob \
    --bundle "${ARCHIVE_NAME}.tar.gz.bundle" \
    "${ARCHIVE_NAME}.tar.gz"
  ```
  Uses keyless signing with GitHub Actions OIDC — no secret key needed.
- [x] Upload `.bundle` files as release assets alongside tarballs
- [x] 1 CI check: `cosign` exits 0 on the signing step

### 1.2 Sign the SBOM

- [x] After generating `sbom.cdx.json`, sign it:
  ```bash
  cosign sign-blob --bundle sbom.cdx.json.bundle sbom.cdx.json
  ```
- [x] Upload `sbom.cdx.json.bundle` as a release asset

### 1.3 Document verification for users

- [x] Add `docs/guides/verify-release.md` explaining:
  - Install cosign: `brew install cosign` / `apt install cosign`
  - Verify a release binary:
    ```bash
    cosign verify-blob \
      --bundle mvmctl-aarch64-apple-darwin.tar.gz.bundle \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp 'https://github.com/auser/mvm/.github/workflows/release.yml.*' \
      mvmctl-aarch64-apple-darwin.tar.gz
    ```
  - Verification proves: built by GitHub Actions, from the official repo, at a specific tag

---

## Phase 2: Pre-swap Smoke Test in `update.rs` **Status: COMPLETE**

Currently `update.rs` extracts the archive and replaces the binary. If the new binary is broken (segfaults, missing libs, etc.), the installation is left in a broken state.

### 2.1 `smoke_test_binary(path: &Path) -> Result<()>`

- [x] Add `fn smoke_test_binary(new_bin: &Path) -> Result<()>` to `update.rs`
- [x] Runs `new_bin --version` — if exit code != 0 or output doesn't contain the version, bail with a clear error
- [x] Called *before* replacing the current binary (after extracting from archive)
- [x] 2 unit tests: current binary passes smoke test, a non-executable path fails

### 2.2 Rollback on post-swap failure

- [x] After copying the new binary, verify it again with `smoke_test_binary` on the installed path
- [x] If post-swap smoke test fails: restore the backup automatically
- [x] Emit a clear error: `"New binary failed smoke test; restored previous version."`
- [x] 1 unit test: smoke test error message matches expected string

---

## Phase 3: Optional Signature Verification in `update.rs` **Status: COMPLETE**

### 3.1 `verify_signature(archive_path, version, archive_name) -> Result<()>`

- [x] Check if `cosign` is installed (via `which::which("cosign")`)
- [x] If available: download `<archive_name>.bundle` from the GitHub release and run `cosign verify-blob`
- [x] If `cosign` not installed: emit a `tracing::warn!` but continue (non-fatal — checksum still verified)
- [x] Add `--skip-verify` flag to `mvmctl update` to bypass signature check
- [x] 2 unit tests: when cosign is not found, verify returns Ok with warning; skip-verify flag respected

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
