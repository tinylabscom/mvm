# Post-Hardening Roadmap

After Sprint 16 (Production Hardening), the codebase is at v0.4.1 with 673 tests, zero clippy warnings, and comprehensive error handling, observability, state safety, and security defaults. The single-VM dev lifecycle is feature-complete.

This document captures remaining hardening gaps and future directions, prioritized by impact.

---

## Near-Term (Sprint 17+)

### 1. Resource Safety — Drop Impls for VM Resources

**Priority: HIGH** — Prevents orphaned Firecracker processes and leaked TAP interfaces.

If a struct holding VM resources is dropped without explicit `stop()`, the underlying OS resources leak. Add `Drop` impls that perform best-effort cleanup (log-and-continue on failure).

**Targets:**
- Firecracker child process handles — kill on drop
- TAP interface ownership — teardown on drop
- Vsock listener sockets — close on drop
- Temp directories created during builds — remove on drop

**Approach:** RAII guard structs that wrap the resource handle and clean up in `Drop`. The existing `stop()` / `teardown()` functions already have the cleanup logic — `Drop` just calls them with error suppression.

### 2. MSRV Specification

**Priority: LOW** — One-liner, good practice for downstream consumers.

Add `rust-version = "1.85"` to workspace `Cargo.toml` (Edition 2024 requires 1.85+). Ensures `cargo install` gives a clear error on old toolchains.

### 3. Release v0.5.0

**Priority: MEDIUM** — Package the hardening work as a versioned release.

- Bump all workspace Cargo.toml versions to 0.5.0
- Update CHANGELOG.md with Sprint 16 highlights
- Tag and publish

---

## Medium-Term

### 4. Metrics Export

**Priority: MEDIUM** — Metrics are collected internally but not exposed.

Options:
- Prometheus `/metrics` endpoint (requires HTTP server in runtime)
- StatsD push (lightweight, no server needed)
- File-based metrics dump (simplest, `jq`-friendly)

Consider: Is this needed for single-VM dev mode, or only for fleet orchestration (mvmd)?

### 5. State Migration Framework

**Priority: MEDIUM** — `schema_version` fields are in place (Sprint 16 Phase 4.3) but no migration logic exists yet.

When a future sprint changes a persisted struct's schema:
- Read `schema_version` from file
- If < current, run migration function chain (v0→v1, v1→v2, etc.)
- Write back with updated version

Implement when the first actual schema change occurs — not before.

### 6. Native Crypto for Snapshot Encryption

**Priority: LOW** — Currently shells out to `xxd`/`cryptsetup` for key reading and LUKS operations.

Replace `xxd -p` hex decoding in `FileKeyProvider` with native Rust `hex` crate (already have `hex_decode` in keystore.rs). LUKS/dm-crypt operations must remain shell-based (kernel interfaces).

---

## Long-Term

### 7. Binary Signing & SBOM

**Priority: LOW** — Supply chain hardening for release artifacts.

- Sign release binaries with cosign or minisign
- Generate SBOM via `cargo-sbom` or `cargo-cyclonedx`
- Publish signatures alongside release artifacts

### 8. Multi-VM Orchestration Improvements

**Priority: MEDIUM** — Core types live in mvm-core, orchestration in mvmd.

Potential work in this repo:
- Batch template operations (build N templates in parallel)
- Template dependency graphs (base template → derived variants)
- Shared build cache across templates

### 9. Performance

**Priority: LOW** — Current performance is adequate for dev workflow.

- Parallel Nix builds for multi-role templates
- Incremental rootfs updates (layer-based, not full rebuild)
- Boot time profiling and optimization beyond Sprint 13 work

### 10. Dev Experience

**Priority: MEDIUM** — Quality-of-life improvements.

- `mvmctl watch` — auto-rebuild on flake changes
- Better error messages with actionable suggestions
- Shell completions (bash/zsh/fish) via clap_complete
- `mvmctl doctor` improvements — check Nix version, disk space, Lima health
