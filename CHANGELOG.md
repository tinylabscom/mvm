# Changelog

All notable changes to mvm are documented in this file.

## [0.6.0] — 2026-03-14

### Added
- Enhance mvmctl doctor with Nix version validation, flake check, Lima disk, and store health
- Replace polling watch mode with native filesystem events
- Add CLI aliases (ps, rm) and richer error hints
- Add mvmctl metrics command (Prometheus + JSON output)
- Add shell injection guards in crypto code (keystore, encryption)
- Add state migration framework and wire into RunInfo load
- Sprint 20 — input validation, checksum verification, stale PID cleanup, release hardening (v0.6.0)
- Merge Sprint 20 — input validation, checksum verification, stale PID cleanup, release hardening (v0.6.0)
- Sprint 21 — binary signing, smoke test, and signature verification
- Sprint 22 — timing gauges, tracing spans, HTTP metrics endpoint
- Sprint 23 — global config file at ~/.mvm/config.toml
- Sprint 24 — man pages via xtask + clap_mangen
- Sprint 25 — mvmctl uninstall + E2E test harness
- Sprint 26 — local audit logging and mvmctl audit tail
- Sprint 27 — config validation & input sanitisation at parse time
- Sprint 28 — config file hot-reload & watch mode
- Sprint 29 — shell completion generation tests
- Sprint 30 — mvmctl config edit subcommand
- Sprint 31 — honour config defaults for cpus and memory in mvmctl run
- Sprint 32 — mvmctl vm list subcommand
- Sprint 33 — mvmctl template init --preset
- Sprint 34 — mvmctl flake check
- Sprint 35 — mvmctl run --watch (edit→rebuild→reboot loop)
- Add mkNodeService helper to guest-lib + hello-node example
- Add startupGraceSecs grace period for health checks
- Sprint 36 — Fast Boot & Minimal Images
- Sprint 37 — Image Insights, DX Polish & Guest-Lib Expansion

### Changed
- Tag v0.5.0 and archive Sprint 17
- Merge feat/sprint-27 — config validation & input sanitisation
- Merge feat/sprint-28 — config file hot-reload & watch mode
- Merge feat/sprint-29 — shell completion generation tests
- Merge feat/sprint-30 — mvmctl config edit subcommand
- Merge feat/sprint-31 — VM resource defaults from config
- Merge feat/sprint-32 — mvmctl vm list subcommand
- Merge feat/sprint-33 — template init --preset
- Merge feat/sprint-34 — mvmctl flake check
- Merge feat/sprint-35 — mvmctl run --watch

### Documentation
- Sprint 18 plan — Developer Experience & Polish
- Archive Sprint 18 and plan Sprint 19 — Observability & Security Hygiene
- Archive Sprint 20 and plan Sprint 21 — Binary Signing & Upgrade Safety
- Sync CLI reference with commands.rs, enforce docs-as-deliverable
- Mark Sprint 36 Phase 1 complete — tsx eliminated, 80 sec boot measured
- Add explicit Clippy zero-warnings rule to AGENTS.md
- Remove all mvmd references from README and site docs

### Fixed
- Replace stale 'mvm' binary name with 'mvmctl' in user-facing strings
- Paperclip example — correct tsx loader path, deployment mode, and init setup
- Resolve clippy warnings in test code for --all-targets builds
- Update quinn-proto to 0.11.14 for RUSTSEC-2026-0037

### Performance
- Eliminate tsx runtime transpilation in paperclip — 3 min → 80 sec boot
- Prune dev-only npm packages from paperclip rootfs closure
- Speed up config_watcher tests with configurable debounce

### Testing
- Fix test_e2e_cli_flow_flags_parse to use --help instead of real commands

### Plan
- Sprint 36 — Fast Boot & Minimal Images

## [0.5.0] — 2026-03-12

### Added
- **Resource safety**: RAII guards (`FirecrackerGuard`, `TapGuard`) that automatically clean up orphaned Firecracker processes and TAP interfaces on drop
- **MSRV specification**: `rust-version = "1.85"` in workspace Cargo.toml — `cargo install` now gives a clear error on old toolchains
- **Observability**: Structured tracing instrumentation across all VM lifecycle operations (start, stop, build, snapshot, restore, template)
- **State safety**: Schema versioning on all persisted structs, atomic writes via `mvm_core::atomic_io`, file locking with `fs2`
- **Security defaults**: `SecurityPolicy::require_auth` defaults to `true` (secure by default), `dev_defaults()` for permissive dev mode
- **Signal handling**: Graceful Ctrl-C cleanup via `ctrlc` crate

### Changed
- **Error handling**: Replaced 83+ `let _ =` silent error swallows with `tracing::warn!` log-and-continue pattern
- **Robustness**: Replaced 32 `.unwrap()` in production code with `.expect()` or proper error propagation
- **Test coverage**: 679 tests (up from 630), including new coverage for mvm-runtime and mvm-guest

### Fixed
- Shell mock infrastructure now intercepts `run_visible()` calls, enabling proper unit testing of Drop impls
- `.ok()` silent failures replaced with logged warnings across CLI, runtime, and guest agent

## [0.4.1] — 2026-03-07

### Fixed
- **ci**: Fix cross-compilation for aarch64-unknown-linux-gnu

## [0.4.0] — 2026-03-07

### Added
- Expose all public interfaces through root crate

## [0.3.10] — 2026-03-07

### Fixed
- Sync internal crate versions to 0.4.0
- **release**: Strip 'v' prefix from git-cliff version output

# Changelog


## [0.3.9] — 2026-03-06

### Added
- feat(agent): add protocol extensions for deployment control, batch ops, and monitoring
- fix(docs): fix double-slash in landing page navigation links

### Changed

### Fixed


## [0.3.8] — 2026-03-05

### Added
- Updated @SPRINT.md
- Updated docs css
- Added AGENTS.md
- chore: bump version to 0.3.7 and update changelog
- feat(docs): add mobile hamburger menu to landing page header
- chore(docs): update license year, fix broken links, correct env vars and binary name
- feat(core): add RegistryArtifact type and extract registry_download_revision
- feat(core): add UpdateStrategy types and new DesiredState fields for mvmd integration
- chore: archive sprints 14-15, move mvm to maintenance mode
- feat: remove legacy start command, improve paperclip/openclaw examples, update docs

### Changed

### Fixed


## [0.3.7] — 2026-03-05

### Added
- feat(docs): add mobile hamburger menu to landing page header
- chore(docs): update license year, fix broken links, correct env vars and binary name
- feat(core): add RegistryArtifact type and extract registry_download_revision
- feat(core): add UpdateStrategy types and new DesiredState fields for mvmd integration
- chore: archive sprints 14-15, move mvm to maintenance mode
- feat: remove legacy start command, improve paperclip/openclaw examples, update docs
- fix(docs): fix double-slash in header navigation links
- Added paperclip example
- chore(docs): add CNAME for gomicrovm.com and update site URL
- feat(guest): snapshot post-restore, OpenClaw loopback proxy, Nix restructure

### Changed

### Fixed


## [0.3.6] — 2026-03-03

### Added
- rename(cli): rename `upgrade` command to `update`
- fix(init): use Google DNS (8.8.8.8) instead of gateway for microVM DNS resolution
- fix(examples): fix dynamic mounts permissions and simplify OpenClaw example
- feat(openclaw): add simple native install approach
- fix(openclaw): attempt to fix esbuild bundling with external flags
- fix(bootstrap): update Lima installation to use GitHub releases

### Changed

### Fixed


## [0.3.5] — 2026-03-03

### Added
- `mvmctl template edit` command for modifying template configurations (flake, profile, role, cpus, mem, data-disk)
- Automated changelog generation via `scripts/update-changelog.sh` integrated into `just release` workflow
- Template snapshot health check timeout increased to 15 minutes for nested virtualization compatibility
- Improved install script error handling for GitHub API rate limits and tmpdir cleanup

### Changed
- **Template snapshot redesign**: Fixed Firecracker snapshot API ordering (load before config)
- Template snapshots now use template-relative paths for drives and vsock with per-instance symlinks
- Implemented flock-based serialization for concurrent instance startup from same template
- Multiple VMs can now run from the same template snapshot without path conflicts

### Fixed
- Fixed Firecracker "Loading a microVM snapshot not allowed after configuring boot-specific resources" error
- Fixed template snapshot vsock socket path issues
- Fixed release verification script to accept both hyphen and em dash date separators in CHANGELOG.md
- Bootstrap improvements: install jq and better doctor messaging

All notable changes to mvm are documented in this file.

## [0.3.2] — 2026-02-25

### Added
- `mvm sync --json` and `mvm build --json` flags for structured JSON event output (`PhaseEvent` with timestamp, command, phase, status)
- Nix build error capture — `dev_build()` now surfaces full build stderr in the error context instead of losing it to inherited stdio
- `shell_exec_capture()` method on `ShellEnvironment` trait for capturing both stdout and stderr
- `run_on_vm_capture()` / `run_in_vm_capture()` shell functions with piped output
- `mvm doctor --json`, `setup --force`, `template build --force` flags verified in integration tests
- Improved help text for all `template` subcommands (argument descriptions, flag explanations)
- README.md for each workspace crate (mvm-core, mvm-guest, mvm-build, mvm-runtime, mvm-cli)

### Changed
- Archived sprint files renamed to numbered format (`01-foundation.md`, etc.)
- `CLAUDE.md` sprint naming convention updated to `<NN>-<name>.md`

## [0.3.0] — 2026-02-17

### Added
- Template cache key validation — composite SHA256 of flake hash + profile + role prevents cross-profile artifact reuse
- Etcd state persistence for coordinator — configurable via `etcd_endpoints` in coordinator config
- Builder failure log surfacing — SSH backend captures stderr, vsock backend collects log frames
- `--log-format <human|json>` global CLI flag for structured logging
- Doctor regression tests for Lima detection and cargo path resilience
- 20 essential-path integration tests across all crates (instance lifecycle, agent reconcile, build pipeline, coordinator routing, CLI commands)
- Deployment and operations documentation (see `public/src/content/docs/`)

### Fixed
- Template reuse now compares cache keys instead of individual fields, preventing stale artifact reuse across profiles

## [0.2.0] — 2026-02-01

### Added
- **Workspace migration**: 7-crate Cargo workspace (mvm-core, mvm-runtime, mvm-build, mvm-guest, mvm-agent, mvm-coordinator, mvm-cli) replacing monolithic src/
- **Nix builder pipeline**: ephemeral Firecracker VMs with vsock and SSH backends for reproducible builds
- **Template system**: `mvm template create/build/push/pull/verify` with S3-compatible registry and SHA256 integrity
- **CI/CD**: GitHub Actions for CI, release (4-platform binaries), crate publishing, and GitHub Pages
- **Install script**: `install.sh` with dev/node/coordinator modes and platform detection
- **Deploy guard**: `scripts/deploy-guard.sh` verifies tag matches workspace version before release
- **Systemd units**: mvm-agent, mvm-agentd, mvm-hostd service files with privilege separation
- Lima template rendering with Tera (custom template path + extra context via `LimaRenderOptions`)

## [0.1.0] — 2026-01-01

### Added

#### Foundation (Sprint 1)
- Multi-tenant object model: Tenant, WorkerPool, Instance with full lifecycle API
- Instance state machine: Created → Ready → Running → Warm → Sleeping → (wake) → Running
- Per-tenant network isolation with dedicated bridges (`br-tenant-<net_id>`)
- TAP device management with deterministic naming (`tn<net_id>i<ip_offset>`)
- Tenant quotas (max vCPUs, memory, running/warm/sleeping counts, disk)
- CLI skeleton with Clap: tenant/pool/instance CRUD, dev mode, bootstrap

#### Production Readiness (Sprint 2)
- Shell mock infrastructure for integration testing without Lima/Firecracker
- Structured tracing with JSON logging layer
- Coordinator client foundation (QUIC + mTLS)
- Error handling with anyhow context chains

#### Platform Support (Sprint 3)
- Native Linux support with `/dev/kvm` detection
- Conditional shell dispatch: direct execution on Linux, Lima on macOS
- Platform detection module for architecture and OS

#### Security Hardening (Sprint 4)
- Firecracker jailer with chroot + UID/GID isolation per instance
- Cgroup v2 enforcement: memory.max, cpu.max, pids.max with read-back verification
- Seccomp BPF filter (~33 allowed syscalls in strict mode)
- tmpfs-backed ephemeral secrets disk (recreated per boot, chmod 0400)
- LUKS data volume encryption (AES-256-XTS) with per-tenant keys
- Append-only audit logging for all lifecycle events
- Ed25519 signed state for reconcile API
- AES-256-GCM snapshot encryption

#### Sleep/Wake (Sprint 5)
- Snapshot-based sleep/wake with ~200ms restore time
- Pool-level base snapshots shared across instances
- Instance-level delta snapshots on sleep
- Sleep policy with minimum runtime enforcement (wall-clock timestamps)
- Snapshot integrity verification

#### Minimum Runtime (Sprint 6)
- Vsock guest agent: CONNECT handshake + 4-byte BE length-prefixed JSON frames (port 52)
- Host-side minimum runtime enforcement preventing premature reclamation
- Drain protocol for graceful instance shutdown

#### Role-Based Profiles (Sprint 7)
- Role enum: Worker (default) and Gateway with distinct runtime policies
- NixOS module system integration for profile-based builds
- Reconcile ordering: gateways start before workers

#### Integration Lifecycle (Sprint 8)
- Gateway routing table model (MatchRule/RouteTarget)
- Integration state preservation across sleep/wake cycles
- Artifact reporting via vsock
- Per-integration secret scoping

#### OpenClaw Support (Sprint 9)
- `mvm new openclaw` template scaffolding
- Template-based deployments with standalone deploy command
- OpenClaw gateway + worker templates with external flake support

#### Coordinator (Sprint 10)
- On-demand gateway proxy with port-based routing
- Wake coalescing: concurrent requests for same tenant share one wake operation
- Idle tracking with configurable per-route timeout overrides
- Background health checking with TCP probes
- L4 bidirectional TCP proxy
- TOML configuration with validation
