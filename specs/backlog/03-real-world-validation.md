# mvm Sprint 3: Real-World Validation

Previous sprints:
- [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete)
- [SPRINT-2-production-readiness.md](sprints/SPRINT-2-production-readiness.md) (complete)

Sprint 1 built the full multi-tenant foundation. Sprint 2 added observability, CLI polish, error handling, coordinator client, performance, and documentation. Sprint 3 closes the gap between "code that compiles" and "system you can actually run."

---

## Phase 1: Native Linux Support
**Status: COMPLETE**

Detect platform and skip Lima on real Linux with `/dev/kvm`:

- [x] Platform detection module (`src/infra/platform.rs`) — detect Linux vs macOS, check `/dev/kvm` presence
- [x] Conditional shell dispatch — on Linux, run commands directly instead of via `limactl shell`
- [x] Skip Lima setup/bootstrap on native Linux
- [x] Firecracker binary download for native Linux (direct, not via Lima)
- [x] Integration test for platform detection logic
- [x] Update `mvm bootstrap` to handle Linux-native path (apt-based FC install)

## Phase 2: End-to-End Smoke Test
**Status: DEFERRED** (requires real Lima VM — will be done as manual validation)

Actually boot a Lima VM and run the full lifecycle:

- [ ] CI job or script that runs the real workflow (not shell mocks)
- [ ] Tenant create → pool create → pool build → instance create → instance start → SSH → stop → destroy
- [ ] Sleep → wake round-trip with snapshot verification
- [ ] Agent serve + coordinator push (QUIC round-trip)
- [ ] Bridge verify produces clean report
- [ ] Fix any issues discovered during real execution
- [ ] Document any platform-specific quirks

## Phase 3: Reconcile Loop Hardening
**Status: COMPLETE**

Wire health checks and GC into the reconcile loop:

- [x] Call `detect_stale_pids()` at the start of each reconcile cycle, auto-transition dead instances to Stopped
- [x] Call `detect_orphans()` and log warnings for orphaned directories
- [x] Pool `--force` destroy — check for running instances before destroy (fix existing TODO)
- [x] Audit log rotation — cap file size at 10MB, compress to `.gz`, keep last 3
- [x] Storage GC: `mvm pool gc <path>` — calls `cleanup_old_revisions()` (keep 2)
- [x] Storage GC: `mvm node gc` — runs GC across all pools + reports freed space
- [x] `mvm node disk` — show disk usage report
- [x] Config validation on load — reject corrupt/incomplete JSON state files (pool + tenant)
- [x] Retry wrapper already exists in `src/infra/retry.rs` — used by reconcile operations

## Phase 4: Operational UX
**Status: COMPLETE**

Make the CLI production-friendly:

- [x] Shell completions — `mvm completions bash|zsh|fish|powershell|elvish` via `clap_complete`
- [x] `mvm events <tenant>` — tail audit log as formatted events (with `--json` and `-n` flags)
- [x] `mvm node disk` — show disk usage report (with `--json` flag)
- [x] `mvm node gc` — run GC across all pools, reports freed space
- [x] `mvm pool gc <path>` — clean up old build revisions for a single pool
- [x] Better error messages — actionable context via `anyhow::Context` on all config loads
- [x] Config validation — corrupt pool/tenant configs now fail with clear messages

---

## Future Sprints (Not Yet Planned)

### Guest Agent & vsock
- vsock guest agent for lifecycle signals (replace SSH-based interaction)
- Structured health probes over vsock
- Log streaming from guest to host
- Worker exec without SSH

### Scale & Multi-Node
- Coordinator server (HTTP/QUIC service managing desired state across nodes)
- Node registration (agents register with coordinator on startup)
- Fleet-wide commands (`mvm fleet status`, `mvm fleet scale`)
- Automatic placement (coordinator assigns tenants to nodes by capacity)
- Cross-node tenant migration
