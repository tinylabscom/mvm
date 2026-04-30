# mvm Sprint Tracker

Tracks implementation progress against [specs/plans/0-comprehensive-implementation.md](specs/plans/0-comprehensive-implementation.md).

---

## Phase 1: Lib/bin split + data models + CLI skeleton
**Status: COMPLETE**

- [x] Lib/bin crate structure (`src/lib.rs` + `Cargo.toml` `[lib]`/`[[bin]]`)
- [x] `src/main.rs` imports from library crate (no `mod` declarations)
- [x] All import paths fixed (`crate::infra::`, `super::`, etc.)
- [x] Data models: `TenantConfig`, `PoolSpec`, `InstanceState` with serde
- [x] State machine: `validate_transition()` in `instance/state.rs` with full test coverage
- [x] Naming: `validate_id`, `generate_instance_id`, `tap_name`, `parse_pool_path`, `parse_instance_path`
- [x] Bridge: `ensure_tenant_bridge`, `destroy_tenant_bridge`, `verify_tenant_bridge`
- [x] CLI: all subcommands wired (tenant, pool, instance, agent, net, node + dev mode)
- [x] Stub modules: `security/`, `sleep/`, `worker/`, `agent.rs`, `node.rs`
- [x] Platform-aware bootstrap (Homebrew on macOS, apt/dnf/pacman on Linux)
- [x] 49 tests passing, 0 warnings

## Phase 2: Nix flake + guest modules + builder module
**Status: COMPLETE**

- [x] `nix/flake.nix` — inputs (nixpkgs 24.11, microvm.nix), outputs per profile
- [x] `nix/guests/baseline.nix` — base NixOS: openssh, static IP, fstab, worker hooks
- [x] `nix/guests/profiles/minimal.nix` — baseline only
- [x] `nix/guests/profiles/python.nix` — + python3, pip
- [x] `nix/builders/nix-builder.nix` — Nix + git, outbound net, SSH, large tmpfs
- [x] User-flake convention documented (`nix build <flake_ref>#tenant-<profile>`)
- [x] `nixosModules` exposed for user flakes to import mvm baseline
- [x] Pool config + build docs updated for arbitrary flake refs

## Phase 3: `pool/build.rs` — ephemeral FC build VMs
**Status: COMPLETE**

- [x] Load pool spec + tenant config, validate exists
- [x] `ensure_builder_artifacts()` — download kernel + rootfs on first use
- [x] `boot_builder()` — ephemeral FC VM on tenant bridge (IP offset .2)
- [x] `run_nix_build()` — SSH into builder, `nix build <flake_ref>#tenant-<profile>`
- [x] `extract_artifacts()` — SCP kernel + rootfs to `revisions/<hash>/`
- [x] `record_revision()` + `record_build_history()` — update symlink, append history
- [x] `teardown_builder()` — kill FC, remove TAP, clean up run dir
- [x] Builder net: deterministic IP/MAC/TAP from tenant subnet (offset 2)
- [x] 3 new unit tests (builder_instance_net, subnet variants, constants)

### Host-side crate improvements
- [x] Added `chrono` — replaced shell `date -u` with `http::utc_now()` (tenant + build)
- [x] Added `reqwest` (blocking + json) — replaced `curl` in `upgrade.rs`
- [x] New `infra/http.rs` — `fetch_text()`, `fetch_json()`, `download_file()`, `utc_now()`
- [x] 53 tests passing, 0 warnings

## Phase 4: `bridge.rs` + `instance/net.rs` — per-tenant networking
**Status: COMPLETE**

- [x] `bridge.rs` — idempotent bridge creation with iptables NAT rules
- [x] `bridge.rs` — `BridgeReport` struct with 7-check health verification
- [x] `bridge.rs` — `full_bridge_report()` for structured JSON diagnostics
- [x] `instance/net.rs` — TAP setup/teardown (`setup_tap`, `teardown_tap`)
- [x] `instance/net.rs` — `allocate_ip_offset()` scans tenant-wide instance.json files
- [x] `instance/net.rs` — `build_instance_net()` constructs InstanceNet from subnet + offset
- [x] `mvm net verify` — uses `full_bridge_report` for rich per-tenant JSON output
- [x] 56 tests passing (46 lib + 10 integration), 0 warnings

## Phase 5: `instance/lifecycle.rs` + core lifecycle
**Status: COMPLETE**

- [x] `instance_create` — allocate ID, IP, write InstanceState (Created)
- [x] `instance_start` — validate transition, quota check, bridge, TAP, cgroup, disks, FC config, launch, record PID
- [x] `instance_stop` — kill FC, cleanup cgroup + TAP, update state (Stopped)
- [x] `instance_warm` — pause vCPUs via FC API socket (Running -> Warm)
- [x] `instance_ssh` — process replacement via limactl shell + SSH with tenant key
- [x] `instance_destroy` — stop if running, teardown TAP, remove cgroup, remove dirs
- [x] `instance_list` — scan pool instances dir, load all InstanceState
- [x] `instance_logs` — read Firecracker log from runtime dir
- [x] `fc_config.rs` — generate FC JSON with network boot args (`ip=` kernel param), data + secrets drives, CIDR-to-mask conversion
- [x] `disk.rs` — `ensure_data_disk()` (persistent), `create_secrets_disk()` (recreated per run)
- [x] `tenant/quota.rs` — `compute_tenant_usage()` scans all instance.json, `check_quota()` enforces limits
- [x] CLI: `mvm instance create`, `list`, `start`, `stop`, `warm`, `ssh`, `destroy`, `stats`, `logs` all wired
- [x] 65 tests passing (55 lib + 10 integration), 0 warnings

## Phase 6: `instance/snapshot.rs` — sleep/wake/warm
**Status: COMPLETE**

- [x] `snapshot.rs` — `SnapshotMeta` model with serde serialization
- [x] Base snapshots: `has_base_snapshot()`, `create_base_snapshot()` via FC API (`PUT /snapshot/create`, type Full)
- [x] Delta snapshots: `has_delta_snapshot()`, `create_delta_snapshot()` via FC API (type Diff)
- [x] `remove_delta_snapshot()` — cleanup on stop/destroy
- [x] `restore_snapshot()` — copy files, decompress, load via FC API (`PUT /snapshot/load`), resume vCPUs
- [x] Compression helpers: `compress_snapshot_files()` / `decompress_snapshot_files()` (lz4/zstd via VM shell)
- [x] `invalidate_base_snapshot()` — called when pool artifacts rebuilt
- [x] `base_snapshot_info()` / `delta_snapshot_info()` — metadata queries
- [x] `instance_sleep` — signal guest prep (SSH), create delta snapshot, kill FC, keep TAP, Sleeping state
- [x] `instance_wake` — quota check, ensure bridge+TAP, fresh secrets disk, launch FC (snapshot mode), restore base+delta, resume vCPUs
- [x] 69 tests passing (59 lib + 10 integration), 0 warnings

## Phase 7: `security/` modules — hardened runtime
**Status: COMPLETE**

- [x] `jailer.rs` — `compute_uid()`, `jailer_available()`, `launch_jailed()` (chroot + uid/gid), `launch_direct()` (fallback), `ip_offset_from_guest_ip()`, `cleanup_jail()`
- [x] `cgroups.rs` — `create_instance_cgroup()` with memory.max, cpu.max, pids.max; `remove_instance_cgroup()` with process migration; `tenant_cgroup_usage()` aggregate; `instance_cgroup_path()` helper
- [x] `seccomp.rs` — `seccomp_filter_path()` (baseline/strict), `ensure_strict_profile()` writes BPF JSON, full Vmm/Api/Vcpu allowlists based on official FC recommendations
- [x] `audit.rs` — `log_event()` appends JSON lines to per-tenant audit.log, `read_audit_log()` reads last N entries, `AuditEntry` with Serialize+Deserialize, added `SnapshotCreated`/`SnapshotRestored` actions
- [x] `metadata.rs` — `setup_metadata_endpoint()` with nftables rules (per-tenant table, input filter + DNAT to port 8169), `teardown_metadata_endpoint()`, `metadata_endpoint_active()` check
- [x] `lifecycle.rs` — replaced inline FC launch with `jailer::launch_jailed()` / `jailer::launch_direct()`, added seccomp support, metadata endpoint setup on start
- [x] 82 tests passing (72 lib + 10 integration), 0 warnings

## Phase 8: `sleep/` + `worker/` — intelligent sleep policies
**Status: COMPLETE**

- [x] `sleep/policy.rs` — `SleepPolicy` configurable thresholds, `evaluate_pool()` respects pinned/critical, `evaluate_instance()` checks idle/CPU/net vs thresholds, `pressure_candidates()` for memory-pressure-driven sleep, `PolicyDecision` with reasons, coldest-first sorting
- [x] `sleep/metrics.rs` — `collect_metrics()` from FC API + cgroup stats, `update_metrics()` with idle accumulation, `read_cpu_usage()` from metrics FIFO, `read_net_bytes()` from FC /metrics, `estimate_idle_secs()` heuristic
- [x] `worker/hooks.rs` — `signal_sleep_prep()` via SSH to guest systemd, `is_worker_ready()` checks signal file, `worker_status()` (ready/idle/busy/unknown), `signal_wake()` for post-restore init
- [x] 98 tests passing (88 lib + 10 integration), 0 warnings

## Phase 9: `agent.rs` + `node.rs` — reconcile + node info
**Status: COMPLETE**

- [x] `agent.rs` — `DesiredState` schema with `DesiredTenant`, `DesiredPool`, `DesiredTenantNetwork`
- [x] `agent.rs` — `reconcile()` loads desired state JSON, runs convergence, prints summary
- [x] `agent.rs` — `reconcile_desired()` 6-phase convergence: ensure tenants, ensure pools, scale instances, prune unknown pools, prune unknown tenants, run sleep policy
- [x] `agent.rs` — `reconcile_pool_instances()` scale up (start stopped then create new) / scale down (stop excess)
- [x] `agent.rs` — `validate_desired_state()` schema version, empty IDs, zero vCPUs validation
- [x] `node.rs` — `collect_info()` hostname, arch, node_id (persistent), Lima/FC status, vcpus, memory, jailer, cgroup v2
- [x] `node.rs` — `collect_stats()` aggregate instance counts by status across all tenants/pools
- [x] `node.rs` — `info(json)` / `stats(json)` display functions (human-readable + JSON)
- [x] 106 tests passing (96 lib + 10 integration), 0 warnings

## Phase 10: Agent daemon — tokio + QUIC + mTLS
**Status: COMPLETE**

- [x] Tokio async runtime for `mvm agent serve` — `tokio::runtime::Builder::new_multi_thread()`
- [x] QUIC transport — `quinn` 0.11 + `rustls` 0.23, length-prefixed JSON frame protocol over bi-directional streams
- [x] Strongly typed message protocol — `AgentRequest`/`AgentResponse` serde enums (Reconcile, NodeInfo, NodeStats, TenantList, InstanceList, WakeInstance)
- [x] mTLS certificate management — `security/certs.rs`: `generate_self_signed()` (rcgen CA + node cert), `init_ca()`, `rotate_certs()`, `load_server_config()`/`load_client_config()` (quinn crypto), `cert_status()`/`show_status()`
- [x] CLI: `mvm agent certs init [--ca]`, `mvm agent certs rotate`, `mvm agent certs status [--json]`
- [x] QUIC server — `run_daemon()` accepts connections, dispatches typed requests to `handle_request()` on blocking threads
- [x] Periodic reconcile — `tokio::spawn` interval task, reads desired state file, runs `reconcile()` via `spawn_blocking`
- [x] Graceful shutdown — `tokio::signal::ctrl_c()`, `endpoint.close()`, abort reconcile task
- [x] 110 tests passing (100 lib + 10 integration), 0 warnings

## Final: Integration pass
**Status: COMPLETE**

- [x] End-to-end verification of all CLI commands (tenant, pool, instance, agent, agent certs, net, node + dev mode)
- [x] README rewrite — accurate command tables, state machine diagram, architecture tree, agent serve usage
- [x] `cargo build && cargo test` clean — 110 lib + 10 integration = 120 tests, 0 warnings
