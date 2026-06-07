You are a senior virtualization performance engineer and Rust systems architect.

You are working in the existing repository:
https://github.com/tinylabscom/mvm

Assume the repo already supports:
- multi-tenant Firecracker microVMs
- Nix-built guest artifacts
- jailer, cgroups, seccomp, audit logging
- reconcile-based node agent
- snapshot-based sleep / wake

Your task is to OPTIMIZE sleep / wake behavior for large fleets of bursty agent-workload-style microVM workers,
minimizing idle cost, snapshot size, and wake latency.

This is an implementation task. Do not explain. Make concrete code changes, add files, and refactor aggressively.

----------------------------------------------------------------
CORE OBJECTIVES
----------------------------------------------------------------

1) Sleeping microVMs must consume ~zero CPU and minimal disk
2) Wake latency must be minimized and predictable
3) Snapshots must be as small and reusable as possible
4) The system must make intelligent sleep/keep-warm decisions

----------------------------------------------------------------
SLEEP / WAKE OPTIMIZATION (DO ALL)
----------------------------------------------------------------

1) Snapshot layout optimization
- Change snapshot storage layout to:

/var/lib/mvm/tenants/<tenantId>/snapshots/
  base/
    vmstate.bin
    mem.bin
  deltas/
    <timestamp>/
      mem.delta.bin
      vmstate.delta.bin
  latest -> deltas/<timestamp>

- Base snapshot is taken immediately after:
  - boot
  - guest initialization
  - agent-workload worker idle-ready state

- Delta snapshots capture only memory dirtied since base

2) Snapshot reuse
- Multiple revisions of the SAME tenant (same kernel + rootfs hash)
  MUST reuse the same base snapshot
- Track base snapshot hash in TenantState

3) Memory minimization before sleep
Inside the guest (implement guest-side support via Nix module):

- Add a sleep-prep hook:
  - drop page cache
  - compact memory
  - stop background services
  - park worker threads
- Triggered by host via:
  - vsock command
  - or signal-based RPC

Host must wait for ACK before snapshotting.

4) Memory ballooning (if supported)
- Enable Firecracker memory balloon device if available
- Inflate balloon aggressively before snapshot
- Deflate on wake

5) Snapshot compression (optional but preferred)
- Support lz4 or zstd compression of snapshot memory files
- Compression must be configurable per tenant:
  snapshot_compression = none | lz4 | zstd
- Store compression metadata in snapshot manifest

----------------------------------------------------------------
WAKE LATENCY OPTIMIZATION
----------------------------------------------------------------

6) Fast restore path
- Implement a "warm wake" mode:
  - restore VM state
  - defer non-critical device initialization
  - resume vCPUs immediately
- Ensure networking is reattached before guest resumes execution

7) Pre-warming strategy
- Add command:
  mvm tenant warm <tenantId>
- Warm state:
  - VM restored
  - worker paused
  - ready to accept work
- Warm VMs consume memory but no CPU

8) Parallel wake
- Reconcile agent must be able to wake N microVMs concurrently
- Implement bounded parallelism with backpressure

----------------------------------------------------------------
INTELLIGENT SLEEP POLICY
----------------------------------------------------------------

9) Idle detection
- Add per-tenant idle metrics:
  - last work timestamp
  - CPU usage moving average
  - in-guest heartbeat
- Persist in TenantState

10) Sleep heuristics
Implement default policy:

- If idle > T1 → warm
- If idle > T2 → sleep
- If memory pressure detected → sleep coldest VMs first

Expose config:
- global defaults
- per-tenant overrides

11) Agent-driven sleep
- Reconcile loop may transition:
  running → warm → sleeping
  based on observed metrics
- Must never sleep a VM that is marked "pinned" or "critical"

----------------------------------------------------------------
AGENT-WORKLOAD WORKER ALIGNMENT
----------------------------------------------------------------

12) Worker lifecycle hooks
Inside guest (Nix module):

- Provide hooks:
  /run/mvm/worker-ready
  /run/mvm/worker-idle
  /run/mvm/worker-busy

Host must:
- observe these signals
- update TenantState
- influence sleep policy decisions

13) Stateless worker guarantee
- Sleeping or destroying a worker must never lose in-flight state
- Require:
  - explicit ACK from worker before sleep
  - or forced fail + requeue semantics

----------------------------------------------------------------
OBSERVABILITY
----------------------------------------------------------------

14) Snapshot metrics
Expose:
- snapshot size
- compression ratio
- snapshot time
- restore time

Add:
mvm tenant stats <tenantId>

15) Node-wide sleep stats
Add:
mvm node stats

Shows:
- running / warm / sleeping counts
- memory saved by sleeping
- estimated $ savings (best-effort)

----------------------------------------------------------------
IMPLEMENTATION DETAILS
----------------------------------------------------------------

- Add modules:
  src/snapshot/{layout.rs,delta.rs,compression.rs}
  src/sleep/{policy.rs,metrics.rs}
  src/worker/hooks.rs

- Extend TenantState with:
  - base_snapshot_hash
  - last_idle_at
  - sleep_state (running|warm|sleeping)
  - snapshot_metadata

- Extend CLI:
  mvm tenant warm <tenantId>
  mvm tenant sleep <tenantId> --force
  mvm tenant wake <tenantId>
  mvm tenant stats <tenantId>
  mvm node stats

----------------------------------------------------------------
IMPLEMENT NOW
----------------------------------------------------------------

- Optimize snapshot size and reuse
- Minimize wake latency
- Implement intelligent sleep policies
- Keep dev mode intact
- Ensure code compiles and commands exist
