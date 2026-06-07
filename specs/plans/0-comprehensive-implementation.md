# True Multi-Tenant Firecracker: Nix Builds, Sleep/Wake, Security & Fleet Control

## Context

The `mvm` Rust CLI manages Firecracker microVMs on Apple Silicon and x86_64 via Lima. It has a dev workflow (`mvm start/stop/ssh/dev`) and an image build pipeline.

This plan implements a production-ready **true multi-tenant** microVM management system where:
- A **Tenant** is a security, isolation, and policy boundary that may own multiple microVMs
- A **WorkerPool** defines a homogeneous workload type within a tenant
- An **Instance** is an individual Firecracker microVM

**Previous model (replaced):** `tenant == microVM` (1:1)
**New model:** `Tenant → WorkerPools → Instances` (1:N:M)

Existing dev mode remains untouched throughout.

---

## Crate Structure: Library + Binary

mvm is structured as a **library crate with a binary target**. All core functionality lives in the library; the CLI binary is a thin clap dispatcher that calls into it.

### Why

1. The TypeScript+Hono API server (separate repo) is the **coordinator**. It communicates with `mvm agent serve` via the QUIC+mTLS API already planned. No Rust API server in this repo.
2. Clean separation: data models, lifecycle logic, networking, snapshots, security are all library code. Only CLI parsing and dispatch are binary-specific.
3. Enables future consumers (other Rust tools, test harnesses) to import mvm as a dependency.

### Cargo.toml

```toml
[package]
name = "mvm"
version = "0.0.1"
edition = "2024"

[lib]
name = "mvm"
path = "src/lib.rs"

[[bin]]
name = "mvm"
path = "src/main.rs"
```

### src/lib.rs

```rust
pub mod infra;
pub mod vm;
pub mod security;
pub mod sleep;
pub mod worker;
pub mod agent;
pub mod node;
```

### src/main.rs

```rust
use mvm::*;          // import from the library crate
use clap::{Parser, Subcommand};
// ... CLI struct, dispatch, command handlers
```

The binary imports from the library. No `mod` declarations in main.rs (except for the CLI-specific code). The `pub use` re-exports currently in main.rs are removed — they move to lib.rs.

### Dependency Gating (optional, deferred)

CLI-only dependencies (clap, colored, indicatif, inquire) could be feature-gated behind a `cli` feature in the future. For now, they stay as regular dependencies since we ship the binary from this crate.

---

## Object Model

### 1. Tenant (security/quota boundary)

A Tenant owns policy, quotas, secrets, config, and audit scope. It is NOT a runtime entity.

```rust
pub struct TenantConfig {
    pub tenant_id: String,
    pub quotas: TenantQuota,
    pub net: TenantNet,
    pub secrets_epoch: u64,
    pub config_version: u64,
    pub pinned: bool,               // reconcile cannot auto-stop tenant's instances
    pub audit_retention_days: u32,  // 0 = forever
    pub created_at: String,
}

pub struct TenantQuota {
    pub max_vcpus: u32,
    pub max_mem_mib: u64,
    pub max_running: u32,
    pub max_warm: u32,
    pub max_pools: u32,
    pub max_instances_per_pool: u32,
    pub max_disk_gib: u64,
}

pub struct TenantNet {
    pub tenant_net_id: u16,     // Coordinator-assigned, cluster-unique (0..4095)
    pub ipv4_subnet: String,    // Coordinator-assigned CIDR, e.g. "10.240.3.0/24"
    pub gateway_ip: String,     // First usable IP, e.g. "10.240.3.1"
    pub bridge_name: String,    // "br-tenant-<tenant_net_id>", e.g. "br-tenant-3"
}
```

### 2. WorkerPool (per-tenant workload group)

A WorkerPool defines a homogeneous group of instances. It has desired counts but NO runtime state.

```rust
pub struct PoolSpec {
    pub pool_id: String,
    pub tenant_id: String,
    pub flake_ref: String,
    pub profile: String,            // "baseline" | "minimal" | "python"
    pub instance_resources: InstanceResources,
    pub desired_counts: DesiredCounts,
    pub seccomp_policy: String,     // "baseline" | "strict"
    pub snapshot_compression: String, // "none" | "lz4" | "zstd"
    pub metadata_enabled: bool,
    pub pinned: bool,               // reconcile won't auto-sleep
    pub critical: bool,             // reconcile won't touch
}

pub struct InstanceResources {
    pub vcpus: u8,
    pub mem_mib: u32,
    pub data_disk_mib: u32,
}

pub struct DesiredCounts {
    pub running: u32,
    pub warm: u32,
    pub sleeping: u32,
}

pub struct BuildRevision {
    pub revision_hash: String,
    pub flake_ref: String,
    pub flake_lock_hash: String,
    pub artifact_paths: ArtifactPaths,
    pub built_at: String,
}
```

### 3. Instance (individual Firecracker microVM)

An Instance is the ONLY entity with runtime state.

```rust
pub struct InstanceState {
    pub instance_id: String,        // system-generated "i-<8hex>"
    pub pool_id: String,
    pub tenant_id: String,
    pub status: InstanceStatus,
    pub net: InstanceNet,
    pub revision_hash: Option<String>,
    pub firecracker_pid: Option<u32>,
    pub last_started_at: Option<String>,
    pub last_stopped_at: Option<String>,
    pub idle_metrics: IdleMetrics,
    pub healthy: Option<bool>,
    pub last_health_check_at: Option<String>,
    pub manual_override_until: Option<String>,
}

pub struct InstanceNet {
    pub tap_dev: String,        // "tn<net_id>i<offset>", e.g. "tn3i5"
    pub mac: String,            // "02:xx:xx:xx:xx:xx" (deterministic from tenant_net_id + offset)
    pub guest_ip: String,       // From coordinator-assigned subnet, e.g. "10.240.3.5"
    pub gateway_ip: String,     // Tenant gateway, e.g. "10.240.3.1"
    pub cidr: u8,               // From subnet mask, e.g. 24
}
```

---

## Instance State Machine

State machines apply ONLY at the Instance level. Tenants and WorkerPools have no runtime state.

```
         create         pool build        start
Absent ────────► Created ──────────► Ready ────────► Running
                                      ▲                │  │
                                      │                │  │ warm
                                      │           stop │  ▼
                                      │                │  Warm
                                      │                │  │
                                      │                │  │ sleep
                                      │           stop │  ▼
                                      │                │  Sleeping
                                      │                │  │
                                      │                ▼  │ wake
                                      │             Stopped◄┘
                                      │                │
                                      │    rebuild     │
                                      └────────────────┘
```

Valid transitions (enforced in `instance/state.rs`):
- `Created → Ready` (pool build completes)
- `Ready → Running` (start)
- `Running → Warm` (pause vCPUs)
- `Running → Stopped` (stop)
- `Warm → Sleeping` (snapshot + shutdown)
- `Warm → Running` (resume)
- `Warm → Stopped` (stop)
- `Sleeping → Running` (wake from snapshot)
- `Sleeping → Stopped` (stop, discard snapshot)
- `Stopped → Running` (fresh boot)
- `Ready → Ready` (rebuild)
- Any → Destroyed (destroy)

Quotas are checked at the TENANT level before start/wake transitions.
Desired counts are evaluated at the WORKERPOOL level by the reconcile loop.

---

## Networking (Cluster-Wide, Coordinator-Assigned)

### Design: Cluster-wide tenant subnets with per-host bridges

This is a **multi-host, multi-tenant** fleet. Network identity is cluster-wide and coordinator-owned.

**Key invariant:** The same tenant ALWAYS gets the same subnet on every host in the cluster.

- **Coordinator** is the ONLY component that allocates tenant subnets
- **Agents** consume subnet allocations from desired state — they NEVER derive or hash IPs locally
- Each tenant gets one Linux bridge per host, with the coordinator-assigned subnet
- **Within-tenant east/west: ALLOWED** — instances on the same bridge freely communicate at L2/L3
- **Cross-tenant: DENIED by construction** — separate bridges are separate broadcast domains
- **Egress: NAT masquerade** — instances can reach external networks

### Cluster CIDR and Allocation

```
Cluster CIDR:  10.240.0.0/12   (10.240.0.0 – 10.255.255.255)
Default per-tenant subnet: /24 (252 usable IPs per tenant per host)

Coordinator allocates from this range:
  tenant "acme"   → tenant_net_id=3,   ipv4_subnet="10.240.3.0/24"
  tenant "beta"   → tenant_net_id=17,  ipv4_subnet="10.240.17.0/24"
  tenant "gamma"  → tenant_net_id=200, ipv4_subnet="10.240.200.0/24"
```

Allocation is persisted in the coordinator's tenant registry. `tenant_net_id` is a cluster-unique integer (0..4095) assigned at tenant creation time and NEVER reused (even after tenant deletion).

### Bridge and Gateway (Per Host)

```
Bridge name:  br-tenant-<tenant_net_id>
Gateway IP:   first usable IP in subnet (e.g. 10.240.3.1 for /24)

Examples:
  tenant_net_id=3   → br-tenant-3   10.240.3.1/24
  tenant_net_id=17  → br-tenant-17  10.240.17.1/24
  tenant_net_id=200 → br-tenant-200 10.240.200.1/24
```

Bridge names are max 15 chars. `br-tenant-4095` = 14 chars (fits).

### Within-Tenant IP Allocation

```
.1      = bridge gateway (NAT egress point)
.2      = reserved (builder microVM)
.3-.254 = instance IPs (allocated sequentially by agent on this host)
```

Instance IPs are host-local offsets within the coordinator-assigned subnet. The agent allocates them sequentially from `.3` upward. These IPs are recorded in `InstanceNet` but NOT communicated back to the coordinator (coordinator doesn't track instance IDs or IPs).

### TAP Device Naming

Format: `tn<net_id>i<ip_offset>` — max 12 chars, under 15-char Linux limit.
Examples: `tn3i5`, `tn17i3`, `tn200i100`, `tn4095i254`

### Network Rules (per tenant bridge, idempotent)

```bash
# Global (once)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Per-tenant bridge setup (using coordinator-assigned subnet)
ip link add br-tenant-<N> type bridge
ip addr add <gateway_ip>/<cidr> dev br-tenant-<N>
ip link set br-tenant-<N> up

# Per-tenant NAT (egress only)
iptables -t nat -A POSTROUTING -s <subnet> ! -o br-tenant-<N> -j MASQUERADE
iptables -A FORWARD -i br-tenant-<N> ! -o br-tenant-<N> -j ACCEPT
iptables -A FORWARD ! -i br-tenant-<N> -o br-tenant-<N> -m state --state RELATED,ESTABLISHED -j ACCEPT
```

No east-west rules needed — intra-tenant traffic flows freely within the bridge. Cross-tenant traffic is impossible because bridges are separate L2 domains.

### Sleep/Wake Network Preservation

When an instance sleeps, its TAP device and IP allocation are preserved in `InstanceNet`. On wake, the same TAP is reattached to the same tenant bridge with the same IP. Network identity is stable across sleep/wake cycles.

### `mvm net verify` Checks

1. Each tenant bridge exists and has the coordinator-assigned subnet
2. Bridge gateway IP matches `TenantNet.gateway_ip`
3. Each tenant's iptables NAT + forward rules exist
4. No cross-tenant bridge connectivity (separate L2 domains)
5. Within-tenant instances can ping each other (optional, active probe)
6. Subnet matches coordinator allocation in `tenant.json`
7. Report JSON or human-readable

---

## Filesystem Layout

```
/var/lib/mvm/
    node.json                              # Node identity + resource limits
    builder/                               # Ephemeral build microVM workspace
        run/<build-id>/
    tenants/
        <tenant_id>/
            tenant.json                    # TenantConfig (quotas, network)
            secrets.json                   # Tenant-scoped secrets
            audit.log                      # Per-tenant append-only audit
            ssh_key, ssh_key.pub           # Per-tenant Ed25519 keypair
            pools/
                <pool_id>/
                    pool.json              # PoolSpec (flake, profile, resources, desired_counts)
                    build_history.json     # Last N BuildRevisions
                    artifacts/
                        current -> revisions/<hash>/
                        revisions/<hash>/
                            vmlinux
                            rootfs.ext4
                            fc-base.json
                    snapshots/
                        base/              # Shared base snapshot (pool-level)
                            vmstate.bin
                            mem.bin
                            meta.json
                    instances/
                        <instance_id>/
                            instance.json  # InstanceState
                            runtime/
                                fc.json
                                firecracker.socket
                                fc.pid
                                firecracker.log
                            volumes/
                                data.ext4      # Per-instance persistent data
                                secrets.ext4   # Per-instance (recreated each run)
                            snapshots/
                                delta/         # Instance-specific delta snapshot
                                    vmstate.delta.bin
                                    mem.delta.bin
                                    meta.json
                            jail/
```

Key decisions:
- **Artifacts** at pool level — all instances share same kernel/rootfs
- **Base snapshots** at pool level — identical post-boot state, shared across instances
- **Delta snapshots** at instance level — unique per-instance memory state
- **Secrets disk** recreated per-run from tenant-level `secrets.json`
- **Audit log** at tenant level — unified compliance trail

---

## CLI Structure

```
# --- Tenant management ---
mvm tenant create <id> --net-id <N> --subnet <CIDR> [--max-vcpus N] [--max-mem M] [--max-running R] [--max-warm W]
mvm tenant list [--json]
mvm tenant info <id> [--json]
mvm tenant update <id> [--max-vcpus N] [--max-mem M] ...
mvm tenant destroy <id> [--force] [--wipe-volumes]
mvm tenant secrets set <id> --from-file <path>
mvm tenant secrets rotate <id>

# --- Pool management ---
mvm pool create <tenant>/<pool> --flake <ref> --profile <name> --cpus N --mem M [--data-disk D]
mvm pool list <tenant> [--json]
mvm pool info <tenant>/<pool> [--json]
mvm pool build <tenant>/<pool> [--timeout N]
mvm pool scale <tenant>/<pool> --running N [--warm W] [--sleeping S]
mvm pool update <tenant>/<pool> [--flake <ref>] [--profile <name>] ...
mvm pool rollback <tenant>/<pool> [--revision N]
mvm pool destroy <tenant>/<pool> [--force]

# --- Instance operations ---
mvm instance list [--tenant T] [--pool P] [--json]
mvm instance ssh <tenant>/<pool>/<instance>
mvm instance start <tenant>/<pool>/<instance>
mvm instance stop <tenant>/<pool>/<instance>
mvm instance warm <tenant>/<pool>/<instance>
mvm instance sleep <tenant>/<pool>/<instance> [--force]
mvm instance wake <tenant>/<pool>/<instance>
mvm instance stats <tenant>/<pool>/<instance> [--json]
mvm instance destroy <tenant>/<pool>/<instance> [--wipe-volumes]
mvm instance logs <tenant>/<pool>/<instance>

# --- Agent ---
mvm agent reconcile --desired <path.json> [--prune]
mvm agent serve [--interval-secs N] [--desired <path>] [--listen <addr>] \
    [--tls-cert <path>] [--tls-key <path>] [--tls-ca <path>] [--coordinator-url <url>]
mvm agent certs init --ca <path>
mvm agent certs request --coordinator <url>
mvm agent certs rotate
mvm agent certs status [--json]

# --- Network ---
mvm net verify [--json]

# --- Node ---
mvm node info [--json]
mvm node stats [--json]

# --- Dev mode (UNCHANGED) ---
mvm bootstrap [--production]
mvm setup
mvm dev
mvm start [image] [--config] [--volume] [--cpus] [--memory]
mvm stop
mvm ssh
mvm status
mvm destroy
mvm upgrade [--check] [--force]
mvm build [path] [--output]
```

Build is per-pool (shared artifacts). Scale is per-pool (desired counts). SSH/stop/wake are per-instance.

---

## Agent Desired State Schema

Coordinator sends a **hierarchical tenant/pool** structure scoped to the node:

```json
{
  "schema_version": 1,
  "node_id": "node-abc123",
  "tenants": [
    {
      "tenant_id": "acme",
      "network": {
        "tenant_net_id": 3,
        "ipv4_subnet": "10.240.3.0/24"
      },
      "quotas": {
        "max_vcpus": 16,
        "max_mem_mib": 32768,
        "max_running": 8,
        "max_warm": 4,
        "max_pools": 3,
        "max_instances_per_pool": 10,
        "max_disk_gib": 100
      },
      "secrets_hash": "sha256:abc...",
      "pools": [
        {
          "pool_id": "workers",
          "flake_ref": "github:org/agent-workload-worker?rev=abc123",
          "profile": "minimal",
          "instance_resources": { "vcpus": 2, "mem_mib": 1024, "data_disk_mib": 2048 },
          "desired_counts": { "running": 3, "warm": 1, "sleeping": 2 },
          "seccomp_policy": "baseline",
          "snapshot_compression": "zstd"
        }
      ]
    }
  ],
  "prune_unknown_tenants": false,
  "prune_unknown_pools": false
}
```

**Network allocation is mandatory.** Every tenant in the desired state MUST include a `network` block with `tenant_net_id` and `ipv4_subnet`. The agent MUST reject any tenant entry missing this field. Agents never derive, compute, or hash network allocations — they consume them verbatim.

The node agent creates/destroys instance IDs locally. The coordinator does not track instance IDs or instance IPs.

### Agent Reconcile Loop

```
for each desired_tenant:
    REQUIRE network.tenant_net_id and network.ipv4_subnet (reject if missing)
    ensure tenant exists (create dirs if missing)
    apply coordinator-assigned network (create bridge with assigned subnet)
    update quotas

    for each desired_pool:
        ensure pool exists
        if artifacts missing or revision changed → build

        compute current instance counts by status
        usage = compute_tenant_usage(tenant_id)

        # Scale to desired_counts:
        # 1. Wake sleeping → running (if deficit)
        # 2. Resume warm → running (if deficit)
        # 3. Start stopped → running (if deficit)
        # 4. Create new instances → running (if deficit AND quota allows)
        # 5. Stop excess running → stopped
        # 6. Warm running → warm (to match warm count)
        # 7. Sleep warm → sleeping (to match sleeping count)

        # Quota check before every start/wake/create

    if prune: destroy pools not in desired list

if prune: destroy tenants not in desired list
```

Agent enforcement rules:
- **cgroup v2 limits per instance AND per-tenant aggregate** — never exceed tenant quotas
- **Filesystem isolation** — per-tenant directories, per-tenant secrets, no shared writable drives
- **Network isolation** — per-tenant bridge, cross-tenant denied by construction
- **Per-tenant audit logs** — all instance lifecycle events logged under tenant

---

## Module Layout

```
src/
    main.rs                      # CLI dispatch (tenant/pool/instance/agent/net/node subcommands)
    agent.rs                     # Reconcile loop + daemon serve mode + QUIC API
    node.rs                      # Node identity, info, stats
    infra/                       # UNCHANGED
        mod.rs, config.rs, shell.rs, bootstrap.rs, upgrade.rs, ui.rs
    vm/
        mod.rs
        # Dev mode (UNCHANGED)
        microvm.rs, firecracker.rs, network.rs, lima.rs, image.rs
        # Multi-tenant model (NEW)
        naming.rs                # ID validation, instance_id gen, TAP naming (tn<net_id>i<offset>)
        bridge.rs                # Per-tenant bridge (br-tenant-<net_id>) create/destroy/verify
        tenant/
            mod.rs
            config.rs            # TenantConfig, TenantQuota, TenantNet
            lifecycle.rs         # tenant_create, tenant_destroy, tenant_list, tenant_info
            quota.rs             # compute_tenant_usage, check_quota
            secrets.rs           # secrets_set, secrets_rotate
        pool/
            mod.rs
            config.rs            # PoolSpec, DesiredCounts, BuildRevision, InstanceResources
            lifecycle.rs         # pool_create, pool_destroy, pool_scale, pool_update, pool_rollback
            build.rs             # Ephemeral builder microVM, nix build, artifact storage
            artifacts.rs         # Revision management, symlinks, rollback
        instance/
            mod.rs
            state.rs             # InstanceStatus enum, InstanceState, validate_transition()
            lifecycle.rs         # instance_create/start/stop/warm/sleep/wake/destroy/ssh
            net.rs               # Per-instance TAP setup/teardown, IP allocation within tenant subnet
            fc_config.rs         # Generate Firecracker config for an instance
            disk.rs              # Data disk + secrets disk management
            snapshot.rs          # Base (pool-level) + delta (instance-level) snapshots
    security/
        mod.rs
        jailer.rs                # Firecracker jailer + fallback
        cgroups.rs               # cgroup v2 per-instance + per-tenant aggregate
        seccomp.rs               # Seccomp profile selection
        audit.rs                 # Append-only per-tenant audit log
        metadata.rs              # Minimal metadata service
    sleep/
        mod.rs
        policy.rs                # Sleep heuristics (per-pool, respects tenant quotas)
        metrics.rs               # Per-instance idle metrics
    worker/
        mod.rs
        hooks.rs                 # Guest worker lifecycle signals
```

---

## Nix Flake (Guest + Builder)

```
nix/
    flake.nix                    # Inputs: nixpkgs (24.11), microvm.nix
    guests/
        baseline.nix             # Base NixOS: openssh, static IP, fstab, worker hooks
        profiles/
            minimal.nix          # Baseline only
            python.nix           # + python3, pip
    builders/
        nix-builder.nix          # Nix + git, outbound net, SSH, large tmpfs
```

Outputs per profile: `packages.<system>.tenant-<profile>.{kernel,rootfs,fcBaseConfig}`
Builder: `packages.<system>.nix-builder.{kernel,rootfs,fcBaseConfig}`
Supports: `aarch64-linux`, `x86_64-linux`

---

## Build: Ephemeral Firecracker MicroVMs (NO Docker)

`mvm pool build <tenant>/<pool>`:
1. Load pool spec, validate tenant exists
2. Ensure builder artifacts exist (download from release URL on first use)
3. Boot ephemeral Firecracker builder microVM on tenant's bridge
4. Execute `nix build` inside builder via vsock/SSH
5. Copy artifacts to `pools/<pool>/artifacts/revisions/<hash>/`
6. Update `current` symlink
7. Shut down builder, clean up TAP
8. Record BuildRevision, audit log entry
9. Mark all Created instances as Ready

Builder microVMs are NOT instances — stateless, disposable, uniquely named per build.

---

## Instance Lifecycle API

`src/vm/instance/lifecycle.rs` — the single internal API for all operations:

```rust
pub fn instance_create(tenant_id, pool_id) -> Result<String>     // returns instance_id
pub fn instance_start(tenant_id, pool_id, instance_id) -> Result<()>
pub fn instance_stop(tenant_id, pool_id, instance_id) -> Result<()>
pub fn instance_warm(tenant_id, pool_id, instance_id) -> Result<()>
pub fn instance_sleep(tenant_id, pool_id, instance_id, force) -> Result<()>
pub fn instance_wake(tenant_id, pool_id, instance_id) -> Result<()>
pub fn instance_ssh(tenant_id, pool_id, instance_id) -> Result<()>
pub fn instance_destroy(tenant_id, pool_id, instance_id, wipe) -> Result<()>
pub fn instance_stats(tenant_id, pool_id, instance_id, json) -> Result<()>
```

Every function:
1. Loads InstanceState, calls `validate_transition()`
2. For start/wake: calls `quota::check_quota(tenant_id)` — rejects if tenant quota exceeded
3. Performs operation (networking, firecracker, snapshots)
4. Updates InstanceState atomically
5. Calls `audit::log_event(tenant_id, ...)`

### start() flow
1. Load instance + pool + tenant state
2. Check tenant quota (compute_tenant_usage vs TenantQuota)
3. `bridge::ensure_tenant_bridge(tenant_net)` (idempotent)
4. `instance::net::setup_tap(instance_net)` — attach to tenant's bridge
5. `cgroups::create_instance_cgroup(tenant_id, instance_id, resources)`
6. `disk::ensure_data_disk()` + `disk::create_secrets_disk()` from tenant secrets
7. `fc_config::generate()` — overlay pool artifacts + instance net + resources
8. Launch via `jailer::launch_jailed()` or `jailer::launch_direct()`
9. Record PID, update status to Running

### sleep() flow
1. Validate Running/Warm → Sleeping
2. Signal guest sleep-prep (via vsock)
3. Wait for ACK (or timeout if --force)
4. Pause Firecracker, create delta snapshot (instance-level)
5. Compress if configured
6. Kill process, cleanup cgroup
7. Keep TAP and data disk for wake
8. Update status to Sleeping

### wake() flow
1. Validate Sleeping → Running
2. Check tenant quota
3. Ensure TAP attached to tenant bridge
4. Create fresh secrets disk
5. Restore from pool base snapshot + instance delta
6. Resume vCPUs
7. Update status to Running

---

## Snapshot Management

**Pool-level base snapshots** — shared across all instances in a pool:
- Created after first boot + guest init of any instance
- Stored at `pools/<pool>/snapshots/base/`
- Keyed by `hash(kernel + rootfs)` — invalidated on rebuild
- Reused across all instances (significant optimization for scaling)

**Instance-level delta snapshots** — unique per instance:
- Captures memory dirtied since base
- Stored at `instances/<instance>/snapshots/delta/`
- Created on `instance_sleep`

**Wake restore order:**
1. Delta exists → restore base + delta
2. No delta → restore base only
3. No base → fresh boot

**Compression:** configurable per pool (`none` | `lz4` | `zstd`)

**Cross-tenant isolation:** Snapshots NEVER reused across tenants. Base snapshots are pool-scoped (pool ⊂ tenant).

---

## Security Hardening

### Jailer (`security/jailer.rs`)
- Unique uid/gid per instance: `10000 + (tenant_net_id * 256) + ip_offset`
- `tenant_net_id` is coordinator-assigned, cluster-unique — guarantees no uid/gid collisions
- Chroot under `instances/<id>/jail/`
- Fallback to direct launch with loud warning

### cgroups (`security/cgroups.rs`)
- Per-instance: `/sys/fs/cgroup/mvm/<tenant_id>/<instance_id>/`
- Limits: memory.max, cpu.max, pids.max
- Per-tenant aggregate enforcement via `compute_tenant_usage()`

### Seccomp (`security/seccomp.rs`)
- "baseline" → Firecracker default profile
- "strict" → custom restricted profile

### Audit (`security/audit.rs`)
- Per-tenant append-only log: `tenants/<tenant>/audit.log`
- Events: instance lifecycle, snapshot events, revision changes, quota enforcement
- Fields: timestamp, tenant_id, pool_id, instance_id, action, hashes, resources

### Metadata (`security/metadata.rs`)
- Tenant-scoped metadata endpoint on bridge gateway
- nftables rules restrict per-tenant access

---

## Sleep Policy & Worker Hooks

### Policy (`sleep/policy.rs`)
- Per-pool evaluation (respects tenant quotas)
- idle > T1 (default 5min) → warm
- idle > T2 (default 15min) → sleep
- Memory pressure → sleep coldest instances first
- Never sleep pinned/critical pools

### Worker Hooks (`worker/hooks.rs`)
- Guest signals: `/run/mvm/worker-{ready,idle,busy}`
- Sleep prep: drop page cache, compact memory, park threads
- ACK required before snapshot (or --force timeout)

---

## Agent Daemon (`agent.rs`)

`mvm agent serve` — tokio async runtime:
- **QUIC API server** (mTLS) — accepts coordinator connections
- **Reconcile loop** — periodic reconcile + sleep policy evaluation
- All other mvm commands remain synchronous

### QUIC + mTLS Communication
- `quinn` + `rustls` for transport
- Certificate hierarchy: Root CA → Coordinator cert + Node certs
- Short-lived certs (24h), auto-renewal at 50% lifetime
- `mvm agent certs {init,request,rotate,status}`

### Node Agent API
```
POST /v1/reconcile              # push desired state
GET  /v1/node/info              # node capabilities
GET  /v1/node/stats             # aggregate stats
GET  /v1/tenants                # list tenants with usage
GET  /v1/tenants/<id>/instances # list instances
POST /v1/tenants/<id>/pools/<p>/instances/<i>/wake  # urgent wake
```

---

## Node Info & Stats (`node.rs`)

`mvm node info`: Lima status, FC version, jailer/cgroup/nftables availability, bridges, node ID
`mvm node stats`: Per-tenant running/warm/sleeping counts, memory usage, snapshot stats

---

## Cargo Dependencies (additions)

```toml
tokio = { version = "1", features = ["full"] }
quinn = "0.11"
rustls = { version = "0.23", features = ["ring"] }
rustls-pemfile = "2"
rcgen = "0.13"
lz4_flex = "0.11"
sha2 = "0.10"
uuid = { version = "1", features = ["v4"] }
rand = "0.8"
```

---

## Critical Gap Coverage

1. **Concurrent locking** — flock per instance (not per tenant)
2. **Build timeouts** — `timeout 1800 nix build`, configurable via `--timeout`
3. **SSH keys** — Ed25519 per tenant, private key never enters guest
4. **Error recovery** — PID liveness checks, cleanup-on-failure, idempotent ops
5. **Storage GC** — `mvm pool gc`, `mvm node gc`, auto-GC in agent
6. **Graceful shutdown** — SIGTERM handling, don't stop running instances
7. **Node resource limits** — `/var/lib/mvm/node.json`, checked before start
8. **Health checks** — Post-boot SSH verification, periodic pings in daemon
9. **Clock sync** — NTP on resume, `clocksource=kvm-clock`
10. **Builder bootstrap** — Download pre-built from GitHub release on first use
11. **Rate limiting** — Token-bucket in QUIC API, 10 req/s default
12. **Memory ballooning** — Inflate before snapshot, deflate on wake

---

## Implementation Order

1. **Phase 1**: Lib/bin split (`src/lib.rs` + update `Cargo.toml`) + data model (`tenant/config.rs`, `pool/config.rs`, `instance/state.rs`, `naming.rs`, `bridge.rs`) + CLI skeleton in `main.rs` → `cargo build` passes
2. **Phase 2**: Nix flake + guest modules + builder module
3. **Phase 3**: `pool/build.rs` (ephemeral FC build VMs) → `mvm pool build` works
4. **Phase 4**: `bridge.rs` + `instance/net.rs` → per-tenant networking
5. **Phase 5**: `instance/lifecycle.rs` + `fc_config.rs` + `disk.rs` + `tenant/quota.rs` → core lifecycle
6. **Phase 6**: `instance/snapshot.rs` → sleep/wake/warm
7. **Phase 7**: `security/` modules → hardened runtime
8. **Phase 8**: `sleep/` + `worker/` → intelligent sleep policies
9. **Phase 9**: `agent.rs` + `node.rs` → reconcile + node info/stats
10. **Phase 10**: Agent daemon with tokio + QUIC + mTLS
11. **Final**: Integration pass, README rewrite, cargo build + test

Each phase must compile before proceeding.

---

## Files Summary

### New Rust files (~22):
| File | Purpose |
|------|---------|
| `src/vm/naming.rs` | ID validation, instance_id gen, TAP naming (tn<net_id>i<offset>) |
| `src/vm/bridge.rs` | Per-tenant bridge (br-tenant-<net_id>) create/destroy/verify |
| `src/vm/tenant/mod.rs` | Module declarations |
| `src/vm/tenant/config.rs` | TenantConfig, TenantQuota, TenantNet |
| `src/vm/tenant/lifecycle.rs` | tenant_create/destroy/list/info/update |
| `src/vm/tenant/quota.rs` | compute_tenant_usage, check_quota |
| `src/vm/tenant/secrets.rs` | secrets_set, secrets_rotate |
| `src/vm/pool/mod.rs` | Module declarations |
| `src/vm/pool/config.rs` | PoolSpec, DesiredCounts, BuildRevision |
| `src/vm/pool/lifecycle.rs` | pool_create/destroy/scale/update/rollback |
| `src/vm/pool/build.rs` | Ephemeral builder microVM |
| `src/vm/pool/artifacts.rs` | Revision management, symlinks |
| `src/vm/instance/mod.rs` | Module declarations |
| `src/vm/instance/state.rs` | InstanceStatus, InstanceState, validate_transition |
| `src/vm/instance/lifecycle.rs` | Unified lifecycle API |
| `src/vm/instance/net.rs` | TAP setup/teardown within tenant bridge |
| `src/vm/instance/fc_config.rs` | FC config generation |
| `src/vm/instance/disk.rs` | Data + secrets disk management |
| `src/vm/instance/snapshot.rs` | Base (pool) + delta (instance) snapshots |
| `src/security/{mod,jailer,cgroups,seccomp,audit,metadata}.rs` | Security modules |
| `src/sleep/{mod,policy,metrics}.rs` | Sleep policy + metrics |
| `src/worker/{mod,hooks}.rs` | Worker lifecycle signals |
| `src/agent.rs` | Reconcile + daemon |
| `src/node.rs` | Node identity + stats |

### New entry point:
| File | Purpose |
|------|---------|
| `src/lib.rs` | Library crate root — exports all public modules (infra, vm, security, sleep, worker, agent, node) |

### Modified files:
| File | Change |
|------|--------|
| `Cargo.toml` | Add `[lib]` + `[[bin]]` sections, add new dependencies |
| `src/main.rs` | Remove `mod`/`pub use` declarations, import from `mvm::*` library crate, add subcommands |
| `src/vm/mod.rs` | Add tenant/, pool/, instance/, bridge, naming module declarations |
| `src/vm/tenant.rs` | **REPLACE** with `src/vm/tenant/` directory module |
| `src/infra/bootstrap.rs` | Add `--production` flag |

### Nix files (5):
`nix/flake.nix`, `nix/guests/baseline.nix`, `nix/guests/profiles/{minimal,python}.nix`, `nix/builders/nix-builder.nix`

### Untouched (dev mode preserved):
`src/vm/{microvm,firecracker,network,lima,image}.rs`, `src/infra/{config,shell,ui,upgrade}.rs`

---

## Verification

```bash
cargo build && cargo test

# Dev mode
mvm status && mvm dev

# Tenant lifecycle
mvm tenant create acme --net-id 3 --subnet 10.240.3.0/24 --max-vcpus 16 --max-mem 32768 --max-running 8
mvm pool create acme/workers --flake . --profile minimal --cpus 2 --mem 1024
mvm pool build acme/workers
mvm pool scale acme/workers --running 3 --warm 1 --sleeping 2
mvm instance list acme/workers
mvm instance ssh acme/workers/i-a3f7b2c1

# Sleep/wake
mvm instance warm acme/workers/i-a3f7b2c1
mvm instance sleep acme/workers/i-a3f7b2c1
mvm instance wake acme/workers/i-a3f7b2c1

# Networking
mvm net verify

# Multi-tenant isolation (subnets assigned by coordinator via desired state)
mvm agent reconcile --desired desired.json  # desired.json includes acme (net_id=3, 10.240.3.0/24) and beta (net_id=17, 10.240.17.0/24)
# Verify: acme instances on br-tenant-3 (10.240.3.0/24), beta on br-tenant-17 (10.240.17.0/24)
# Verify: acme instances can ping each other, cannot reach beta instances

# Reconcile
mvm agent reconcile --desired desired.json
mvm node stats

# Cleanup
mvm pool destroy acme/workers --force
mvm tenant destroy acme --force --wipe-volumes
```
