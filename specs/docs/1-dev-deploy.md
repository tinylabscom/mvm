# mvm Deployment Plan
A single reference plan for deploying a **multi-tenant Firecracker microVM fleet** (the agent workload's workers) with:
- **Coordinator** (global intent: tenants, pools, allocations, scheduling)
- **Host Agents (mvm agent)** (local execution + enforcement: Firecracker, networking, cgroups, jailer, snapshots, drives)
- **Cluster-wide tenant networking** (stable tenant subnets; within-tenant allow, cross-tenant deny)
- **No SSH** (host↔guest control via vsock or disk-job runner)
- **Sleep/Wake/Warm** to reduce cost and improve latency
- **Immutable rootfs images** (Nix-built), mutable state via mounted drives (data/config/secrets)

> This file focuses on deployment and “getting started” flows. It assumes your `mvm` repo implements the architecture discussed.

---

## 0) Concepts & Invariants

### Control plane shape
- **Coordinator is authoritative for intent**
  - Tenant registry + quotas
  - Subnet allocator (cluster-wide)
  - WorkerPool desired counts (running/warm/sleeping)
  - Placement decisions (which node runs which instances)
  - Rollout/rollback decisions (by flake lock hash + artifact hashes)
- **Host Agent is authoritative for execution**
  - Runs Firecracker microVMs
  - Enforces isolation locally (jailer + cgroups + nftables)
  - Sets up per-tenant bridges + taps
  - Mounts drives (data/config/secrets) and manages snapshots
  - Reports status/metrics + emits per-tenant audit logs

### Multi-tenant networking invariant
- **Within-tenant east/west: allowed**
- **Cross-tenant: default deny**
- **Cluster-wide addressing:** Coordinator allocates a stable subnet per tenant from a cluster CIDR (example `10.240.0.0/12`)
- **Host enforcement (recommended):** per-tenant bridge per host (`br-tenant-<tenantNetId>`)

### Runtime primitives
- **Rootfs** (immutable, Nix-built, read-only)
- **Drives** (all mutable state is attached as block devices)
  - `vdb` → `/data` (persistent, optional)
  - `vdc` → `/run/secrets` (ephemeral, refreshed each run/wake, read-only in guest)
  - `vdd` → `/etc/mvm-config` (versioned config drive, read-only)
- **Control channel:** vsock guest agent (preferred). No sshd in guests.

### Sleep states
- **running:** executing vCPUs
- **warm:** paused vCPUs, stays in RAM, near-zero CPU, fastest resume
- **sleeping:** snapshot + stop Firecracker, releases RAM/CPU, slower resume
- **stopped:** off, no snapshot retained

---

## 1) Prerequisites

### Host requirements (nodes running Firecracker)
- Linux host with **KVM available** (`/dev/kvm`)
- cgroup v2 enabled
- nftables available (or iptables if you’re using it)
- Sufficient fast disk (NVMe recommended) for snapshots + artifact cache:
  - `/var/lib/mvm` should be on fast local storage if possible

> Firecracker uses KVM. In cloud environments, prefer **bare metal** nodes or **nested virtualization supported** VMs.

### Coordinator requirements
- Can run anywhere (VM or managed Kubernetes)
- Needs durable storage (SQLite for dev/staging; Postgres for production)
- Exposes an API to distribute desired state to agents and receive status

---

## 2) Repository layout and config (recommended)
Suggested runtime dirs on each node:
- `/var/lib/mvm/`
  - `node-id`
  - `tenants/<tenantId>/...` (state, audit logs, volumes, snapshots)
  - `artifacts-cache/` (kernel/rootfs/config templates)
  - `builder/` (builder microVM artifacts if you do Nix builds via microVMs)

---

## 3) Scenario A — Development (single machine)

### Goal
Run a “fleet-of-one” that behaves like production:
- Coordinator + 1 agent + microVMs
- Cluster-wide networking semantics still apply (stable tenant subnets)
- All enforcement happens on the single node

### Recommended dev topology
- macOS → **Lima Linux VM** (this is your “node”) → `mvm agent` → Firecracker microVMs
- Coordinator can run:
  - locally on macOS (simplest), OR
  - inside Lima (closer to prod)

### Getting started (dev) — one script
Save as `scripts/dev-single-machine.sh` and run on macOS:

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1) Build mvm locally
cargo build --release
MVM="$(pwd)/target/release/mvm"

# 2) Bootstrap dev environment (existing flow)
# This should create/start Lima and install Firecracker tooling inside Lima.
"$MVM" bootstrap

# 3) Start dev node services needed for tenant mode
# In your implementation, prefer a production bootstrap that also:
# - verifies /dev/kvm
# - enables cgroup v2 checks
# - prepares nftables
# - prepares base cluster networking
"$MVM" bootstrap --production

# 4) Start coordinator (choose ONE)
# Option A: run coordinator locally (example placeholder binary)
# ./target/release/mvm-coordinator --db ./dev-coordinator.sqlite --listen 127.0.0.1:7777 &
#
# Option B: run coordinator inside Lima via mvm helper (if you have one)
# "$MVM" coordinator start --db /var/lib/mvm/coordinator.sqlite --listen 0.0.0.0:7777

echo "Coordinator: ensure it's running and reachable."

# 5) Start agent on the node (inside Lima)
# Agent should connect to coordinator, fetch desired state, and reconcile.
# Use mTLS if enabled; otherwise start with a dev token.
"$MVM" agent serve \
  --coordinator-url http://127.0.0.1:7777 \
  --interval-secs 15

# Now use coordinator tooling to create tenants/pools (examples below).
