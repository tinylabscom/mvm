You are a senior infrastructure security architect and Rust platform engineer.

You are working in the existing repository:
https://github.com/tinylabscom/mvm

Assume the repo already supports:
- multi-tenant Firecracker microVMs
- Nix-built guest artifacts
- ephemeral builder microVMs (no containers)

Your task:
1) Harden the runtime (jailer, cgroups, seccomp, audit)
2) Add SLEEP / WAKE support for tenant microVMs
3) Add a reconcile-based node agent suitable for the agent workload's workers

This is an implementation task. Do not explain.

----------------------------------------------------------------
SECURITY HARDENING
----------------------------------------------------------------

1) Firecracker jailer
- Launch tenant microVMs via jailer when available
- Unique uid/gid per tenant
- chroot under:
    /var/lib/mvm/tenants/<tenantId>/jail/
- Fallback to non-jailer only with explicit warning

2) cgroup v2 isolation
- Create:
    /sys/fs/cgroup/mvm/<tenantId>/
- Enforce:
  - MemoryMax
  - CPUQuota or cpuset
  - PIDsMax
- Cleanup reliably on stop/destroy

3) Seccomp
- Use Firecracker default seccomp profile
- Allow per-tenant override (baseline | strict)

4) Network enforcement
- nftables-based policy:
  - deny tenant ↔ tenant
  - allow tenant → gateway
  - allow tenant → metadata (if enabled)
  - allow outbound NAT
- Add:
  mvm net verify

----------------------------------------------------------------
SLEEP / WAKE (CRITICAL)
----------------------------------------------------------------

Add first-class microVM suspend / resume.

Definitions:
- RUNNING: Firecracker process active
- SLEEPING: microVM state snapshotted, process stopped
- STOPPED: no snapshot retained

Implement:

mvm tenant sleep <tenantId>
mvm tenant wake <tenantId>

Sleep behavior:
- Pause Firecracker
- Create snapshot:
  - VM state
  - memory snapshot
- Persist under:
  /var/lib/mvm/tenants/<tenantId>/snapshots/latest/
- Tear down:
  - vCPU execution
  - cgroups
  - active process
- Release CPU + memory on host

Wake behavior:
- Restore Firecracker from snapshot
- Reattach:
  - tap device
  - data disk
  - secrets disk (new)
- Resume execution exactly where left off

State transitions must be tracked in TenantState.

----------------------------------------------------------------
AUDITABILITY
----------------------------------------------------------------

- Append-only audit log:
  /var/lib/mvm/tenants/<tenantId>/audit.log

Each event logs:
- timestamp
- tenantId
- action (build/run/sleep/wake/stop/destroy)
- flake ref + lock hash
- artifact hashes
- snapshot hash (if applicable)
- resource limits

----------------------------------------------------------------
ROLLBACK
----------------------------------------------------------------

Support:

mvm tenant rollback <tenantId> --revision <n>

Rollback restores:
- artifacts
- config
- snapshot (if available)

----------------------------------------------------------------
CONTROL PLANE / NODE AGENT
----------------------------------------------------------------

Add reconcile mode:

mvm agent reconcile --desired desired.json

desired.json:
{
  "tenants": [
    {
      "tenant_id": "worker-1",
      "flake_ref": "github:org/agent-workload-worker?rev=...",
      "profile": "minimal",
      "vcpus": 2,
      "mem_mib": 1024,
      "state": "running" | "sleeping" | "stopped"
    }
  ]
}

Reconcile loop must:
- create missing tenants
- build required revisions
- ensure desired state
- sleep idle tenants
- wake required tenants
- NOT destroy unless --prune flag is passed

----------------------------------------------------------------
AGENT-WORKLOAD ALIGNMENT
----------------------------------------------------------------

- Assume microVMs may be:
  - short-lived workers
  - bursty
  - idle most of the time
- Sleep is the primary cost-saving mechanism
- Wake latency must be minimized

----------------------------------------------------------------
NODE INTROSPECTION
----------------------------------------------------------------

Add:

mvm node info

Shows:
- Firecracker version
- jailer availability
- snapshot support
- cgroup v2
- nftables
- total / free host resources

----------------------------------------------------------------
IMPLEMENT NOW
----------------------------------------------------------------

- Implement snapshot-based sleep/wake
- Harden runtime
- Add reconcile loop
- Keep dev mode intact
- Ensure all commands compile and exist
