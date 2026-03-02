---
title: Guest Agent
description: The mvm guest agent provides host visibility and control over microVMs via vsock.
---

Every microVM built with `mkGuest` includes **mvm-guest-agent**, a lightweight Rust daemon that runs inside the guest on vsock port 52.

## Capabilities

| Capability | Description |
|------------|-------------|
| **Health checks** | Runs per-service health commands on a schedule, reports results to the host |
| **Worker status** | Tracks idle/busy state by sampling `/proc/loadavg` — used by fleet autoscaling |
| **Snapshot lifecycle** | Coordinates sleep/wake: flushes data, drops page cache before snapshot, signals restore |
| **Integration management** | Loads service definitions from `/etc/mvm/integrations.d/*.json` |
| **Probes** | Loads read-only system checks from `/etc/mvm/probes.d/*.json` (disk usage, custom metrics) |
| **Remote command** | Dev-only: `mvmctl vm exec <name> -- <cmd>` runs commands inside the guest |

## Protocol

The agent communicates using **length-prefixed JSON frames** over Firecracker's vsock UDS socket:

1. Host writes `CONNECT 52\n` to the socket
2. Agent responds with `OK 52\n`
3. All subsequent communication is request/response pairs

Request types: `ping`, `status`, `sleep-prep`, `wake`, and more.

## Health Checks

Health checks defined in `mkGuest`'s `healthChecks` parameter are automatically written to `/etc/mvm/integrations.d/` at build time:

```json
{
  "name": "my-service",
  "health_cmd": "curl -sf http://localhost:8080/health",
  "health_interval_secs": 10,
  "health_timeout_secs": 5
}
```

The agent picks them up on boot and begins periodic checks immediately.

## Querying from the Host

```bash
# Simple health ping
mvmctl vm ping
mvmctl vm ping my-vm

# Detailed status (worker state, integrations, health)
mvmctl vm status my-vm
mvmctl vm status my-vm --json

# Deep inspection (probes, integrations, worker status)
mvmctl vm inspect my-vm
```

## Probes

Probes are read-only system checks loaded from `/etc/mvm/probes.d/*.json`:

```json
{
  "name": "disk-usage",
  "command": "df -h /mnt/data | tail -1 | awk '{print $5}'",
  "interval_secs": 60
}
```

Probe results are included in `mvmctl vm inspect` output.

## Snapshot Coordination

Before creating a snapshot, the host sends a `sleep-prep` request. The agent:

1. Runs checkpoint commands for each integration
2. Syncs filesystem buffers
3. Drops page cache
4. Responds with "ready"

On wake (snapshot restore), the host sends a `wake` request and the agent runs restore commands for each integration.
