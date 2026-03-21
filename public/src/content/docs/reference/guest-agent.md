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
| **Remote command** | Dev-only: execute commands inside the guest via vsock |

## Protocol

The agent communicates using **length-prefixed JSON frames** over vsock (Firecracker, Apple Container, microvm.nix) or a unix socket (Docker):

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

### Startup Grace Period

Services that take time to initialize (e.g., running database migrations) can specify a grace period. During the grace period, health check failures are suppressed and the service reports `Starting` status instead of `Error`:

```json
{
  "name": "my-service",
  "health_cmd": "curl -sf http://localhost:8080/health",
  "health_interval_secs": 10,
  "health_timeout_secs": 5,
  "startup_grace_secs": 120
}
```

In a Nix flake, set the grace period via `startupGraceSecs`:

```nix
healthChecks.my-app = {
  healthCmd = "curl -sf http://localhost:8080/health";
  healthIntervalSecs = 10;
  startupGraceSecs = 120;  # suppress failures for 2 minutes after boot
};
```

After the grace period expires, normal health reporting resumes.

## Querying from the Host

```bash
# Check guest console output
mvmctl logs my-vm

# Follow logs in real time
mvmctl logs my-vm -f

# List VMs and their status
mvmctl ls
```

Health check results and probe output are included in the guest console logs.

## Probes

Probes are read-only system checks loaded from `/etc/mvm/probes.d/*.json`:

```json
{
  "name": "disk-usage",
  "command": "df -h /mnt/data | tail -1 | awk '{print $5}'",
  "interval_secs": 60
}
```

Probe results are reported via the vsock protocol and included in guest console logs.

## Snapshot Coordination

Before creating a snapshot, the host sends a `sleep-prep` request. The agent:

1. Runs checkpoint commands for each integration
2. Syncs filesystem buffers
3. Drops page cache
4. Responds with "ready"

On wake (snapshot restore), the host sends a `wake` request and the agent runs restore commands for each integration.
