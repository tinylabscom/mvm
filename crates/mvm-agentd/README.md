# mvm-agentd

Vsock protocol definitions and integration management for guest-side agents running inside Firecracker microVMs. Defines the wire protocol between host and guest — no SSH, ever.

## Modules

| Module | Purpose |
|--------|---------|
| `vsock` | Guest control protocol: `GuestRequest`/`GuestResponse` |
| `builder_agent` | Host-VM dispatch protocol: `HostVmRequest`/`HostVmResponse` |
| `integrations` | Integration manifest system: `IntegrationManifest`, `IntegrationEntry`, health checks |

## Wire Protocol

All communication uses **4-byte big-endian length prefix + JSON body** over Firecracker vsock.

| Port | Direction | Purpose |
|------|-----------|---------|
| 5252 | Host -> Guest | Guest agent control (Ping, WorkerStatus, SleepPrep, Wake) |
| 21470 | Host -> Guest | Builder agent (NixBuild, HealthCheck) |

> Listen-side ports (Host → Guest direction) live above 1023 because the
> agent runs as uid 901 with no `CAP_NET_BIND_SERVICE`.

## Binaries

- **mvm-guest-agent** — Runs inside tenant instances on port 5252. Handles health checks, load sampling, sleep/wake lifecycle, and integration status reporting.
- **mvm-builder-agent** — Runs inside ephemeral builder VMs on port 21470. Accepts `nix build` commands and reports results.

## Integration System

Workloads declare themselves via JSON drop-in files in `/etc/mvm/integrations.d/`. The guest agent discovers, monitors, and reports integration health to the host.

## Dependencies

- `mvm-core` (types, config)
