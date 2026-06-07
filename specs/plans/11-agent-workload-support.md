# Plan 11: Agent-Workload Support — Role + Wake API + Deploy Config

## Overview

Deploy the reference AI-agent workload — a Node.js AI-agent platform (Claude API, gateway, MCP servers, channels) — as a multi-tenant service on mvm where:
1. A shared **agent-workload gateway** (Node.js, always-on) receives Telegram/Discord messages and routes them to per-user worker VMs
2. Per-user **agent-workload worker VMs** (sleep/wake) run Claude AI + tool execution
3. The gateway wakes sleeping worker VMs on incoming messages
4. Deployment is driven by a simple config file

## Architecture

```
Telegram → Agent-Workload Gateway VM (always-on, Node.js)
              ├── User Alice's msg → Alice's worker VM (wake if sleeping)
              ├── User Bob's msg → Bob's worker VM
              └── Returns results to Telegram
```

No nginx. The agent workload's Node.js application handles Telegram protocols and routing.
mvm provides VM lifecycle, networking, secrets, and wake-on-demand.

## What Exists

- `mvm new agent-workload alice` — template creates tenant + gateway + workers (src/templates.rs)
- `AgentRequest::WakeInstance` — already in QUIC protocol (src/agent.rs)
- `agent reconcile --desired state.json` — standalone mode, no coordinator needed
- Worker role has vsock, integration manager, sleep-prep (nix/roles/worker.nix)
- Gateway role has config drive, IP forwarding (nix/roles/gateway.nix)
- RoutingTable data model supports path_prefix matching (src/vm/pool/routing.rs)
- IntegrationManifest supports checkpoint/restore (src/worker/integrations.rs)

## Phase 1: CapabilityAgentWorkload Role + Template Update

### Rust Changes

- `src/vm/pool/config.rs`: Add `CapabilityAgentWorkload` variant to Role enum, Display arm
- `src/main.rs`: Add `"capability-agent-workload"` to `parse_role()`, update help text
- `src/agent.rs`: Add `Role::CapabilityAgentWorkload => 3` to `role_priority()`
- `src/vm/pool/nix_manifest.rs`: Add to SAMPLE_TOML + tests

### NixOS Module

- `nix/mvm-profiles.toml`: Add `[roles.capability-agent-workload]` with config_drive=true, secrets_drive=true
- `nix/roles/agent-workload.nix` (NEW): Self-contained module combining worker.nix + gateway.nix patterns:
  - Config drive mount (/dev/vdd → /etc/mvm-config)
  - `mvm-agent-workload-env` — assembles /run/agent-workload/env from secrets drive
  - `agent-workload-gateway` — Node.js main service as agent-workload:agent-workload user
  - `mvm-worker-agent` — vsock host communication
  - `mvm-integration-manager` — /data/integrations/ setup
  - `mvm-sleep-prep-vsock` — checkpoint + ACK on port 5200
  - `mvm-agent-workload-wake` — restore integrations, restart gateway
  - TCP keepalive sysctl, packages: nodejs_22, socat, jq, curl, git
- `nix/flake.nix`: Add tenant-capability-agent-workload-{minimal,python} outputs + mvm-role-agent-workload to nixosModules

### Template Update

- `src/templates.rs`: Change agent-workload template workers from Role::Worker to Role::CapabilityAgentWorkload, bump mem_mib to 2048

## Phase 2: Vsock Wake Protocol

### Guest→Host Communication

The agent workload's gateway VM tells the host agent "wake user X's worker VM" via vsock.

- `src/worker/vsock.rs`: Add HostBoundRequest/HostBoundResponse types:
  - WakeInstance { tenant_id, pool_id, instance_id }
  - QueryInstanceStatus { tenant_id, pool_id, instance_id }
  - WakeResult { success }
  - InstanceStatus { status, guest_ip }
- Host agent listens on each gateway VM's vsock UDS (port 53)
- On WakeInstance, calls existing instance_wake()
- Reuses existing length-prefixed JSON frame protocol

### Routing Table

Gateway→worker mapping delivered via config drive routes.json using existing RoutingTable model.
No new Rust types needed.

## Phase 3: Config File + Deploy Command

### Config for mvm new

- Add `--config <path>` to `Commands::New`
- DeployConfig TOML type: secrets (file refs), overrides (flake, pool resources)
- `mvm new agent-workload alice --config config.toml` reads secrets, applies overrides

### Standalone mvm deploy

- Add `Commands::Deploy { manifest, watch, interval }`
- DeploymentManifest TOML: tenant, pools, secrets, all in one file
- Converts to DesiredState, calls reconcile_desired(), delivers secrets
- With --watch: loop at interval
- Add `toml = "0.8"` crate

## Sleep/Wake Behavior for the Agent Workload

### Sleep (checkpoint)
1. Host sends CheckpointIntegrations via vsock
2. Guest signals the agent workload via /run/agent-workload/control.sock → CHECKPOINT
3. The agent workload closes Telegram/Discord connections gracefully
4. Guest runs standard sleep-prep (drop caches, sync)
5. Host takes Firecracker snapshot

### Wake (restore)
1. Host restores from snapshot
2. Guest mvm-agent-workload-wake service fires:
   - Re-assembles /run/agent-workload/env (secrets may have rotated)
   - Restores integrations from /data/integrations/
   - Restarts agent-workload-gateway.service
3. The agent workload re-establishes Telegram/Discord connections

### Recommended RuntimePolicy
```json
{
  "min_running_seconds": 300,
  "min_warm_seconds": 120,
  "drain_timeout_seconds": 30
}
```

## Config Drive Contents

```json
{
  "instance_id": "i-abc123",
  "pool_id": "workers",
  "tenant_id": "alice",
  "guest_ip": "10.240.1.5",
  "agent_workload": {
    "gateway_url": "https://api.agent-workload.example",
    "plugin_dir": "/data/agent-workload/plugins"
  },
  "integrations": [
    {
      "name": "telegram",
      "checkpoint_cmd": "/opt/agent-workload/bin/agent-workload-ctl checkpoint telegram",
      "restore_cmd": "/opt/agent-workload/bin/agent-workload-ctl restore telegram",
      "critical": true
    }
  ]
}
```

## Secrets Drive Layout

```
/run/secrets/
  anthropic/ANTHROPIC_API_KEY
  telegram/TELEGRAM_BOT_TOKEN
  agent-workload/AGENT_WORKLOAD_AUTH_TOKEN
```

## Usage Examples

### Quick start (template)
```bash
mvm new agent-workload alice --config deploy.toml
```

### Full control (manifest)
```bash
mvm deploy deployment.toml --watch
```

### Deployment manifest example
```toml
[tenant]
id = "alice"

[[pools]]
id = "gateways"
role = "gateway"
profile = "minimal"
flake = "github:agent-workload/nix-agent-workload-integration"
vcpus = 2
mem_mib = 1024

[[pools]]
id = "workers"
role = "capability-agent-workload"
profile = "minimal"
flake = "github:agent-workload/nix-agent-workload-integration"
vcpus = 2
mem_mib = 2048
desired_running = 1

[secrets]
anthropic_key = { file = "./secrets/anthropic.key" }
telegram_token = { file = "./secrets/telegram.token" }
```
