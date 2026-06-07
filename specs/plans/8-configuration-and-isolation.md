Update the mvm multi-tenant Firecracker fleet architecture to introduce
ROLE-BASED NixOS microVM profiles as a first-class design constraint.

This system must support different types of microVMs driven entirely by configuration,
not by ad-hoc scripts or mutable runtime logic.

Do not add Docker.
Do not add SSH.
Preserve multi-tenant isolation, cluster-wide addressing, sleep/wake, and mounted drive model.

----------------------------------------------------------------
CORE ARCHITECTURAL CHANGE (MANDATORY)
----------------------------------------------------------------

MicroVM types must be defined declaratively via NixOS modules.

Instead of treating all microVMs as identical, introduce ROLE-BASED VM PROFILES.

Each microVM must have:

- role: gateway | worker | builder | capability-imessage (future-safe)
- profile: minimal | python | agent-workload-gateway | agent-workload-worker | custom
- config_version
- secrets_epoch

Roles must determine:
- which services run
- which ports (if any) are exposed
- which drives are mounted
- which vsock control handlers are enabled
- whether external ingress is allowed

----------------------------------------------------------------
REQUIRED ROLES
----------------------------------------------------------------

1) gateway role
- Runs the agent workload's gateway.
- Exposes WebSocket endpoint internally (tenant network).
- Optionally exposed via ingress (WSS).
- Loads channel connectors (WhatsApp, Telegram).
- Reads persistent workspace + session state from /data.
- Loads secrets from /run/secrets.
- Loads configuration from /etc/mvm-config.

2) worker role
- Runs the agent workload's worker execution engine.
- Connects to tenant’s Gateway over tenant network.
- Does NOT expose external ports.
- Uses persistent workspace on /data.
- Uses secrets from /run/secrets.

3) builder role
- Runs Nix build jobs.
- No tenant external exposure.
- Uses job-drive model (no SSH).
- Disposable; no persistent tenant state.

4) capability-imessage (future)
- Placeholder role for connectors requiring macOS.
- Must be isolated at tenant level.
- Must still use mounted config/secrets model.

----------------------------------------------------------------
NIXOS INTEGRATION REQUIREMENTS
----------------------------------------------------------------

Implement roles as composable NixOS modules:

Example conceptual structure:

- nix/
    roles/
        gateway.nix
        worker.nix
        builder.nix
    profiles/
        minimal.nix
        python.nix
        agent-workload-gateway.nix
        agent-workload-worker.nix

Role modules define:
- services
- systemd units
- vsock guest agent integration
- drive mount expectations

Profiles define:
- language/runtime layers
- base packages
- resource expectations

Artifacts produced by Nix must include:
- kernel
- rootfs
- base Firecracker config template

Runtime must never reference the Nix store.

----------------------------------------------------------------
AGENT-WORKLOAD CONNECTION INTEGRATION
----------------------------------------------------------------

Incorporate the agent workload's documentation correctly:

- Gateway protocol is WebSocket JSON; clients must send a `connect` frame declaring role/scope.
- Token authentication may be required at gateway boundary.
- Memory is plain Markdown in workspace and must be stored on persistent /data.
- WhatsApp and Telegram connectors are configured via agent-workload.json and require tokens / login flows.
- Channel login/session state must persist on /data.

Mapping to drives:

- vda (immutable rootfs)
- vdb → /data (persistent tenant workspace + sessions + channel state)
- vdc → /run/secrets (ephemeral secrets)
- vdd → /etc/mvm-config (versioned config drive)

No tenant state may live in the rootfs.

----------------------------------------------------------------
RECONCILE BEHAVIOR UPDATE
----------------------------------------------------------------

Agent reconcile loop must:

- Ensure gateway instances are reconciled before worker instances.
- Refuse to start gateway if required config/secrets drives missing.
- Refuse to enable connectors without required secrets.
- Track instance role explicitly in state machine.

Sleep policy must:
- Respect role-specific min_runtime.
- Never sleep gateway below required minimum (configurable).

----------------------------------------------------------------
SCHEMA UPDATE
----------------------------------------------------------------

Update desired state schema:

{
  "tenants": [
    {
      "tenant_id": "...",
      "tenant_net_id": "...",
      "ipv4_subnet": "...",
      "pools": [
        {
          "pool_id": "...",
          "role": "gateway" | "worker",
          "profile": "...",
          "revision": { ... },
          "resources": { ... },
          "desired_counts": { ... }
        }
      ]
    }
  ]
}

Instance schema must include:
- role
- profile
- config_version
- secrets_epoch

----------------------------------------------------------------
GOALS
----------------------------------------------------------------

This change must:

- Make microVM type differences entirely declarative.
- Allow adding new VM types by adding Nix modules, not rewriting runtime.
- Preserve multi-tenant isolation.
- Preserve sleep/wake correctness.
- Keep dev mode intact.

Do not introduce unrelated features.
Produce an updated architecture plan reflecting this role-based NixOS integration.
