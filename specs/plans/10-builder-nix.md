You are a senior Rust infrastructure architect and systems designer.

You are working in the existing repository:
https://github.com/tinylabscom/mvm

Your task is to update the architecture and repo layout to match the full multi-tenant microVM fleet design for the reference AI-agent workload — a Node.js AI-agent platform (Claude API, gateway, MCP servers, channels) — we have discussed, using:

- A Rust WORKSPACE structure
- A clean internal module map
- A configuration-driven way to define and create new microVM types

This is an implementation task.
Do not explain.
Make concrete code changes, add files, and refactor aggressively where needed.
Do not add Docker or SSH.

----------------------------------------------------------------
NON-NEGOTIABLE CONSTRAINTS
----------------------------------------------------------------

- Multi-tenant: within-tenant east/west allowed; cross-tenant default deny.
- Cluster-wide tenant subnet allocation owned by coordinator (agents never invent IPs).
- Firecracker microVMs for isolation; use jailer always in production mode.
- No SSH anywhere (tenants or builders). Host↔guest control is vsock and/or disk-job-runner.
- Rootfs is immutable and Nix-built; all tenant state via mounted drives:
  - vdb => /data (persistent; encrypted at rest baseline)
  - vdc => /run/secrets (ephemeral; ro)
  - vdd => /etc/mvm-config (versioned; ro)
- Sleep/Wake/Warm supported; minimum runtime policy supported.
- Role-based microVM profiles defined by composable NixOS modules:
  roles: gateway | worker | builder | capability-imessage
  profiles: minimal | python | agent-workload-gateway | agent-workload-worker | custom

----------------------------------------------------------------
CONFIGURATION FILE BEHAVIOR (IMPORTANT CHANGE)
----------------------------------------------------------------

mvm must support configuration files with the following precedence:

1) If --config /path/to/mvm.toml is provided:
     → use that file.

2) Else if ./mvm.toml exists in the current working directory:
     → use that file.

3) Else if /etc/mvm/mvm.toml exists:
     → use that file (node default).

4) Else:
     → fail with a clear error message explaining how to provide config.

Never silently guess beyond these rules.
Always print which config file is being used.

The loaded config file hash must be recorded in:
- BuildRevision
- Instance state
- Audit log
- Node status output

----------------------------------------------------------------
A) REFACTOR INTO A RUST WORKSPACE (MANDATORY)
----------------------------------------------------------------

Convert the repo into a Cargo workspace:

/Cargo.toml (workspace)
crates/
  mvm-cli/
  mvm-core/
  mvm-agent/
  mvm/
  mvm-build/
  mvm-guest/

Rules:
- mvm-cli depends on mvm-agent and mvm-core only.
- mvm-agent depends on mvm-core, mvm, mvm-build, mvm-guest.
- mvm must not depend on mvm-agent.
- mvm-build must not depend on mvm except through narrow interfaces.
- Keep dev mode intact (macOS + Lima) but isolate platform-specific code.

----------------------------------------------------------------
B) INTERNAL MODULE MAP (IMPLEMENT CLEANLY)
----------------------------------------------------------------

Implement modules as previously defined:
- mvm-core: ids, schema, state store, audit, hashing, config loader
- mvm-agent: reconcile, planner, sleep policy, coordinator client
- mvm: firecracker, jailer, cgroups, nftables, taps, bridges, volumes, luks
- mvm-build: nix builder VM, artifact cache, config/secrets/job drives
- mvm-guest: vsock protocol, agent-workload connector mapping
- mvm-cli: clap commands only

Ensure boundaries are respected.

----------------------------------------------------------------
C) CONFIGURATION-DRIVEN MICROVM TYPES
----------------------------------------------------------------

Support declarative mvm.toml defining:

- microvms.roles.*
- microvms.profiles.*
- nixos_modules per role/profile
- required drives
- default resources
- default min runtime values
- connector requirements

Example:

[microvms.roles.gateway]
nixos_modules = ["nix/roles/gateway.nix"]
required_drives = ["data","config","secrets"]
expose_ingress = true
vsock_ports = [10500]

[microvms.profiles.agent-workload-worker]
nixos_modules = ["nix/profiles/agent-workload-worker.nix"]
defaults.vcpus = 2
defaults.mem_mib = 1024
defaults.min_running_seconds = 180

Agent must validate:
- role/profile combination exists
- required drives are mounted
- connector secrets exist before enabling connectors

Add CLI commands:
- mvm config validate
- mvm config print-effective
- mvm config scaffold (optional)

----------------------------------------------------------------
D) BUILD FLOW
----------------------------------------------------------------

mvm build must:

1) Resolve configuration file (precedence rules above).
2) Validate role/profile definitions.
3) Compose Nix modules for role + profile.
4) Build artifacts.
5) Copy artifacts out of nix store into /var/lib/mvm cache.
6) Record config hash + artifact hashes.

Never depend implicitly on repo-root configuration.
If using ./mvm.toml, it must be explicit in logs.

----------------------------------------------------------------
E) MULTI-TENANT AGENT-WORKLOAD SUPPORT
----------------------------------------------------------------

Maintain:

- Gateway role
- Worker role
- Connector mapping to agent-workload.json
- Tenant data layout on drives:
    /data
    /run/secrets
    /etc/mvm-config

Reconcile must:
- Start gateway before workers.
- Validate connectors before enabling them.
- Respect minimum runtime policy.

----------------------------------------------------------------
F) INSTALL / BOOTSTRAP UPDATE
----------------------------------------------------------------

install.sh and bootstrap must:

- Install workspace-built mvm-cli binary.
- Create a default config template at:
    ./mvm.toml (dev)
    /etc/mvm/mvm.toml (node)
- Print which config is in use.
- Allow:
    mvm bootstrap node --config /etc/mvm/mvm.toml

Combined mvm-install.sh must remain a single-command entrypoint.

----------------------------------------------------------------
DELIVERABLES
----------------------------------------------------------------

- Workspace conversion complete.
- Config resolution precedence implemented.
- CLI updated to support --config with sensible defaults.
- Config hash recorded in state.
- Updated Nix flake for role/profile composition.
- Documentation updated.
- Dev mode intact.

Do not leave TODOs.
Do not silently fall back to hidden config.
Always log which config file is loaded.
