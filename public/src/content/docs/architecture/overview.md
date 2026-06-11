---
title: Architecture overview
description: How mvm builds and runs secure local microVM workloads.
---

`mvm` keeps build, admission, runtime, and guest control boundaries explicit.

```text
SDK / CLI
  -> mvm local runtime
  -> builder VM for Linux build work
  -> signed plan admission
  -> microVM backend
  -> guest agent and workload
```

## Responsibilities

| Component | Owns |
| --- | --- |
| SDK | Authoring, lifecycle calls, result surfaces, and local transport choice. |
| `mvm` | Build handoff, launch admission, backend lifecycle, guest protocol, local audit. |
| Builder VM | Linux Nix evaluation, builds, image assembly, microVM-specific tooling. |
| Guest agent | In-guest process, filesystem, readiness, and telemetry RPC. |

See [Control surfaces](/architecture/control-surfaces/) for the current CLI,
SDK, MCP, console, and guest RPC entry points.

## Security posture

The runtime should be understandable from evidence:

- the artifact identity is known before launch;
- the plan binds resources and policy references;
- the audit chain records runtime decisions;
- credentials are references and grants;
- network access is explicitly mediated;
- checkpoint and snapshot restore carry backend-specific integrity evidence.
