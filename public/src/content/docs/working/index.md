---
title: Working in the MicroVM
description: Local sandbox management with mvmctl.
---

`mvmctl` is the local sandbox management surface. It builds images, boots microVMs, runs commands, transfers files, declares ingress ports at boot, captures logs, and moves sandboxes through pause, cold, resume, stop, and destroy-style workflows.

## Common lifecycle

```sh
mvmctl machine build --flake ./my-app
mvmctl machine run --flake ./my-app --name agent-sandbox -d
mvmctl machine exec agent-sandbox -- python /work/task.py
mvmctl machine logs agent-sandbox -f
mvmctl machine stop agent-sandbox
```

## Management tasks

| Task | Start here |
| --- | --- |
| Understand sandbox states and transitions | [Lifecycle states](/working/lifecycle-states/) |
| Run commands and processes | [Run commands & processes](/working/commands/) |
| Move files across the host/guest boundary | [Filesystem operations](/working/filesystem/) |
| Expose services or constrain egress | [Network & exposing ports](/working/network/) |
| Keep state across runs | [Persistence, pause & resume](/working/persistence/) |
| Save and recover machine state | [Cold mode](/working/cold-mode/) and [Snapshots](/working/snapshots/) |

## Security posture

- Build inputs are materialized before runtime launch.
- Runtime guests boot through explicit backend selection and local admission.
- Guest operations go through the control plane rather than broad host access.
- Logs, file transfer, and snapshots can carry sensitive data and should be handled as such.
- Network access should be explicit for agent and browser workloads.

## Local first

The local workflow should be complete on its own: build, launch, inspect, debug, pause, recover, and remove state from the host you control. Hosted or fleet layers can build on the same semantics later, but the local management commands are the baseline.
