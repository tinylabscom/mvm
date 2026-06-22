---
title: Persistent workspaces
description: Use encrypted volumes, copy workflows, snapshots, and cleanup policies for stateful sandboxes.
---

Persistent state is useful for agents, browser sessions, caches, databases, and
long-running services. It is also where sensitive data accumulates. Choose the
smallest state mechanism that fits the workflow, and make the retention policy
explicit before the sandbox starts.

## Pick a state mechanism

| Need | Use | Security posture |
| --- | --- | --- |
| One input file or result file | `mvmctl cp` or `mvmctl machine fs` | Narrowest boundary; preferred for generated-code tasks. |
| Read-only fixtures | `mvmctl run --add-dir ...:ro` | Host data is exposed but not writable by the guest. |
| Local dev edits | `mvmctl run --profile dev --add-dir ...:rw` | Writable host share; use only for trusted dev workflows. |
| Stateful app data | managed encrypted volume | Encrypted at rest when locked; plaintext exists while unlocked. |
| Fast retry or recovery | snapshot or cold mode | Can contain memory, files, processes, prompts, and credentials. |

Do not use a snapshot when a narrow output file is enough. Do not use a writable
host share when a managed volume is enough.

## Managed encrypted volume

Create a managed local volume:

```sh
mvmctl volume create agent-cache
```

Managed volumes are locked by default. Unlock before mounting:

```sh
mvmctl volume unlock agent-cache
```

Mount the unlocked volume into a running sandbox:

```sh
mvmctl volume mount agent-sandbox \
  --volume agent-cache \
  --guest /cache \
  --rw
```

List mounts:

```sh
mvmctl volume ls agent-sandbox
```

Unmount and lock when the workflow is done:

```sh
mvmctl volume unmount agent-sandbox /cache
mvmctl volume lock agent-cache
```

Security rules:

- `volume mount` refuses a managed volume while it is locked;
- `volume unlock` creates plaintext state that must be treated as sensitive;
- `volume lock` reseals the volume and removes plaintext after use;
- keep volume names scoped to the workflow or project;
- do not mount the same writable volume into unrelated sandboxes unless sharing
  state is the intent.

## Host-backed mounts

Ad-hoc host-backed mounts are useful when an existing encrypted host directory
is the source of truth:

```sh
mvmctl volume mount agent-sandbox \
  --volume project-data \
  --host /absolute/path/to/data \
  --guest /data
```

Use `--rw` only for trusted workflows:

```sh
mvmctl volume mount agent-sandbox \
  --volume project-data \
  --host /absolute/path/to/data \
  --guest /data \
  --rw
```

The host directory must live on encrypted backing storage. If encryption cannot
be verified, the command should fail closed.

## Copy instead of mount

For model-generated code, third-party scripts, and code interpreter workloads,
prefer copy-in/copy-out:

```sh
mvmctl cp ./input.json agent-sandbox:/work/input.json
mvmctl exec agent-sandbox -- python /work/task.py
mvmctl cp --max-bytes 16777216 agent-sandbox:/work/output.json ./output.json
```

Copy workflows reduce host exposure. Treat copied guest output as untrusted
input when it returns to the host.

## Snapshots versus volumes

Volumes preserve selected filesystem state. Snapshots preserve machine state.

| Capability | Volume | Snapshot or cold state |
| --- | --- | --- |
| Files only | Yes | Yes |
| Process memory | No | Yes |
| Running process state | No | Backend-specific |
| Easier to inspect | Yes | No |
| Smaller retention surface | Usually | Usually not |
| Can contain secrets | Yes | Yes |

Use a volume when you need durable files. Use cold mode or snapshots when you
need to resume a whole machine state.

## Agent workspace pattern

For a coding agent:

1. Create a named sandbox with a short TTL.
2. Copy the task input into `/work`.
3. Mount a managed volume at `/workspace` only if the agent needs durable state.
4. Keep network closed until the task has an approved egress need.
5. Copy out bounded results.
6. Stop, cold-pause, or destroy based on the retention decision.
7. Lock volumes and record receipt/audit identifiers.

Example:

```sh
mvmctl volume create coding-agent-work
mvmctl volume unlock coding-agent-work
mvmctl up ./agent-image --name coding-agent
mvmctl volume mount coding-agent --volume coding-agent-work --guest /workspace --rw
mvmctl cp ./task.json coding-agent:/work/task.json
mvmctl exec coding-agent --timeout 120 -- python /work/run_task.py
mvmctl cp --max-bytes 16777216 coding-agent:/work/result.json ./result.json
mvmctl volume unmount coding-agent /workspace
mvmctl machine stop coding-agent
mvmctl volume lock coding-agent-work
```

## Cleanup checklist

Before marking a stateful sandbox done:

- stop compute with `mvmctl machine stop` when it no longer needs to run;
- lock every managed volume;
- remove mounts that are no longer needed;
- delete snapshots that no longer have a recovery purpose;
- rotate credentials if generated code had access to them;
- store receipt/audit identifiers with the job record;
- review logs before attaching them to tickets, traces, or model context.

Stopping compute is not the same as erasing state. Volumes, logs, receipts,
snapshots, caches, copied files, and generated artifacts may remain.

## Related pages

- [Persistence, pause & resume](/working/persistence/)
- [Filesystem operations](/working/filesystem/)
- [Lifecycle states](/working/lifecycle-states/)
- [Cold mode](/working/cold-mode/)
- [Snapshots](/working/snapshots/)
- [Secrets and credentials](/guides/secrets-and-credentials/)
