---
title: Persistent workspaces
description: Use encrypted volumes, copy workflows, snapshots, and cleanup policies for stateful sandboxes.
---

:::note[Hidden verbs]
`machine volume`, `machine cp` and `machine fs` are all marked hidden in the
CLI: they work, but they do not appear in `mvmctl machine --help`.

Guest mount paths must be under `/data` or `/work` — those are the only two
allow-roots. `/cache`, `/workspace` and anything under `/mnt` are refused.
:::

Persistent state is useful for agents, browser sessions, caches, databases, and
long-running services. It is also where sensitive data accumulates. Choose the
smallest state mechanism that fits the workflow, and make the retention policy
explicit before the sandbox starts.

## Pick a state mechanism

| Need | Use | Security posture |
| --- | --- | --- |
| One input file or result file | `mvmctl machine cp` or `mvmctl machine fs` | Narrowest boundary; preferred for generated-code tasks. |
| Read-only fixtures | `mvmctl run --mount ...:ro` | Host data is exposed but not writable by the guest. |
| Local dev edits | `mvmctl machine cp` or managed volume | Explicit copy or encrypted persistent state; no writable transient host share. |
| Stateful app data | managed encrypted volume | Encrypted at rest when locked; plaintext exists while unlocked. |
| Fast retry or recovery | snapshot or cold mode | Can contain memory, files, processes, prompts, and credentials. |

Do not use a snapshot when a narrow output file is enough. Do not use a writable
host share when a managed volume is enough.

## Managed encrypted volume

Create a managed local volume:

```sh
mvmctl machine volume create agent-cache
```

Managed volumes are locked by default. Unlock before mounting:

```sh
mvmctl machine volume unlock agent-cache
```

Mount the unlocked volume into a running sandbox:

```sh
mvmctl machine volume mount agent-sandbox \
  --volume agent-cache \
  --guest /data/cache \
  --rw
```

List mounts:

```sh
mvmctl machine volume ls agent-sandbox
```

Unmount and lock when the workflow is done:

```sh
mvmctl machine volume unmount agent-sandbox /data/cache
mvmctl machine volume lock agent-cache
```

Security rules:

- `volume mount` refuses a managed volume while it is locked;
- `volume unlock` creates plaintext state that must be treated as sensitive;
- `volume lock` reseals the volume and removes plaintext after use;
- keep volume names scoped to the workflow or project;
- do not mount the same writable volume into unrelated sandboxes unless sharing
  state is the intent.

## Durable tenant volumes through mvmd

Use remote mode when mvmd owns the tenant, storage provider, encryption keys,
quota, and attachment policy. Configure the authenticated client without
putting the bearer token on the command line:

```sh
export MVM_GATEWAY_URL=https://mvmd.example.com
export MVM_TENANT_ID=tenant-acme
read -rsp "mvmd bearer token: " MVM_GATEWAY_TOKEN
export MVM_GATEWAY_TOKEN
```

The client refuses cleartext HTTP except for a loopback sidecar. Provider
credentials never enter `mvmctl`; mvmd resolves them from the registered
`StorageBucket`.

Create and list durable volumes:

```sh
mvmctl machine volume create database --size 20G --remote --bucket bucket-primary
mvmctl machine volume catalog --remote --json
```

The API allocates whole GiB, so smaller human-readable sizes round up to one
GiB. Use the returned volume ID for attachment and checkpoint operations:

```sh
mvmctl machine volume mount worker-1 --volume vol-123 --guest /data --rw --remote
mvmctl machine volume checkpoint vol-123 before-upgrade --remote
mvmctl machine volume restore vol-123 snap-456 --target database-recovered --remote
mvmctl machine volume unmount worker-1 /data --remote
mvmctl machine volume delete vol-123 --remote
```

Remote restore always creates a new volume from a pinned, ready checkpoint; it
does not overwrite the source volume. Delete is refused while a volume remains
attached or retains checkpoints. Attachment conflicts, quota failures,
authorization failures, provider outages, and integrity refusals are returned
as errors rather than falling back to the local registry.

## Host-backed mounts

Ad-hoc host-backed mounts seed a machine from an existing encrypted host
directory. The directory is **snapshotted into a content-addressed ext4 image**
and attached as a block device; it is not a live view. `machine start` hashes
the source tree and refreshes the registered snapshot when its contents or
guest-visible metadata changed. Host edits made while the machine is running
therefore become visible after the next stop/start. If the source directory is
missing at start, the launch refuses instead of silently using stale bytes.

This is the same treatment `mvmctl machine run --mount HOST:/GUEST` gives a
transient run. Both paths share the same verified mount-image cache, and for
the same reason: no workload backend has a virtio-fs device, so a live
host-directory share cannot be expressed at all.

```sh
mvmctl machine volume mount agent-sandbox \
  --volume project-data \
  --host /absolute/path/to/data \
  --guest /data
```

Use `--rw` only for trusted workflows:

```sh
mvmctl machine volume mount agent-sandbox \
  --volume project-data \
  --host /absolute/path/to/data \
  --guest /data \
  --rw
```

Both the host directory and mvm's local snapshot destination must live on
encrypted backing storage. If either check cannot verify encryption, the
command fails closed before source bytes are written.

## Copy instead of mount

For model-generated code, third-party scripts, and code interpreter workloads,
prefer copy-in/copy-out:

```sh
mvmctl machine cp ./input.json agent-sandbox:/work/input.json
mvmctl machine exec agent-sandbox -- python /work/task.py
mvmctl machine cp --max-bytes 16777216 agent-sandbox:/work/output.json ./output.json
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
3. Mount a managed volume at `/data/workspace` only if the agent needs durable state.
4. Keep network closed until the task has an approved egress need.
5. Copy out bounded results.
6. Stop, cold-pause, or destroy based on the retention decision.
7. Lock volumes and record receipt/audit identifiers.

Example:

```sh
mvmctl machine volume create coding-agent-work
mvmctl machine volume unlock coding-agent-work
mvmctl machine run --flake ./agent-image --name coding-agent -d
mvmctl machine volume mount coding-agent --volume coding-agent-work --guest /data/workspace --rw
mvmctl machine cp ./task.json coding-agent:/work/task.json
mvmctl machine exec coding-agent -- python /work/run_task.py
mvmctl machine cp --max-bytes 16777216 coding-agent:/work/result.json ./result.json
mvmctl machine volume unmount coding-agent /data/workspace
mvmctl machine stop coding-agent
mvmctl machine volume lock coding-agent-work
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
