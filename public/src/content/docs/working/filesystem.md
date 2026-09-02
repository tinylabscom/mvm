---
title: Filesystem operations
description: Move files across the host and guest boundary safely.
---

Filesystem operations cross a trust boundary. Keep paths narrow, copy only the files required for the task, and avoid broad host mounts for generated or third-party code.

`machine cp` and `machine volume` are hidden advanced verbs: they work, but they
do not appear in `mvmctl machine --help`.

## Copy files

```sh
mvmctl machine cp ./input.json agent-sandbox:/work/input.json
mvmctl machine cp agent-sandbox:/work/output.json ./output.json
```

Useful options:

```sh
mvmctl machine cp --create-parents ./input.json agent-sandbox:/work/in/input.json
mvmctl machine cp --force agent-sandbox:/work/output.json ./output.json
mvmctl machine cp --max-bytes 16777216 agent-sandbox:/work/output.json ./output.json
```

Exactly one endpoint uses `VM:/absolute/path` form. Guest paths are validated by the guest filesystem policy before read or write.

## Use controlled mounts

For short-lived one-shot runs:

```sh
mvmctl run --mount ./fixtures:/work:ro -- python /work/test.py
```

Transient host-directory shares are read-only. Use `mvmctl machine cp` or a managed
volume when the guest must produce host-visible changes.

## Volumes

Managed local volumes are encrypted at rest by `mvm` and must be unlocked before mounting:

```sh
mvmctl machine volume create agent-cache
mvmctl machine volume unlock agent-cache
mvmctl machine volume mount agent-sandbox --volume agent-cache --guest /cache --rw
```

Lock the volume again after use:

```sh
mvmctl machine volume lock agent-cache
```

See [Persistent workspaces](/guides/persistent-workspaces/) for volume lifecycle, snapshots versus volumes, and cleanup policy.

## Security notes

- Do not mount `$HOME`, credential directories, SSH agents, cloud config, or browser profiles into untrusted guests.
- Prefer copy-in/copy-out over writable mounts for agent tasks.
- Use byte caps for machine-driven downloads.
- Treat guest output files as untrusted input when reading them on the host.
