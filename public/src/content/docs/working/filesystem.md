---
title: Filesystem operations
description: Move files across the host and guest boundary safely.
---

Filesystem operations cross a trust boundary. Keep paths narrow, copy only the files required for the task, and avoid broad host mounts for generated or third-party code.

## Copy files

```sh
mvmctl cp ./input.json agent-sandbox:/work/input.json
mvmctl cp agent-sandbox:/work/output.json ./output.json
```

Useful options:

```sh
mvmctl cp --create-parents ./input.json agent-sandbox:/work/in/input.json
mvmctl cp --force agent-sandbox:/work/output.json ./output.json
mvmctl cp --max-bytes 16777216 agent-sandbox:/work/output.json ./output.json
```

Exactly one endpoint uses `VM:/absolute/path` form. Guest paths are validated by the guest filesystem policy before read or write.

## Use controlled mounts

For short-lived one-shot runs:

```sh
mvmctl run --mount ./fixtures:/work:ro -- python /work/test.py
```

Transient host-directory shares are read-only. Use `mvmctl cp` or a managed
volume when the guest must produce host-visible changes.

## Volumes

Managed local volumes are encrypted at rest by `mvm` and must be unlocked before mounting:

```sh
mvmctl volume create agent-cache
mvmctl volume unlock agent-cache
mvmctl volume mount agent-sandbox --volume agent-cache --guest /cache --rw
```

Lock the volume again after use:

```sh
mvmctl volume lock agent-cache
```

See [Persistent workspaces](/guides/persistent-workspaces/) for volume lifecycle, snapshots versus volumes, and cleanup policy.

## Security notes

- Do not mount `$HOME`, credential directories, SSH agents, cloud config, or browser profiles into untrusted guests.
- Prefer copy-in/copy-out over writable mounts for agent tasks.
- Use byte caps for machine-driven downloads.
- Treat guest output files as untrusted input when reading them on the host.
