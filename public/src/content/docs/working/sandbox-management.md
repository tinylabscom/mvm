---
title: Sandbox management
description: Create, inspect, stop, pause, resume, and clean up local mvm sandboxes.
---

Use `mvmctl` when you need the local management layer for sandboxes.

## Create or boot

```sh
mvmctl init ./agent-sandbox --preset python
mvmctl build ./agent-sandbox
mvmctl up ./agent-sandbox --name agent-sandbox
```

`mvmctl build` uses the builder VM for Linux image construction. `mvmctl up` boots the runtime guest from the built artifact.

## Inspect

```sh
mvmctl ls
mvmctl boot-report agent-sandbox
mvmctl machine logs agent-sandbox
```

Use JSON output where commands support it when integrating with tooling.

## Operate

```sh
mvmctl exec agent-sandbox -- python /work/task.py
mvmctl machine fs ls agent-sandbox /work
mvmctl forward agent-sandbox -p 8080:8080
```

Command execution, file operations, and port forwarding cross trust boundaries. Keep command args explicit, file paths narrow, and ports intentional.

## Preserve state

```sh
mvmctl pause agent-sandbox
mvmctl resume agent-sandbox
```

For Vz memory checkpoints (vm-full class):

```sh
mvmctl checkpoint create agent-sandbox --class vm-full
mvmctl checkpoint restore agent-sandbox --name <checkpoint-name>
```

Snapshots can contain memory, files, and runtime credentials. Apply retention and deletion policy.

## Stop and clean up

```sh
mvmctl machine stop agent-sandbox
mvmctl cleanup
```

Stopping compute is not the same as deleting all state. Check manifests, volumes, snapshots, and cache entries when you need stronger cleanup.
