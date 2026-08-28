---
title: Sandbox management
description: Create, inspect, stop, pause, resume, and clean up local mvm sandboxes.
---

Use `mvmctl` when you need the local management layer for sandboxes.

The advanced single-VM verbs used below (`pause`, `resume`, `checkpoint`, `fs`)
are hidden: they work, but they do not appear in `mvmctl machine --help`.

## Create or boot

```sh
mvmctl init ./agent-sandbox --preset python
mvmctl machine build --flake ./agent-sandbox
mvmctl machine run --flake ./agent-sandbox --name agent-sandbox -d
```

`mvmctl machine build` uses the builder VM for Linux image construction. `mvmctl machine run` boots the runtime guest from the built artifact.

## Inspect

```sh
mvmctl machine ls
mvmctl machine boot-report agent-sandbox
mvmctl machine logs agent-sandbox
```

Use JSON output where commands support it when integrating with tooling.

## Operate

```sh
mvmctl machine exec agent-sandbox -- python /work/task.py
mvmctl machine fs ls agent-sandbox /work
```

Command execution and file operations cross trust boundaries. Keep command
args explicit and file paths narrow. Declare ingress before boot with
`machine run --port`.

## Preserve state

```sh
mvmctl machine pause agent-sandbox
mvmctl machine resume agent-sandbox
```

Full-VM memory checkpoints (vm-full class) need a backend at the `save-restore` snapshot tier or better — today `hvf` and `apple-container`. Check `mvmctl doctor` for the authoritative capability before requesting them:

```sh
mvmctl machine checkpoint create agent-sandbox --class vm-full
mvmctl machine checkpoint restore <checkpoint-id>
```

Snapshots can contain memory, files, and runtime credentials. Apply retention and deletion policy.

## Stop and clean up

```sh
mvmctl machine stop agent-sandbox
mvmctl env cleanup
```

Stopping compute is not the same as deleting all state. Check manifests, volumes, snapshots, and cache entries when you need stronger cleanup.
