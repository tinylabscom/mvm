---
title: Console
description: Interactive shell access to a running mvm microVM.
---

The console is the human debugging path into a running microVM. Use it when
you need a terminal, a shell prompt, or a one-off command with terminal
semantics.

Programmatic automation should usually use `mvmctl machine exec`, `mvmctl machine proc`, or
the SDK runtime surface instead. Those paths are easier to script, test, and
audit.

## Security model

Console access is intentionally gated by the image mode and launch policy.
Development images may expose a console; sealed production images should refuse
interactive shell access and rely on declared entrypoints, logs, guest RPC, and
audit records. This console gate is separate from the agent-verb grant: a
baked-entrypoint run on a non-dev profile can receive restricted ProdSafe verbs,
while a PTY always requires DevOnly verbs.

That distinction matters because an interactive shell is broad authority inside
the guest. It is useful for debugging, but it is not the default control plane
for production workloads.

## Common commands

```sh
mvmctl machine run --flake ./my-app --name devbox -d
mvmctl machine console devbox
mvmctl machine console devbox --command "uname -a"
```

Use `--command` for a one-shot shell command when you want console transport
but not an interactive session. Use `mvmctl machine exec` for normal automation.

## When to use which surface

| Need | Prefer |
| --- | --- |
| Human debugging | `mvmctl machine console <name>` |
| Scripted command execution | `mvmctl machine exec <name> -- <cmd>` |
| Process lifecycle control | `mvmctl machine proc start/ls/wait/kill` |
| File transfer | `mvmctl machine fs` or `mvmctl machine cp` |
| Service logs | `mvmctl machine logs <name>` |

`machine proc`, `machine fs`, and `machine cp` are advanced verbs: they work,
but they are hidden from `machine --help`.

## Related pages

- [Attach to a microVM](/console/attach/)
- [Run commands & processes](/working/commands/)
- [Filesystem operations](/working/filesystem/)
