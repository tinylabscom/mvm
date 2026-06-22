---
title: Interactive terminal
description: Attach to a sandbox intentionally without making SSH the default control path.
---

Interactive terminals are useful for debugging, but they are not the default product control plane.

Use the existing console and guest RPC surfaces:

- [Attach to a microVM](/console/attach/)
- [Run commands and processes](/working/commands/)
- [Filesystem operations](/working/filesystem/)

## Recommended flow

```sh
mvmctl up ./mvm.toml --name debug-vm
mvmctl machine console debug-vm
mvmctl machine logs debug-vm -f
```

## Security notes

- Prefer vsock/control-plane operations over SSH.
- Keep debug instances separate from production policy.
- Tear down or cold-store state explicitly after debugging.
- Do not paste long-lived credentials into an interactive shell.
