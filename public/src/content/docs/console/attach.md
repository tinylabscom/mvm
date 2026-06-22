---
title: Attach to a microVM
description: Open an interactive shell to a running microVM.
---

Start a development microVM, then attach:

```sh
mvmctl up ./my-app --name devbox
mvmctl machine console devbox
```

The console uses the project's guest-control path rather than requiring SSH
inside the guest. That keeps the base image smaller and avoids introducing a
second always-on remote access service.

## One-shot command

```sh
mvmctl machine console devbox --command "id && uname -a"
```

Use this for terminal-shaped checks. For normal automation, prefer:

```sh
mvmctl exec devbox -- id
mvmctl proc start devbox -- python /work/task.py
```

## Attach behavior

Console behavior depends on the active backend and image mode:

- Development images may expose PTY-backed shell access.
- Sealed images should refuse interactive console access.
- Terminal resize, signal forwarding, and scrollback are backend-specific.
- Console sessions end when the VM stops.

When a backend cannot provide a console, use `mvmctl machine logs`, `mvmctl exec`, and
guest readiness probes to debug the workload.

## Security checklist

- Do not treat console access as a production management API.
- Avoid pasting secrets into an interactive shell.
- Prefer short-lived dev sandboxes for debugging third-party code.
- Stop or cold-pause the VM when the debugging session is over.
- Capture relevant state with explicit files or logs instead of relying on
  terminal scrollback.
