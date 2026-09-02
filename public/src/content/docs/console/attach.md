---
title: Attach to a microVM
description: Open an interactive shell to a running microVM.
---

Start a development microVM, then attach:

```sh
mvmctl machine run --flake ./my-app --name devbox -d
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
mvmctl machine exec devbox -- id
mvmctl machine proc start devbox -- python /work/task.py
```

`machine proc` is an advanced verb: it works, but it is hidden from
`machine --help`.

## Attach behavior

Console behavior depends on the active backend, image mode, and launch policy:

- Development images and development-profile runs may expose PTY-backed shell access.
- Sealed images should refuse interactive console access.
- A baked-entrypoint run on a non-dev profile can receive restricted ProdSafe
  agent verbs, but requesting a PTY still requires DevOnly verbs.
- Terminal resize, signal forwarding, and scrollback are backend-specific.
- Console sessions end when the VM stops.

Press `Ctrl+C` to interrupt the foreground command inside the guest. To end the
console locally even when the guest command does not respond, press Enter and
then type `~.`. The escape is handled by `mvmctl` and is not sent to the guest.
Stopping the machine from another terminal also ends the attached console
cleanly; the expected control-channel EOF during teardown is not reported as a
protocol failure.

When a backend cannot provide a console, use `mvmctl machine logs`, `mvmctl machine exec`, and
guest readiness probes to debug the workload.

## Security checklist

- Do not treat console access as a production management API.
- Avoid pasting secrets into an interactive shell.
- Prefer short-lived dev sandboxes for debugging third-party code.
- Stop or cold-pause the VM when the debugging session is over.
- Capture relevant state with explicit files or logs instead of relying on
  terminal scrollback.
