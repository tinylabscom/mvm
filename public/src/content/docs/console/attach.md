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

## Detach and reattach

A console session outlives its client. Detaching leaves the shell running, and
the next `machine console` attaches to it again:

```sh
mvmctl machine console devbox      # starts the session
# ... press Enter, then ~d
mvmctl machine console devbox      # reattaches; recent output is replayed
mvmctl machine attach devbox       # the same verb under its lifecycle name
```

While no client is attached, the guest agent keeps the shell's most recent
output — up to 1 MiB — and replays it to the next client before live output
resumes. The window size of the new terminal is applied on reattach, so a
full-screen program that redraws on resize repaints for it.

Two escapes are handled by `mvmctl` and never sent to the guest. Press Enter
first, then:

- `~d` detaches. The shell keeps running.
- `~.` ends the session. The shell is hung up, and the console exits.

Closing the terminal or losing the connection detaches; it does not end the
shell. A session ends when its shell exits, when it is ended with `~.`, when
the VM stops, or — if it was started with `--detach-timeout <seconds>` — after
that long with no client attached.

One client is attached at a time. A second `machine console` is refused with
the session named and both ways out:

```sh
mvmctl machine console devbox --list    # attached, detached (and for how long), or exited
mvmctl machine detach devbox            # disconnect whoever is attached
mvmctl machine console devbox --force   # take the session over from them
```

`--force` only disconnects the other client; it does not restart the shell or
bypass any check. The machine has one shared console session: an interactive
`machine exec -t -- <command>` or `machine run -it -- <command>` gets its own
session for that command and is refused while the shared shell is running.

## Access rules

Console behavior depends on the active backend, image mode, and launch policy:

- Development images and development-profile runs may expose PTY-backed shell access.
- Sealed images refuse interactive console access, and refuse reattach, detach,
  and listing the same way: all of them are the same dev-only, grant-gated
  guest-agent verbs as the first attach.
- A baked-entrypoint run on a non-dev profile can receive restricted ProdSafe
  agent verbs, but requesting a PTY still requires DevOnly verbs.
- Each attach, reattach, take-over, detach, and session end is recorded in the
  host audit log alongside the guest-agent request that caused it.

Press `Ctrl+C` to interrupt the foreground command inside the guest; it is
forwarded, not handled by `mvmctl`. Stopping the machine from another terminal
also ends the attached console cleanly; the expected control-channel EOF
during teardown is not reported as a protocol failure.

When a backend cannot provide a console, use `mvmctl machine logs`, `mvmctl machine exec`, and
guest readiness probes to debug the workload.

## Security checklist

- Do not treat console access as a production management API.
- Avoid pasting secrets into an interactive shell.
- Prefer short-lived dev sandboxes for debugging third-party code.
- Stop or cold-pause the VM when the debugging session is over.
- Capture relevant state with explicit files or logs instead of relying on
  terminal scrollback: the replay buffer is bounded and lives only in guest
  memory.
- End a session you no longer need with `~.` rather than leaving it detached.
