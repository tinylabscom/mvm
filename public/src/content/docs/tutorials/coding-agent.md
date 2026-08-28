---
title: Coding agent
description: Run coding-agent tasks in a microVM with explicit filesystem, network, and persistence boundaries.
---

Use this pattern when an agent needs to inspect or modify a project but should not run directly in the host process.

## Prepare a workspace

Create a narrow project directory for the task. Avoid mounting `$HOME`, SSH agent sockets, cloud credentials, browser profiles, or unrelated repositories.

```sh
mkdir -p /tmp/mvm-agent-work
cp -R ./src /tmp/mvm-agent-work/src
```

## Build the runtime

Prefer a Nix flake that declares the tools the agent needs:

```sh
mvmctl machine build --flake .
```

For local development through this repository, the builder VM is the Linux build boundary. The runtime guest later boots the built artifact.

## Run the task

```sh
mvmctl machine run --flake . --name coding-agent -d
mvmctl machine exec coding-agent -- bash -lc 'cd /work && python task.py'
```

`-d` is what keeps the machine alive after the command returns; `--name` alone
does not, and `machine run` with neither `-d` nor a trailing `-- <cmd>` refuses
to start.

Use file transfer or a narrow mount for input/output. Keep generated patches and logs outside broad host write access.

## Network policy

Start with no egress for code analysis. If the task needs registries or model APIs, add only those destinations and record why they are needed.

## Persist or discard state

Use cold mode only when the agent needs to resume an environment with installed packages, caches, or intermediate files.

```sh
mvmctl machine pause coding-agent
mvmctl machine resume coding-agent
```

`machine pause` and `machine resume` are advanced verbs: they work, but they
are hidden from `machine --help`.

Use `mvmctl machine stop` and cleanup commands when the task is complete.

## Security checklist

- Do not pass long-lived credentials as plaintext environment variables.
- Keep host mounts narrow and read-only unless write access is required.
- Treat command output and logs as sensitive.
- Keep network allowlists task-specific.
- Save snapshots only when the task requires recoverable state.
