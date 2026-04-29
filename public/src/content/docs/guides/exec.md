---
title: Sandboxed Exec
description: Run a single command inside a fresh microVM and tear it down on exit.
---

`mvmctl exec` is the "send off a single task in a microVM" workflow.
It boots a fresh transient Firecracker microVM, runs one command via
the guest agent, streams stdout/stderr back to your terminal, propagates
the exit code, and tears the VM down -- success, failure, or Ctrl-C.

Think `docker run --rm`, but with a microVM as the isolation boundary.

```bash
mvmctl exec -- uname -a
mvmctl exec --add-dir .:/work -- ls /work
mvmctl exec --template my-tpl -- /bin/true
mvmctl exec --launch-plan ./launch.json
```

> `mvmctl exec` is **dev-mode only** -- it inherits the existing
> `policy.access.debug_exec` gate enforced by the guest agent. It is not
> meant for production workloads; use `mvmctl up` (or `mvmd`) for those.

## When to use it

- **Reach for `mvmctl exec`** when you want to run an untrusted binary,
  a build script, an LLM-generated command, or any one-shot task that
  benefits from a strong isolation boundary but doesn't justify standing
  up a long-running VM.
- **Reach for `mvmctl up`** when you want a long-running VM you can
  re-enter, share state with, or expose ports from.
- **Reach for `mvmctl console <vm> --command "..."`** when you already
  have a VM running and want to run something inside it without a fresh
  boot.

## The bundled default image

If you don't pass `--template` or `--flake`, `mvmctl exec` boots the
bundled default image:

- Defined by [`nix/default-microvm/`](https://github.com/auser/mvm/tree/main/nix/default-microvm)
  in the repo: a minimal `mkGuest` rootfs with busybox and the auto-included
  guest agent. No extra packages.
- Built via Nix on first use, cached at `~/.cache/mvm/default-microvm/`
  (kernel + rootfs).
- Identical for every invocation that doesn't pass `--template`.

If your host has no working Nix builder, `mvmctl exec` will fail with a
clear error. Pass `--template <name>` (a registered template you've
already built) to skip the Nix path.

## Sharing host directories: `--add-dir`

`--add-dir HOST:GUEST` materializes the host directory into a small ext4
image, attaches it as an extra Firecracker drive, and mounts it
**read-only** at `GUEST` inside the microVM. Writes inside the guest are
discarded on teardown.

```bash
echo "hello" > /tmp/foo
mvmctl exec --add-dir /tmp:/host -- cat /host/foo     # prints "hello"
```

The flag is repeatable: pass multiple `--add-dir` to mount several host
paths. v1 is read-only only -- writable mounts (virtio-fs / 9p) are
tracked separately in [issue #6](https://github.com/auser/mvm/issues/6).

## Injecting environment variables: `--env`

```bash
mvmctl exec --env FOO=bar --env BAZ=qux -- env | grep -E '^(FOO|BAZ)='
```

`--env` (or `-e`) is repeatable. When used together with `--launch-plan`,
CLI `--env` overrides any env vars the launch plan carries (see below).

## Snapshot restore (registered templates)

When you pass `--template <name>` and that template has a captured
snapshot, `mvmctl exec` restores from the snapshot instead of cold-booting.
This skips the kernel boot and service-start cost -- typically sub-second
on Linux/KVM.

The snapshot path activates only when:

- the image source is a registered template (the bundled default has no
  template snapshot to restore from), AND
- the request has **no** `--add-dir` extras (extra drives would mismatch
  the snapshot's recorded layout), AND
- the active backend reports snapshot support.

On macOS / Lima QEMU, vsock snapshots return `os error 95` (EOPNOTSUPP);
restore failures fall back to cold boot with a warning rather than
aborting. The harder branch -- parameterized snapshots that allow
`--add-dir` -- is tracked in [issue #7](https://github.com/auser/mvm/issues/7).

## Resource controls

```bash
mvmctl exec --cpus 4 --memory 1G -- ./benchmark.sh
mvmctl exec --timeout 300 -- ./long-running-task.sh
```

Defaults: 2 vCPUs, 512 MiB, 60-second timeout per command.

## Driving from an mvmforge launch plan

If you're using [mvmforge](https://github.com/tinylabscom/decorationer)
to declare workloads, you can hand `mvmctl exec` a `launch.json` and it
will invoke the entrypoint directly:

```bash
mvmforge compile app.py --out ./build
mvmctl exec --launch-plan ./build/launch.json
```

`mvmctl exec` reads a single-app subset of mvmforge's v0 Workload IR.
Only the entrypoint is consumed in v1; image selection still comes from
`--template` or the bundled default.

```json
{
  "apps": [
    {
      "name": "hello",
      "entrypoint": {
        "command": ["python", "main.py"],
        "working_dir": "/app",
        "env": { "PORT": "8080" }
      },
      "env": { "LOG_LEVEL": "info" }
    }
  ]
}
```

Multi-app launch plans are rejected -- that's an orchestration concern
that belongs in `mvmd`, not in `mvmctl exec`. Env precedence (lowest →
highest):

1. `apps[].env`
2. `apps[].entrypoint.env`
3. CLI `--env` (always wins)

`--launch-plan` is mutually exclusive with a trailing argv.

## Teardown semantics

- **Normal exit**: VM is stopped and the staging dir for `--add-dir`
  images is cleaned up.
- **Non-zero exit**: same as normal exit; `mvmctl exec` propagates the
  guest's exit code.
- **Ctrl-C**: a SIGINT handler triggers teardown so the Firecracker
  process and any tap interface don't get orphaned.
- **Hard kill** (`kill -9` on `mvmctl exec` itself): teardown is
  best-effort; you may need `mvmctl ps` and `mvmctl down <name>` to
  clean up. Each transient VM is named `exec-<pid>-<rand>` so they're
  easy to spot.

## Limits

- **Dev-mode only.** `mvmctl exec` requires `policy.access.debug_exec`
  to be on, which is the default in the dev mode the rest of `mvmctl`
  ships with.
- **Network access.** The guest gets the same network configuration
  any other transient VM gets -- if your `--template` exposes outbound
  internet, so does `mvmctl exec` from that template.
- **Stdin** is currently *not* forwarded to the guest. Pipe data via a
  `--add-dir`-shared file instead. Streaming stdin is a future
  improvement.
- **Persistent state** doesn't survive teardown. If you need to keep
  results, write them to a host path via a future writable
  `--add-dir` (tracked in [#6](https://github.com/auser/mvm/issues/6))
  or use `mvmctl up` for a long-running VM with a persistent volume.

## See also

- [CLI reference: One-shot Exec](/reference/cli-commands/#one-shot-exec)
- [Templates guide](/guides/templates/) -- build a reusable base image
  to point `mvmctl exec --template` at
- [Quick Start](/getting-started/quickstart/#7-sandboxed-one-shot-commands)
