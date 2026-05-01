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

> `mvmctl exec` is **dev-mode only** -- the guest agent's Exec handler is
> compiled in only when the `dev-shell` Cargo feature is enabled. Production
> guest builds omit the feature, so the handler is not present in the binary
> at all and `exec` is physically unavailable. It is not meant for production
> workloads; use `mvmctl up` (or `mvmd`) for those.

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

- Defined by [`nix/images/default-tenant/`](https://github.com/auser/mvm/tree/main/nix/images/default-tenant)
  in the repo: a minimal `mkGuest` rootfs with busybox and the auto-included
  guest agent. No extra packages.
- Built via Nix on first use, cached at `~/.cache/mvm/default-microvm/`
  (kernel + rootfs).
- Identical for every invocation that doesn't pass `--template`.

If your host has no working Nix builder, `mvmctl exec` will fail with a
clear error. Pass `--template <name>` (a registered template you've
already built) to skip the Nix path.

## Sharing host directories: `--add-dir`

`--add-dir HOST:GUEST[:MODE]` materializes the host directory into a
small ext4 image, attaches it as an extra Firecracker drive, and mounts
it at `GUEST` inside the microVM. `MODE` is `ro` (default) or `rw`. The
flag is repeatable.

### Read-only (default)

```bash
echo "hello" > /tmp/foo
mvmctl exec --add-dir /tmp:/host -- cat /host/foo     # prints "hello"
```

The guest sees the contents at boot. Writes inside the guest are
discarded when the microVM is torn down.

### Writable: `:rw`

```bash
mvmctl exec --add-dir .:/work:rw -- sh -c 'echo result > /work/output.txt'
cat ./output.txt       # "result" — written by the guest
```

The mount is read-write inside the guest. Once the command exits and
the VM stops, the ext4 image is mounted host-side and `rsync -aH
--delete`-ed back over the host directory. New files appear, modified
files are updated, and files removed inside the guest are removed on
the host.

This is the equivalent of cco's writable project directory --
exactly what you want for a coding agent that needs to edit your repo.

#### Trade-offs

See [ADR-002](/contributing/adr/002-writable-add-dir/) for the full
design rationale. Highlights for v1:

- **No in-flight host visibility.** Guest writes only land on the host
  *after* the command exits. Host-side `tail -f`-style tooling won't see
  partial output.
- **Last-writer-wins on concurrent host writes.** If you modify a file
  on the host while the guest is also modifying it, the guest's version
  overwrites the host's at teardown. v1 is for agentic flows where the
  host isn't editing the same directory in parallel.
- **No incremental durability.** A 30-minute task that crashes at
  minute 29 loses all guest writes -- the rsync only runs after a clean
  exit. Keep `mvmctl exec` for short-lived invocations; long-lived
  workloads belong in `mvmd`.
- **Guest deletes propagate.** The rsync uses `--delete`, so files
  removed inside the guest are removed on the host.

For a live two-way mount (visible during the run, no clobber semantics),
virtio-fs is on the v2 roadmap once Firecracker ships upstream
`vhost-user-fs` support.

### Multiple shares

Modes are independent per directory:

```bash
mvmctl exec \
  --add-dir ./src:/work:rw \
  --add-dir ~/.cargo:/root/.cargo:ro \
  -- cargo build --manifest-path /work/Cargo.toml
```

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
to declare workloads, you can hand `mvmctl exec` either the `launch.json`
artifact from `mvmforge compile` or the Workload IR manifest from
`mvmforge emit` — `--launch-plan` accepts both shapes and auto-detects:

```bash
mvmforge compile manifest.json --out ./build
mvmctl exec --launch-plan ./build/launch.json
```

```bash
mvmforge emit app.py > manifest.json
mvmctl exec --launch-plan manifest.json
```

Only the entrypoint is consumed in v1; image selection still comes from
`--template` or the bundled default.

**LaunchPlan artifact** (`mvmforge compile`'s `launch.json` output):

```json
{
  "artifact_format_version": "1.0",
  "workload_id": "hello",
  "entrypoint": {
    "command": ["python", "main.py"],
    "working_dir": "/app",
    "env": { "PORT": "8080" }
  },
  "env": { "LOG_LEVEL": "info" }
}
```

**Workload IR manifest** (`mvmforge emit` stdout):

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

For long-running workloads, prefer `mvmforge up` (or
`mvmctl up --flake <artifact-dir>`): mvmforge bakes the entrypoint into
the generated flake's `services.<id>.command`, and mvm's PID-1 init
supervises it across reboots.

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

- **Dev-mode only.** `mvmctl exec` requires a guest agent built with the
  `dev-shell` Cargo feature, which is the default for the dev images
  `mvmctl` ships with. Production guest images omit the feature and the
  Exec handler is physically absent from the binary.
- **Network access.** The guest gets the same network configuration
  any other transient VM gets -- if your `--template` exposes outbound
  internet, so does `mvmctl exec` from that template.
- **Stdin** is currently *not* forwarded to the guest. Pipe data via a
  `--add-dir`-shared file instead. Streaming stdin is a future
  improvement.
- **Persistent state** doesn't survive teardown beyond what `:rw`
  `--add-dir` rsyncs back. For larger or longer-lived state, use
  `mvmctl up` with a persistent volume.

## See also

- [CLI reference: One-shot Exec](/reference/cli-commands/#one-shot-exec)
- [Templates guide](/guides/templates/) -- build a reusable base image
  to point `mvmctl exec --template` at
- [Quick Start](/getting-started/quickstart/#7-sandboxed-one-shot-commands)
