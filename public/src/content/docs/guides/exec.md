---
title: Sandboxed Exec
description: Run a single command inside a fresh microVM and tear it down on exit.
---

Running a single command in a fresh transient microVM is the
`mvmctl machine run -- <cmd>` workflow: it boots a microVM from a source you
name (`--image`, `--flake`, or `--manifest`), runs one command via the guest
agent, streams stdout/stderr back to your terminal, propagates the exit code,
and tears the VM down -- success, failure, or Ctrl-C.

Think `docker run --rm`, but with a microVM as the isolation boundary.

```bash
mvmctl machine run --image alpine -- uname -a
mvmctl machine run --flake . --volume .:/work -- ls /work
mvmctl machine run --manifest my-tpl -- /bin/true
```

> Overriding the guest's argv (a trailing `-- <cmd>`) is a **dev-tier**
> capability. A sealed production image refuses it (claim 15) — its entrypoint
> is fixed and there is no interactive command surface. Use `--image`/`--flake`
> dev builds for ad-hoc commands; production workloads run their baked
> entrypoint (`machine run --entrypoint`) or go through `mvmd`.

## When to use it

- **Reach for a transient `mvmctl machine run -- <cmd>`** when you want to run
  an untrusted binary, a build script, an LLM-generated command, or any
  one-shot task that benefits from a strong isolation boundary but doesn't
  justify a long-running VM.
- **Reach for a persistent `mvmctl machine run --name <n> -d`** when you want a
  VM you can re-enter, share state with, or forward ports from.
- **Reach for `mvmctl machine exec <n> -- <cmd>`** when you already have a named
  VM running and want to run something inside it without a fresh boot.

## Choosing a source

`mvmctl machine run` always boots from a source you name — there is no bundled
default image:

- `--image <ref>` — an OCI image, pulled and cached (no host Nix, no flake).
  The fastest path for ad-hoc commands.
- `--flake <ref>` — a Nix flake built in the builder VM. Customize the guest
  with `mvm.lib.<system>.mkGuest` (see
  [Building MicroVM Images](/guides/building-microvm-images) +
  [Dev Image](/guides/dev-image)).
- `--manifest <name>` — a pre-built manifest slot or registered template, which
  skips the build step entirely.

## Sharing host directories: `--volume`

`--volume HOST:GUEST[:MODE]` shares a host directory into the guest at
`GUEST`. `MODE` is `ro` (default) or `rw`; a writable share requires
`--profile dev` or `--profile permissive`. The flag is repeatable.

### Read-only (default)

```bash
echo "hello" > /tmp/foo
mvmctl machine run --image alpine --volume /tmp:/host -- cat /host/foo     # prints "hello"
```

### Writable: `:rw`

```bash
mvmctl machine run --flake . --profile dev --volume .:/work:rw -- sh -c 'echo result > /work/output.txt'
cat ./output.txt       # "result" — written by the guest
```

A writable share lets the guest edit host files under `GUEST` — exactly what
you want for a coding agent that needs to edit your repo. For the durability
and host-visibility semantics of the current volume backend, see the
[machine volume docs](/guides/machine-use-cases/).

### Multiple shares

Modes are independent per directory:

```bash
mvmctl machine run --flake . --profile dev \
  --volume ./src:/work:rw \
  --volume ~/.cargo:/root/.cargo:ro \
  -- cargo build --manifest-path /work/Cargo.toml
```

## Injecting environment variables: `--env`

```bash
mvmctl machine run --image alpine -e FOO=bar -e BAZ=qux -- env | grep -E '^(FOO|BAZ)='
```

`--env` (or `-e`) is repeatable. When used together with `--launch-plan`,
CLI `--env` overrides any env vars the launch plan carries (see below).

## Snapshot restore (registered templates)

When you pass `--manifest <name>` and that template has a captured
snapshot, `mvmctl machine run` restores from the snapshot instead of cold-booting.
This skips the kernel boot and service-start cost -- typically sub-second
on Linux/KVM.

The snapshot path activates only when:

- the image source is a registered template (an OCI image or ad-hoc flake has no
  template snapshot to restore from), AND
- the request has **no** `--volume` extras (extra drives would mismatch
  the snapshot's recorded layout), AND
- the active backend reports snapshot support.

On macOS backends without Firecracker (HVF, Vz, libkrun), vsock snapshots return `os error 95` (EOPNOTSUPP);
restore failures fall back to cold boot with a warning rather than
aborting. The harder branch -- parameterized snapshots that allow
`--volume` -- is tracked in [issue #7](https://github.com/tinylabscom/mvm/issues/7).

## Resource controls

```bash
mvmctl machine run --flake . --cpus 4 --memory 1G -- ./benchmark.sh
mvmctl machine run --flake . --timeout 300 -- ./long-running-task.sh
```

Defaults: 2 vCPUs, 512 MiB, 60-second timeout per command.

## Driving from a launch plan

`mvmctl run --launch-plan <path>` accepts either of two JSON
shapes — a `launch.json` artifact (top-level `entrypoint`) or a
Workload IR manifest (top-level `apps[]`) — and auto-detects which
one it is given. Both shapes were historically produced by the
`mvmforge` toolchain
([see the migration guide](/guides/mvmforge-migration/));
the canonical producer today is `mvmctl build compile` in the mvm SDK.

```bash
mvmctl build compile manifest.json --out ./build
mvmctl run --launch-plan ./build/launch.json
```

Only the entrypoint is consumed in v1; image selection still comes from
`--manifest`/`--image`/`--flake`.

**LaunchPlan artifact** (top-level `entrypoint`):

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

**Workload IR manifest** (top-level `apps[]`):

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

For long-running workloads, prefer `mvmctl machine run --flake <artifact-dir>`:
the SDK bakes the entrypoint into the generated flake's
`services.<id>.command`, and mvm's PID-1 init supervises it across
reboots.

Multi-app launch plans are rejected -- that's an orchestration concern
that belongs in `mvmd`, not in `mvmctl machine run`. Env precedence (lowest →
highest):

1. `apps[].env`
2. `apps[].entrypoint.env`
3. CLI `--env` (always wins)

`--launch-plan` is mutually exclusive with a trailing argv.

## Teardown semantics

- **Normal exit**: VM is stopped and the staging dir for `--volume`
  images is cleaned up.
- **Non-zero exit**: same as normal exit; `mvmctl machine run` propagates the
  guest's exit code.
- **Ctrl-C**: a SIGINT handler triggers teardown so the Firecracker
  process and any tap interface don't get orphaned.
- **Hard kill** (`kill -9` on `mvmctl machine run` itself): teardown is
  best-effort; you may need `mvmctl ls` and `mvmctl machine stop <name>` to
  clean up. Each unnamed transient VM gets a generated name like
  `brisk-otter-a1b2`, so it is easy to spot.

## Limits

- **Dev-mode only.** `mvmctl machine run` requires a guest agent built with the
  `dev-shell` Cargo feature, which is the default for the dev images
  `mvmctl` ships with. Production guest images omit the feature and the
  Exec handler is physically absent from the binary.
- **Network access.** The guest gets the same network configuration
  any other transient VM gets -- if your `--manifest` exposes outbound
  internet, so does `mvmctl machine run` from that template.
- **Stdin** is currently *not* forwarded to the guest. Pipe data via a
  `--volume`-shared file instead. Streaming stdin is a future
  improvement.
- **Persistent state** doesn't survive teardown beyond what `:rw`
  `--volume` rsyncs back. For larger or longer-lived state, use
  `mvmctl machine run` with a persistent volume.

## See also

- [CLI reference: One-shot Exec](/reference/cli-commands/#one-shot-exec)
- [Manifests guide](/guides/manifests/) -- build a reusable base image
  via `mvm.toml`; `mvmctl machine run [PATH]` accepts the manifest path directly
- [Quick Start](/getting-started/quickstart/#7-sandboxed-one-shot-commands)
