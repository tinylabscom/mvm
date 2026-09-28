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
mvmctl machine run --flake . --mount .:/work -- ls /work
mvmctl machine run --manifest my-tpl -- /bin/true
```

> Overriding the guest's argv (a trailing `-- <cmd>`) is a **dev-tier**
> capability. It requires DevOnly verbs regardless of the image's sealed bit;
> sealed production images also refuse it because their entrypoint is fixed.
> Use `--image`/`--flake` dev builds and a dev profile for ad-hoc commands;
> production workloads run their baked entrypoint (`machine run --entrypoint`)
> or go through `mvmd`.

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

## Sharing host directories: `--mount`

`--mount HOST:GUEST[:MODE]` shares a host directory into the guest at
`GUEST`. The flag is repeatable. `--volume` remains accepted as a
compatibility alias, but `-v` is global verbosity.

`GUEST` must sit under **`/data` or `/work`** — those are the only two
allow-roots. Anything else is refused, including `/mnt/*`, which is excluded
so a share cannot shadow the runtime's own `/mnt/config` and `/mnt/secrets`
drives.

### Read-only (default)

```bash
echo "hello" > /tmp/foo
mvmctl machine run --image alpine --mount /tmp:/data/host -- cat /data/host/foo   # prints "hello"
```

### Writable disk images: `:rw` under any profile

A sized disk image (`HOST.img:GUEST:SIZE:rw`) is an ext4 file mvm creates at
`HOST` if it is absent and attaches as a block device. The guest writes into
that image, never into the host filesystem, so every profile that accepts
`--mount` accepts it writable — the default `standard`, and `--prod`, included.
This is the way to keep data without `--profile dev`, which would also hand the
guest the dev shell agent and the DevOnly verbs:

```bash
mvmctl machine run --image alpine --mount ./state.img:/data/state:1G:rw \
  -- sh -c 'echo kept > /data/state/note'
```

The guest mount path still has to sit under `/data` or `/work`; the profile
decides whether a volume may be writable, not where it may mount.

### Writable directories: never on a transient run

A **transient** run's directory share is a read-only snapshot under *every*
profile — `--profile dev` does not change that. A write would land in a
throwaway image and never reach the host directory, so `:rw` on a directory is
refused rather than silently lost. Use a disk image for anything the guest has
to write.

### Persistent machines take no live host directory

A persistent machine (`-d`, or `--name` with `--port`, `--ttl` or
`--healthcheck`) cannot attach a live host directory at all, read-only or
writable, under any profile. `machine run` and `machine create` refuse a
directory `--mount` up front and name the two ways to get data in.

Keep the machine's working state in a disk image. It survives stop and start,
under the default profile:

```bash
mvmctl machine run --flake . --name builder -d --mount ./builder.img:/work:4G:rw
mvmctl machine exec builder -- sh -c 'echo result > /work/output.txt'
```

The guest writes into `builder.img`, not into a host directory, so copy
results out with `mvmctl machine cp` rather than expecting them in your
checkout.

Or snapshot a host directory into the machine with `machine volume mount`. A
registration is picked up at the machine's next start, so it can come before
the machine exists:

```bash
mvmctl machine volume mount build --volume src --host "$PWD/src" --guest /work/src
mvmctl machine run --flake . --name build -d --mount ~/cargo.img:/data/cargo:8G:rw
mvmctl machine exec build -- cargo build --manifest-path /work/src/Cargo.toml
```

The directory is copied into an ext4 image each time the machine starts, so
host edits appear after the next stop and start. `--host` must be absolute and
on encrypted storage. With `--rw` the guest writes into the machine's private
copy of the image; those writes never reach the host directory, and a changed
host directory replaces the copy at the next start. Because it is a disk image,
a read-write registration follows the writable-disk-image grant: `standard`,
`dev`, and `permissive` take it, `restrictive` does not. See the [machine volume docs](/guides/machine-use-cases/).

## Injecting environment variables: `--env`

```bash
mvmctl machine run --image alpine -e FOO=bar -e BAZ=qux -- env | grep -E '^(FOO|BAZ)='
```

`--env` (or `-e`) is repeatable. When used together with `--launch-plan`,
CLI `--env` overrides any env vars the launch plan carries (see below).

## Snapshot restore (registered templates)

When you pass `--manifest <name>` and that template has a compatible recovery
artifact, `mvmctl machine run` may use the backend's advertised recovery tier
instead of cold-booting. The tier is backend-specific; inspect `mvmctl doctor`
before relying on its latency or fidelity.

The snapshot path activates only when:

- the image source is a registered template (an OCI image or ad-hoc flake has no
  template snapshot to restore from), AND
- the request has **no** `--mount` extras (extra drives would mismatch
  the snapshot's recorded layout), AND
- the active backend reports snapshot support.

Unsupported recovery requests return an actionable typed error. `mvm` does not
silently downgrade a live-memory or machine-state request to disk-only recovery
or cold boot. The harder branch -- parameterized snapshots that allow
`--mount` -- is tracked in [issue #7](https://github.com/tinylabscom/mvm/issues/7).

## Resource controls

```bash
mvmctl machine run --flake . --cpus 4 --memory 1G -- ./benchmark.sh
mvmctl machine run --flake . --timeout 300 -- ./long-running-task.sh
```

Defaults: 2 vCPUs (`--cpus`), 512 MiB (`--memory`). **`--timeout` has no
default** — omit it and the run is unbounded. A sealed run fails closed when
its selected backend cannot enforce a wall-clock grant; currently Firecracker
and QEMU do not own a long-lived supervisor timer. Use `mvmctl doctor` to check
the active backend before relying on `--timeout` for a sealed workload.

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

- **Normal exit**: VM is stopped and the staging dir for `--mount`
  images is cleaned up.
- **Non-zero exit**: same as normal exit; `mvmctl machine run` propagates the
  guest's exit code.
- **Ctrl-C**: a SIGINT handler triggers teardown so the Firecracker
  process and the per-VM network endpoint don't get orphaned. (There is no
  tap interface to orphan — a workload microVM has no guest NIC.)
- **Hard kill** (`kill -9` on `mvmctl machine run` itself): teardown is
  best-effort; you may need `mvmctl machine ls` and `mvmctl machine stop <name>` to
  clean up. Each unnamed transient VM gets a generated name like
  `brisk-otter-a1b2`, so it is easy to spot.

## Limits

- **Ad-hoc execution is dev-mode only.** A baked-entrypoint
  `mvmctl machine run` may use the restricted ProdSafe grant on a non-dev
  profile. A trailing argv requires the guest agent's `interactive` Cargo
  feature and DevOnly verbs; production guest images may omit that feature, in
  which case the Exec handler is physically absent from the binary.
- **Network access.** The guest gets the same network configuration
  any other transient VM gets -- if your `--manifest` exposes outbound
  internet, so does `mvmctl machine run` from that template.
- **Stdin** is not forwarded to a trailing-argv run. It *is* available to a
  baked-entrypoint run via `machine run --entrypoint --stdin -`, which needs
  the `host.stream.v1` grant on the signed plan — see
  [Workload input](/guides/workload-input/). For a trailing-argv run, pipe
  data via a `--mount`-shared file instead.
- **Persistent state** doesn't survive teardown. No run writes back to a host
  directory: a transient run's directory share is read-only, and a persistent
  machine takes none. For state that has to outlive the run, attach a writable
  disk image (`HOST.img:/GUEST:SIZE:rw`, any profile that accepts `--mount`),
  or boot a persistent machine (`--name` + `-d`) with a disk image or a
  managed volume.

## See also

- [CLI reference: One-shot Exec](/reference/cli-commands/#one-shot-exec)
- [Manifests guide](/guides/manifests/) -- build a reusable base image
  via `mvm.toml`. Only `mvmctl machine build` takes a positional `[PATH]`;
  `machine run` and `run` take `-m/--manifest <PATH>`, because their
  positional slot is the trailing argv.
- [Quick Start](/getting-started/quickstart/#7-sandboxed-one-shot-commands)
