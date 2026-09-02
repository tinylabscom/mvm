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

### Writable: `:rw` needs a persistent machine

A **transient** run's live shares are read-only under *every* profile —
`--profile dev` does not change that. `:rw` is accepted only on a persistent
machine (`--name` plus `-d`), and only under `--profile dev` or
`--profile permissive`:

```bash
mvmctl machine run --flake . --profile dev --name builder -d --mount .:/work:rw
mvmctl machine exec builder -- sh -c 'echo result > /work/output.txt'
cat ./output.txt       # "result" — written by the guest
```

A writable share lets the guest edit host files under `GUEST` — exactly what
you want for a coding agent that needs to edit your repo. For the durability
and host-visibility semantics of the current volume backend, see the
[machine volume docs](/guides/machine-use-cases/).

### Multiple shares

Modes are independent per directory:

```bash
mvmctl machine run --flake . --profile dev --name build -d \
  --mount ./src:/work/src:rw \
  --mount ~/.cargo:/data/cargo:ro
mvmctl machine exec build -- cargo build --manifest-path /work/src/Cargo.toml
```

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
- **Persistent state** doesn't survive teardown. A transient run cannot take
  a `:rw` share at all, so nothing is written back to the host. For state
  that has to outlive the run, boot a persistent machine (`--name` + `-d`)
  with a `:rw` share or a managed volume.

## See also

- [CLI reference: One-shot Exec](/reference/cli-commands/#one-shot-exec)
- [Manifests guide](/guides/manifests/) -- build a reusable base image
  via `mvm.toml`. Only `mvmctl machine build` takes a positional `[PATH]`;
  `machine run` and `run` take `-m/--manifest <PATH>`, because their
  positional slot is the trailing argv.
- [Quick Start](/getting-started/quickstart/#7-sandboxed-one-shot-commands)
