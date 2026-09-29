# The in-process SDKs do everything the CLI transport did

Issue #3711 (PS-01 of `specs/plans/2026-09-25-agent-sandbox-product-surface.md`),
following `3711-sdk-hostlib-inprocess.md`.

Moving the SDKs onto `libmvm_hostlib` left five things that used to work
refusing: a boot command and its environment, template sources, function
dispatch into a microVM, following a machine's logs, and any proof that an SDK
boots a real guest at all. All five work now, through library code the CLI
runs too.

## One launch path for the CLI and the library

`LocalBackend::launch` in persistent mode now boots through the CLI's own
start. The spec reconcile, persist-then-boot, the start record, TTL and
stopping a running machine before a recreate moved out of
`mvm-cli/src/commands/machine/` into `mvm_client::launch::detached`, and
`mvmctl machine run -d` calls them; nothing was copied. A persisted definition
is admitted by `start_machine_spec` whichever process starts it, so the plan,
the verb grant and the audit entries are the same. What differs sits behind
`StartHost`: the CLI may build a kernel, a library never does, and the secret
service and backend the start uses are now the caller's rather than rebuilt
from defaults.

`LaunchRequest` carries:

- a source: `LaunchSource::Image`, or `LaunchSource::Built` from
  `from_template(name)` (the one built slot whose image carries that name) or
  `from_manifest(path | slot)`. Nothing is built on a launch.
- a `command` with its `env` and `cwd`. `env` passes the `env_hygiene`
  denylist when the request is built, and `env` or `cwd` without a command is
  refused rather than dropped. The command starts once the machine is up, as
  the guest agent's process start; the outcome carries its token, and a
  machine whose command did not start is stopped and the launch fails.

`machine.create` takes no command: a definition records what boots.

## Host library (ABI 1.3)

| Method | Answered by |
| --- | --- |
| `machine.run` `{image \| template \| manifest, command?, env?, cwd?, …}` → `{…, process?}` | `LocalBackend::launch` |
| `machine.logs.stream.{open,next,close}` | `open_vm_output`, the reader `mvmctl machine logs --follow` uses, on a bounded reader thread |
| `entrypoint.call`, `session.{start,call,stop,info}` | `mvm_client::entrypoint` |

Log streams share the process streams' handle-and-poll machinery, and a
handle is scoped to its family.

Function dispatch moved from `mvm-cli/src/commands/vm/` into
`mvm_client::entrypoint`: one admission for a transient call and a session
start (keeping the stricter side of the two copies it replaced), boot and
teardown, dispatch returning a typed outcome instead of writing to file
descriptors, the streaming-stdin pump, the session store, the verb-refusal
audit and the `MVM_ENVELOPE` parser. `mvmctl machine run --entrypoint` and
`machine session` are adapters over it. It also closes audit gaps the CLI
had: a vsock-RPC entry on every `RunEntrypoint`, `plan.failed("agent-wait")`
on the transient path, and a `SessionStart` entry for kept-alive calls. A
payload over one agent frame (62 KiB) rides the streaming input plane for a
transient call and is refused for a session call; nothing is truncated. The
workload id resolves through the image sidecar every build writes
(`GuestSidecar.name`), the same lookup templates use.

## SDKs

Python and TypeScript send identical requests.

- `Machine.run(image, command)` boots, runs the command, and returns its
  result, then stops and removes the machine — the contract it had before
  PS-01. `Machine.launch(...)` returns a handle, with `process` and `wait()`
  for a launch command. `Machine.create` takes `template`/`manifest`.
- `Machine.logs(follow=True)` is an iterator of text chunks, decoded across
  chunk boundaries, closing its stream when iteration stops.
- `Sandbox.create` boots an image or a built template, with `command=` and
  `env=`; `sandbox.process` is the command's handle. Every boot is a named
  machine started the way `machine run -d` starts one, as the CLI transport
  did, and `kill()` stops and removes it; a connected machine is only
  stopped.
- The Chromium, Chrome and Obscura `BrowserSandbox` presets boot live.
- `await f()`, `f.sync()`, `workload_ref` and `session()` dispatch through
  `entrypoint.call` / `session.*`; a raised error arrives as the generated
  `RemoteError`. `MVM_NO_VM=1` is unchanged.

Every "not available in-process yet" refusal is gone.

## Live boot, as run

macOS 26.6.2, Apple silicon, HVF, after `just embed` and
`cargo build -p mvm-hostlib`, with `MVM_HOSTLIB_PATH` at the debug
`libmvm_hostlib.dylib` and `MVM_SDK_MODE=live`. The host was heavily loaded
by other work throughout (load average 85–568).

Python:

- `Machine.run("docker.io/library/alpine:latest", ["/bin/sh", "-c", "uname -sm; echo greeting=$GREETING"], env={"GREETING": "hello"})`
  → exit 0, `Linux aarch64\ngreeting=hello\n`, 2.5 s.
- `Sandbox.create(image=alpine, command=["/bin/sh", "-c", "echo boot-$GREETING"], env={"GREETING": "hi"})`
  → `build_mode=dev`; `sandbox.process.wait()` → exit 0, `boot-hi\n`;
  `exec("head", "-1", "/etc/os-release")` → `NAME="Alpine Linux"`;
  `files.write` then `files.read` round-tripped; `logs(5)` returned the
  console; `logs(5, follow=True)` yielded the tail and then waited; `kill()`
  stopped and removed the machine.
- `Machine.launch(manifest=<built "sleeper" slot>, command=[...])` → exit 0,
  `from-template\n`.
- `Machine.launch(template="no-such-template")` → `MachineSpecError` naming
  the build commands.

TypeScript, from the built `dist/`: `Machine.run` → exit 0, same output;
`Sandbox.create` with a command and env → `boot-hi`, and `exec` → Alpine.

The first boot of a checkout cold-builds the guest binaries and the universal
initramfs (about 12 minutes on that host); later boots take seconds.

Function dispatch was not live-booted: no function workload is built on that
host. It is covered by the library's unit tests against doubles and by the
CLI's own invoke and session tests, which now run through the moved code.

## Found on the way

`LocalBackend::launch` in transient mode still admits through
`mvm_hostd::run::admit_and_boot_local`, which attaches no universal initramfs
and no guest boot config. A runtime-lean OCI image booted that way panics at
`/init` (ENOENT) — seen live with Alpine on HVF. The SDKs no longer use that
path. It is tracked under "Converge the transient launch onto the same start"
in `specs/plans/2026-09-15-agent-sandbox-drive-plane.md`, and the Rust
quickstart now shows a persistent launch.

The host runs a workload's primary entrypoint only: the guest protocol has no
function selector, so a non-primary function of a multi-function workload is
not reachable by dispatch yet.

## Tests

- Rust: launch tests for commands (a recording `CommandStarter` in place of a
  guest agent, since the mock backend runs none), templates, the reconcile
  and start moved into `detached`, the secret service and backend threaded
  through the start, and log streams; the moved entrypoint and session code
  with its CLI tests.
- Python and TypeScript: `Machine.run/launch/wait/logs(follow)`, sandbox
  commands, templates and teardown, browser presets, remote calls and
  sessions.
- BDD (s27): a launch fixture in both languages against a golden trace, the
  two traces compared, and every method checked against the generated table.
