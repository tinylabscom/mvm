# The SDKs stop running `mvmctl`: every operation goes through the host library

Issue #3711 (PS-01 of `specs/plans/2026-09-25-agent-sandbox-product-surface.md`),
closing out WS2 of `specs/plans/2026-09-15-agent-sandbox-drive-plane.md`
(#3261).

The Python and TypeScript SDKs built an argv and ran `mvmctl` once per call:
`Sandbox`, `Machine`, `session` and function dispatch each had their own
subprocess path, and the Rust `mvm-sdk` carried two more (`MachineClient` and a
subprocess-backed `MvmClient`). All of them are gone. Each SDK loads
`libmvm_hostlib` in-process and makes one C call per operation; nothing spawns
a process, and nothing falls back to the CLI when the library is missing.

## The library covers the facade surface (ABI 1.2)

| New method | What answers it |
| --- | --- |
| `machine.run` | `LocalBackend::launch`, through `LaunchRequest` — the admitted, chain-audited boot; the reply carries the plan id and the fail-closed `build_mode` |
| `machine.create` | `LocalBackend::create_from_request` — a persistent definition, not booted |
| `machine.start` | `MvmClient::start_machine` |
| `machine.inventory` | `mvm_client::inventory::list_local_inventory` — every machine with its posture, which is how `Sandbox.connect` attaches |
| `guest.proc.stream.{open,next,close}` | a reader thread over `mvm_client::guest::wait_process`, polled by the binding |

`machine.run` hands every field to the `LaunchRequest` builder, so the request
is validated exactly as a Rust caller's is. Fields the in-process launcher
cannot honour yet — a command override, guest environment — are refused there
with the launcher's own reason (`INVALID_SPEC`), not dropped and not rerouted
to the CLI. Egress targets become the plan's egress grant.

Streaming is a handle and a poll, never a callback into the binding. The
reader's queue is bounded (64 chunks), so a binding that stops polling stalls
the guest process's pipe rather than growing the host process; a reply returns
at most 4 MiB; at most 256 streams are open at once; and a wait that fails
after producing output reports the output first and the error on the next
poll. `ProcessHandle.wait`, `exec` and `Machine.exec` all read through it, so
an `on_event` callback sees output as it arrives and there is no 8 MiB
truncation.

## SDKs

- Python: `_cli.py` and `_subprocess.py` deleted; `_sandbox.py`,
  `_machine.py`, `_session.py`, `_remote.py` rewritten onto `_hostlib.call`,
  with shared helpers in `_live.py`. Record mode is byte-identical.
- TypeScript: `_cli.ts` deleted and the same modules rewritten onto `call`,
  synchronously through koffi; `setInvokeForTesting` is the test seam.
- `Machine` now returns typed data: `run`/`create` return a handle, `ls` the
  inventory records, `inspect`/`start` the machine state, `logs` text, `exec`
  an exit code and output. `shell`, `check_artifact`, `dry_run`, `receipt`,
  `json`, `net`, `volumes`, `follow` and `manifest` are gone with the argv
  builders; those stay CLI verbs.
- Live `Sandbox.create` boots an `image`. A template source is refused
  (`SandboxModeError`): the in-process launcher has no template slot yet.
  That also stops the `BrowserSandbox` presets booting live for now — the
  Chromium/Chrome presets are templates and Obscura passes a command
  override — though both still record.
- `MVM_NO_VM=1` dispatch is an in-language call — encode, size-cap, decode,
  call, encode, hardened decode — instead of `mvmctl __sdk-no-vm`. Without it,
  function dispatch into a microVM raises a typed transport error: the invoke
  path lives in the CLI and has to move into `mvm-client` first. `session()`
  is a local scope under `MVM_NO_VM=1` and refuses otherwise.
- Library lookup: `MVM_HOSTLIB_PATH` (now owned by the Rust env registry, so
  the CLI and both loaders share one name), then the SDK package's own
  `_native/` / `native/` directory, then beside `mvmctl` on `PATH` (located,
  never run). `mvmctl run --mode live` sets `MVM_HOSTLIB_PATH` to the library
  beside itself instead of handing the script a CLI path. The registry no
  longer carries `MVM_CLI_BIN`, `MVM_MACHINE_TIMEOUT_SEC` or
  `MVM_MACHINE_MAX_OUTPUT_BYTES`.

## The gate

`xtask check-no-cli-shellout` (in `check-all`) scans the Python and
TypeScript package sources, `crates/mvm-sdk/src` and `crates/mvm-hostlib/src`.
It forbids every process API rather than the `mvmctl` literal — Python
`subprocess`, the `os` spawn/exec calls, `Popen`, `asyncio` subprocesses,
`pty`, `multiprocessing`; Node `child_process`, `spawn`, `exec*`, `fork`,
`Bun.spawn`, `Deno.Command`; Rust `process::Command` and the `libc`
spawn/exec calls — plus the CLI-location overrides and resolvers. Comments are
stripped, strings are not, and a missing or empty root fails closed. Its
fixture tests cover each pattern in each language, comments, strings,
docstrings, vendored trees, empty roots and the live tree.

## `mvm-client` is the one Rust library

It re-exports `RootfsSource`, the grant types, `HostPort`, `NetworkPreset`,
the guest payload types (from `mvm_client::guest`), `MachineInventoryRecord`,
`WorkloadPosture`, `LocalDrive`, the plan types, `error_codes`, `AccessMode`,
`MachineSecretRef`, and `mvm-sdk` as `mvm_client::authoring`.
`tests/embedder_surface.rs` imports nothing else from the workspace, so a
missing re-export fails to compile. The Rust quickstart and SDK reference use
`mvm-client` alone, and their examples compile in the conformance build.

## Tests

- `mvm-hostlib`: every new method against `LocalBackend` driving the mock
  hypervisor under an isolated `MVM_HOME` (admitted boot, audit entry, grant
  persistence, launcher refusals, unknown fields), the stream reader against a
  scripted guest (ordering, mid-flight delivery, empty polls, error after
  output, agent errors, idempotent close, the open-stream cap), routing and ABI
  negotiation for every family.
- Python and TypeScript: every facade method's request shape, typed error
  propagation, DevOnly refusal before any guest call, the stream loop, library
  lookup order, in-language `MVM_NO_VM` dispatch, and a live test against the
  real debug library (ABI negotiation, `machine.inventory`, and `machine.run`
  refusing a command override end to end without booting).
- BDD `s27_sdk/runtime_live_transport.feature`: both SDKs' built artifacts run
  with the C call replaced by an in-process recorder; the traces match a
  golden host-library call sequence and each other, every call names a
  registered method, and a sealed machine makes no `guest.*` call.
- Root `tests/run_live_mode.rs`: the live script path records the same calls,
  and `mvmctl run --mode live` sets `MVM_HOSTLIB_PATH` exactly when the library
  sits beside the binary and never exports a CLI path.

## Not done here

Tracked as open boxes under PS-01: a command override, guest environment and
template sources in the in-process launcher (converging it with the CLI's
`machine run` front half); in-VM function dispatch; `machine.logs` follow as a
stream; a live-boot SDK scenario against a real guest. Shipping the library in
wheels, npm packages and the release tarball is PS-15 (#3724).
