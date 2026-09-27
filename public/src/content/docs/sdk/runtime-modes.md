---
title: Runtime modes
description: Understand record, plan, and live SDK execution modes and when host-side user code is executed.
---

The runtime SDK has two jobs that need different safety properties:

- record a sandbox program into Workload IR for build and admission checks;
- run that program against a real local microVM when the caller explicitly asks.

The mode decides which job is happening.

## Mode summary

| Mode | Command | Executes SDK script on host | Boots a microVM | Output |
| --- | --- | --- | --- | --- |
| Record | `mvmctl build compile ./sandbox.py` | Yes | No | Workload IR or build input. |
| Plan | `mvmctl run --mode plan ./sandbox.py` | Yes | No | Admission/preflight plan. |
| Live | `mvmctl run --mode live ./sandbox.py` | Yes | Yes | Real VM lifecycle and operations. |
| Static declaration | `mvmctl build compile ./app.py` | No import of the user module | No | Workload IR from literal declarations. |

Runtime scripts are imperative. The host runs the script so `Sandbox.create(...)`,
`sandbox.files.write(...)`, and `sandbox.commands.start(...)` can be recorded or
sent to a live VM. Static declarations are different: the compiler reads the
source syntax and extracts supported literal declarations without importing the
module.

Use static declarations for deployable workloads when you want the authoring
surface to be inspectable without running user code.

## Record mode

Record mode is the default SDK transport. The script creates one sandbox handle,
then each supported operation appends to an in-process recording.

```sh
mvmctl build compile ./sandbox.py --out /tmp/workload-ir
```

Equivalent explicit environment for direct debugging:

```sh
MVM_SDK_MODE=record python ./sandbox.py
```

Record mode supports the current runtime SDK surface:

- `Sandbox.create(...)`
- `sandbox.commands.start(...)`
- `sandbox.files.write(...)`
- `sandbox.kill()`

The recording is structured JSON that lowers into the same Workload IR path as
other build inputs. It should contain policy and operation metadata, not secret
values.

## Plan mode

Plan mode uses the same recording path, then asks the local runtime to synthesize
an admission plan without booting a VM.

```sh
mvmctl run --mode plan ./sandbox.py
```

Use it when you want CI or a review tool to answer:

- which workload would be built or admitted;
- which image/template and resources are requested;
- which network and filesystem policy would apply;
- whether policy admission would fail before a real launch.

Plan mode is not a separate SDK-side `MVM_SDK_MODE`. The CLI owns the plan flow
and runs the SDK script under the recording transport.

## Live mode

Live mode drives a real microVM in-process, through the host library
`libmvm_hostlib`:

```sh
mvmctl run --mode live ./sandbox.py
```

The CLI sets `MVM_SDK_MODE=live` for the child process, and `MVM_HOSTLIB_PATH`
when the library is installed beside `mvmctl`. The SDK loads the library and
calls it directly; it never runs `mvmctl`, and a live script run on its own
(`MVM_SDK_MODE=live python sandbox.py`) behaves the same. Each `Sandbox`
operation is one library call:

| `Sandbox` operation | Library method |
| --- | --- |
| `Sandbox.create(image=...)` | `machine.run` — admitted under a signed plan before boot |
| `Sandbox.connect(id)` | `machine.inventory` — reads the machine's dev/prod posture |
| `commands.start`, `exec`, `shell` | `guest.proc.start`, then `guest.proc.stream.*` for the output |
| `files.write` / `read` / `list` / `stat` / `mkdir` / `remove` / `move` | `guest.fs.*` |
| `copy_in` / `copy_out` | `guest.cp` |
| `kill()` | `machine.stop` |

Output from `exec` and `ProcessHandle.wait` streams while the process runs:
the library queues each chunk and the SDK polls for it, so an `on_event`
callback sees output as it arrives rather than after the process ends.

Live mode creates a real microVM. It should be used only when the caller is ready
for runtime side effects: boot, file writes, command execution, logs, audit
events, and cleanup.

## Current live-mode boundaries

Live mode is intentionally narrower than the target SDK contract:

| Surface | Current behavior |
| --- | --- |
| Sandbox count | One active sandbox per SDK process. |
| TTL | Defaults to 30 minutes unless the caller sets `ttl`. |
| Commands | `commands.start(...)` starts a command and returns a handle; `exec(...)` / `shell(...)` is the one-shot that returns a captured `ExecResult`. |
| Files | `files.write(...)` stages bytes into the running VM; `read` / `list` / `stat` / `mkdir` / `remove` / `move` are live-mode only. |
| Source | `image=` (an OCI reference, a rootfs path, or `flake:<ref>#<attr>`). A template or manifest source is refused: the in-process launcher has no template slot yet. |
| Boot command | `command=` is passed to the launcher, which refuses a command override today; the image's own entrypoint runs. |
| Cleanup | Python `with`, TypeScript `using`, or explicit `kill()` stops the machine. |
| Secrets | Live command env forwarding accepts literal values only. Secret refs must use host-managed injection paths. |

`commands.start(...)` is a developer-oriented command surface. Production-style
guest images can refuse it; the SDK raises a typed live error before sending a
guest command when the resolved template is not compatible with command start.

## Security implications

Runtime SDK scripts execute on the host in all runtime modes. Treat them like
build scripts:

- run only trusted SDK scripts on developer machines and CI hosts;
- prefer static declarations for untrusted or review-before-execute workloads;
- keep secrets out of argv, literal env values, stdout, stderr, and source files;
- use policy profiles and deny-by-default network rules for generated code;
- use plan mode before live mode when reviewing a new workload;
- include receipts and audit identifiers when live runs feed automation.

The safety boundary is the microVM for guest execution. The SDK script itself is
host code until it has been recorded, admitted, and launched.

## Environment variables

| Variable | Set by | Meaning |
| --- | --- | --- |
| `MVM_SDK_MODE=record` | CLI or caller | Record SDK operations without launching a VM. |
| `MVM_SDK_MODE=live` | `mvmctl run --mode live`, or the caller | Send SDK operations to a real VM through the host library. |
| `MVM_SDK_OUT_PATH` | CLI | Path where the SDK writes the recording JSON for the parent process. |
| `MVM_HOSTLIB_PATH` | `mvmctl run --mode live`, or the caller | The `libmvm_hostlib` file to load. Otherwise the SDK looks in its own package, then beside `mvmctl` on `PATH`. |

Do not set `MVM_SDK_MODE=plan` in the SDK process. Plan mode is a CLI behavior
that runs the SDK under record mode, then performs admission planning.

## Related pages

- [Runtime SDK](/sdk/runtime/)
- [SDK security model](/sdk/security-model/)
- [Decorator SDK](/sdk/decorator/)
- [Policy profiles](/guides/policy-profiles/)
- [Audit and receipts](/guides/audit-and-receipts/)
