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

Live mode shells SDK operations through the invoking `mvmctl` binary:

```sh
mvmctl run --mode live ./sandbox.py
```

The CLI sets `MVM_SDK_MODE=live` and `MVM_CLI_BIN` for the child process. The SDK
then uses the local CLI for operations such as:

- `mvmctl machine run --up-json --detach --name <generated-id> --manifest <template>`
- `mvmctl machine fs write <vm> <path>`
- `mvmctl machine proc start <vm> -- <argv>`
- `mvmctl machine stop <vm>`

Live mode creates a real microVM. It should be used only when the caller is ready
for runtime side effects: boot, file writes, command execution, logs, audit
events, and cleanup.

## Current live-mode boundaries

Live mode is intentionally narrower than the target SDK contract:

| Surface | Current behavior |
| --- | --- |
| Sandbox count | One active sandbox per SDK process. |
| TTL | Defaults to 30 minutes unless the caller sets `ttl`. |
| Commands | `commands.start(...)` starts a command; result capture is still a parity target. |
| Files | `files.write(...)` stages bytes into the running VM. |
| Cleanup | Python `with`, TypeScript `using`, or explicit `kill()` calls `mvmctl machine stop`. |
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
| `MVM_SDK_MODE=live` | `mvmctl run --mode live` | Send SDK operations to a real VM through `mvmctl`. |
| `MVM_SDK_OUT_PATH` | CLI | Path where the SDK writes the recording JSON for the parent process. |
| `MVM_CLI_BIN` | `mvmctl run --mode live` | Absolute path to the invoking `mvmctl` binary. |

Do not set `MVM_SDK_MODE=plan` in the SDK process. Plan mode is a CLI behavior
that runs the SDK under record mode, then performs admission planning.

## Related pages

- [Runtime SDK](/sdk/runtime/)
- [SDK security model](/sdk/security-model/)
- [Decorator SDK](/sdk/decorator/)
- [Policy profiles](/guides/policy-profiles/)
- [Audit and receipts](/guides/audit-and-receipts/)
