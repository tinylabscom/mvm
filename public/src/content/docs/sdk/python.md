---
title: Python SDK
description: Python runtime and decorator SDK status.
---

The Python SDK currently exposes both runtime and declarative surfaces.

## Runtime

Current:

- `mvm.Sandbox.create(image=..., ...)` (live mode boots an image; `template` is record mode only)
- `sandbox.commands.start(argv, env=...)` — the only method on `commands`
- `sandbox.exec(*argv, ...)` / `sandbox.aexec(...)` / `sandbox.shell(...)` — one-shot with a captured `ExecResult` (live mode only)
- `sandbox.files.write/read/list/stat/mkdir/remove/move(...)` — everything but `write` is live mode only
- `sandbox.copy_in(...)` / `sandbox.copy_out(...)`
- context-manager cleanup with `with` (or `async with`)
- record mode for `mvmctl build compile` and `mvmctl run --mode plan`
- live mode for `mvmctl run --mode live`

Planned:

- logs and event streams;
- snapshot, cold, resume, detach, destroy;
- additional lifecycle result types once the local runtime transport supports them.

There is no `commands.run(...)`. `sandbox.forward(...)` exists only to refuse:
ingress is declared before boot through `network=mvm.network(ports=[...])`.

## How the SDK reaches the host

The SDK drives machines in-process through the host library
`libmvm_hostlib` (a C ABI over `mvm-client`), loaded with `ctypes`. It never
runs `mvmctl` and has no subprocess fallback. It finds the library, first
match wins:

1. `MVM_HOSTLIB_PATH`, naming the library file;
2. `mvm/_native/` inside the installed package (wheels that carry the library
   are follow-up work);
3. beside `mvmctl` on `PATH`, including beside the real file behind a symlink.

A missing library raises `MvmTransportError` naming all three. Every failed
call raises a typed `HostLibraryError` subclass (`MachineNotFoundError`,
`MachineSpecError`, `MachineBackendError`, …) carrying `code` and `retryable`.


## Decorator

Current:

```python
import mvm

@mvm.app(
    name="worker",
    source=mvm.local_path("."),
    image=mvm.nix_packages(["python312"]),
    resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    network=mvm.network(mode="none"),
)
def run() -> str:
    return "ok"
```

The static compiler extracts literal decorator declarations without importing the module.


### AI egress budget

```python
@mvm.app(
    name="llm-worker",
    source=mvm.local_path("."),
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu_cores=1, memory_mb=512, rootfs_size_mb=1024),
    network=mvm.network(
        mode="bridge",
        egress=mvm.egress([mvm.host_port("api.openai.com", 443)]),
        ai=mvm.ai_policy(
            metering=True,
            budget=mvm.ai_budget(max_total_tokens=100_000),
        ),
    ),
)
def run(prompt: str) -> str:
    ...
```

## Security notes

- Runtime scripts execute host-side SDK code.
- Decorator compile is preferred for deployable workloads.
- Secret values should be represented as references.
- Network policy should be explicit in examples and tests.

See [Runtime modes](/sdk/runtime-modes/) before using live mode in automation.
See [Operations cookbook](/sdk/operations-cookbook/) for current calls, target helpers, and CLI fallbacks.
