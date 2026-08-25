---
title: Python SDK
description: Python runtime and decorator SDK status.
---

The Python SDK currently exposes both runtime and declarative surfaces.

## Runtime

Current:

- `mvm.Sandbox.create(template, ...)`
- `sandbox.commands.start(argv, env=...)`
- `sandbox.files.write(path, content)`
- context-manager cleanup with `with`
- record mode for `mvmctl build compile` and `mvmctl run --mode plan`
- live mode for `mvmctl run --mode live`

Planned:

- command result capture through `commands.run(...)`;
- file read/list/remove;
- logs and event streams;
- port helpers;
- snapshot, cold, resume, detach, destroy;
- additional lifecycle result types once the local runtime transport supports them.

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
    image=mvm.python_image({"python": "3.12"}),
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
