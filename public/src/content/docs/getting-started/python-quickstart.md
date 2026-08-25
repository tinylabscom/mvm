---
title: Python quickstart
description: Use the current Python SDK runtime surface and the static decorator compiler safely.
---

This page shows the three Python paths: the one-shot `exec` (the quickest), the imperative sandbox lifecycle, and static workload declaration.

> **Status:** The Python package in `crates/mvm-sdk/sdks/python` has `Sandbox.create(...)`, `Sandbox.exec(...)`, `commands.start(...)`, `files.write(...)`, record mode, live mode, and context-manager cleanup. Higher-level helpers such as `commands.run(...)`, file read/list/remove, ports, logs, and cold-mode methods are parity work.

## Run a command (five lines)

Boot a transient dev-tier microVM, run one command, get its output back:

```python
import mvm

with mvm.Sandbox.create(image="python-3.12") as sb:
    result = sb.exec("python", "-c", "print(2 + 2)")
    print(result.stdout.strip())   # -> 4
```

`exec(*argv) -> ExecResult` is a one-shot over `commands.start` (start → wait → collect `stdout`/`stderr`/`exit_code`). `image=` is the friendly alias for the positional template. It is **live-mode only** (dev tier) — run the script with `mvmctl run --mode live ./quickstart.py`; against a prod template it refuses with `SandboxDevOnly` (no silent fallback — ADR-001 claim 4). The `with` block kills the sandbox on exit.

## Imperative runtime

Use this shape when your app owns a sandbox lifecycle.

```python
import mvm

with mvm.Sandbox.create("python-3.12", workload_id="quickstart") as sandbox:
    sandbox.files.write("/app/main.py", "print('hello from mvm')")
    sandbox.commands.start(["python", "/app/main.py"])
```

Run it as an admission-only plan check:

```sh
mvmctl run --mode plan ./quickstart.py
```

Run it against a real local microVM:

```sh
mvmctl run --mode live ./quickstart.py
```

The runtime script executes on the host process that starts it. Keep generated or untrusted program text inside files or commands sent to the guest, not in the host-side Python module.

## Static declaration

Use this shape when you want a deployable workload declaration that can be compiled without importing the Python module.

```python
import mvm

@mvm.app(
    name="hello-python",
    source=mvm.local_path("."),
    image=mvm.nix_packages(["python312"]),
    resources=mvm.resources(cpu_cores=1, memory_mb=512, rootfs_size_mb=512),
    network=mvm.network(mode="none"),
    entrypoint=mvm.entrypoint_function(
        module="app",
        function="main",
        primary=True,
    ),
)
def main() -> str:
    return "hello from mvm"
```

Compile and build:

```sh
mvmctl build compile ./app.py --out /tmp/hello-python
mvmctl machine build --flake /tmp/hello-python
```

## Security checklist

- Use Nix package declarations for reproducible guest images.
- Use `mvm.secret(...)` references instead of plaintext credentials.
- Keep network policy explicit.
- Prefer static compile for deployable workloads.
- Treat runtime record/live mode as host-executed SDK code.
