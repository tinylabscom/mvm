---
title: SDK — Python and TypeScript
description: Declare microVM workloads with the mvm Python and TypeScript SDKs. Decorator-style author surface; mvmctl compile / deploy compiles the same source statically without executing it.
---

The mvm SDK lets you declare a microVM workload from a single
decorated function in Python or TypeScript. Two routes from the same
source file produce the same `Workload` IR:

- **In-process**: `python app.py` or `node app.ts` imports `mvm`, the
  decorator records the declaration, and `mvm.emit_json()` /
  `mvm.emitJson()` writes the canonical IR to stdout.
- **Static compile**: `mvmctl compile app.py` walks the AST without
  importing the script. Same IR; the host never runs user code.

## Python

```python
import mvm

@mvm.app(
    name="hello-app",
    source=mvm.local_path("."),
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    entrypoint=mvm.entrypoint_function(
        module="app",
        function="greet",
        primary=True,
    ),
    env={
        "MODEL_PATH": mvm.literal("/data/model.pt"),
        "API_KEY": mvm.secret("api-key"),
    },
    before_start="export HELLO_BANNER='hi'",
    after_start=mvm.hook(["curl", "-fsS", "http://127.0.0.1:8080/health"]),
)
def greet(name: str) -> str:
    return f"hello {name}"
```

Build, run, invoke:

```sh
mvmctl compile examples/python/hello-app/app.py --out /tmp/hello-app
mvmctl build /tmp/hello-app
mvmctl up hello-app
mvmctl invoke hello-app --input name='ari'
```

## TypeScript

```ts
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  name: "hello-app",
  source: mvm.localPath("."),
  image: mvm.python_image({ python: "3.12" }),
  resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
  entrypoint: mvm.entrypoint_function({
    module: "app",
    function: "greet",
    primary: true,
  }),
  before_start: "export HELLO_BANNER='hi'",
})((name: string): string => `hello ${name}`);
```

## Helper allowlist

Both SDKs ship a closed set of helpers the static parser also
recognizes. Anything else in decorator kwarg position is rejected:

| Helper                  | Returns                  | Notes                                          |
| ----------------------- | ------------------------ | ---------------------------------------------- |
| `python_image(python=)` | `Image::NixPackages`     | `python="3.12"` → `python312` nix attribute    |
| `node_image(node=)`     | `Image::NixPackages`     | `node="22"` → `nodejs_22` nix attribute        |
| `nix_packages([...])`   | `Image::NixPackages`     | direct passthrough                             |
| `resources(...)`        | `Resources`              | `cpu`/`memory_mb`/`rootfs_size_mb`             |
| `network(mode=, ports=)`| `Network`                | `none` \| `bridge` \| `host`                   |
| `secret(name, var=)`    | `EnvValue::SecretRef`    | resolved at admission by supervisor            |
| `literal(value)`        | `EnvValue::Literal`      | parity with `secret(...)`                      |
| `hook(cmd)`             | `HookCmd`                | str → Shell; list → Argv                       |

## Lifecycle hooks

Four phases. Each accepts a string (shell line), a list of strings
(argv), a single `mvm.hook(...)`, or a list of any of those.

| Phase           | Runs                                                                            |
| --------------- | ------------------------------------------------------------------------------- |
| `before_build`  | Inside the builder VM, after deps install and before the rootfs snapshot.       |
| `before_start`  | At every microVM boot, before the entrypoint dispatch.                          |
| `after_start`   | Readiness probe — polled to exit-0 before the agent accepts `mvmctl invoke`.    |
| `before_stop`   | At shutdown, best-effort.                                                       |

Addons (when attached via `addons=[...]`) contribute their own hooks;
the compiler merges them into the rootfs before the consuming app's
hooks, in attachment order. The result lands in `launch.json` for the
Nix factory to bake into `/etc/mvm/hooks/<phase>.sh`.

## Deploy

`mvmctl deploy <entry>` packs the compile output plus an embedded
`mvmd-spec.json` (mvmd ADR-0020 wire shape) into a single signed
`.tar.gz`. v1 ships a stub HTTP client that logs the bundle and exits
0; the real `POST /v1/workloads` lands once mvmd Plan 48 Phase 1090
is live.
