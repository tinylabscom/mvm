# mvm — Python SDK

Declare a microVM workload in Python. Write a function, decorate it, and the
`mvmctl` toolchain bakes it into a Nix-built Firecracker / libkrun microVM
image and boots it — no Dockerfile, no SSH, no agent code in your app.

```sh
pip install mvm
```

`mvmctl` (the Rust host CLI) is distributed separately and does the building,
booting, and signing. This package is the **authoring** surface it reads.

## Quick start

```python
# app.py
import mvm as mv

@mv.func(name="adder")
def add(a: int, b: int) -> int:
    return a + b
```

```sh
mvmctl compile app.py     # parse the script (no execution) → flake.nix + launch plan
mvmctl up --flake .       # build the image and boot the microVM
```

`@mv.func` is the one-liner: it declares the workload, the app, and a function
entrypoint with sane defaults (`nix_packages(["python312"])`, 1 vCPU / 256 MB /
512 MB rootfs). For full control, declare the pieces explicitly:

```python
import mvm as mv

mv.workload(id="hello")

@mv.app(
    name="hello",
    source=mv.local_path("."),
    image=mv.nix_packages(["python312"]),
    resources=mv.resources(cpu_cores=1, memory_mb=256, rootfs_size_mb=512),
    env={"API_KEY": mv.secret("api-key")},
    before_start=mv.hook("export TZ=UTC"),
    after_start=mv.hook(["curl", "-fsS", "http://localhost:8080/health"]),
)
def main(name: str) -> str:
    return f"hello {name}"
```

## How it builds

`mvmctl compile` reads your file **statically** — the decorator and the
`import mvm` line are parsed as data, never executed, so nothing in your module
runs on the host. At image-build time the decorator and the `import mvm` line
are **stripped** from the bundled source, so the guest runs your plain function
with no SDK dependency inside the microVM.

You can also emit the canonical Workload IR in-process, for inspection or tests:

```python
import mvm as mv
print(mv.emit_json())     # the IR mvmctl would produce
```

## Lifecycle hooks

Four hook points, each a shell string or an argv list (or a list of them).
Addons contribute their own hooks, merged at compile time:

| Hook | Runs |
| --- | --- |
| `before_build` | in the builder VM, before the image is assembled |
| `before_start` | in the guest, before the entrypoint |
| `after_start`  | in the guest, after the entrypoint is up |
| `before_stop`  | in the guest, on shutdown |

## Building blocks

| Helper | Purpose |
| --- | --- |
| `mv.nix_packages([...])`, `mv.python_image(...)`, `mv.node_image(...)` | base image |
| `mv.resources(cpu_cores=, memory_mb=, rootfs_size_mb=)` | per-VM budget |
| `mv.network(...)`, `mv.egress(...)` | egress policy (default-deny) |
| `mv.python_deps(...)`, `mv.node_deps(...)` | dependencies, installed into a sealed, audited volume |
| `mv.secret("name")`, `mv.literal("v")` | env values — secrets resolve on the host, never baked into the image |

## Dev-only runtime

`f.remote(...)` / `mv.session(...)` call into a running function-VM, and
`mv.Sandbox` wraps local sandbox primitives. These are **development**
conveniences for build-time emission and introspection. Production microVMs are
observed through `mvmctl` output streams — there are no host-side `.remote()`
calls on the prod path.

## Machine lifecycle wrappers

`mv.Machine` mirrors the beginner `mvmctl machine ...` command group for host
automation. These wrappers deliberately shell to `mvmctl machine ...`; OCI pull,
admission, receipts, audit, networking, and persistent machine state stay owned
by the CLI instead of being reimplemented in Python.

```python
import mvm as mv

result = mv.Machine.run(
    image="alpine:latest",
    command=["uname", "-a"],
    net=True,
    allow_hosts=["example.com:443"],
)
print(result.stdout)

vm = mv.Machine.create(name="devbox", manifest="mvm.toml", profile="dev")
vm.start()
vm.exec(["echo", "hello"])
vm.stop()
```

Set `MVM_CLI_BIN=/path/to/mvmctl` to point the SDK at a local or test CLI
binary. CLI process failures raise `mv.MachineError` with `argv`, `exit_code`,
and captured `stderr`.

## Optional extras

```sh
pip install 'mvm[schema]'   # pydantic-based schema derivation from type hints
```

## Versioning

The SDK version tracks the `mvmctl` toolchain version: a workload emitted by
`mvm` X.Y.Z is consumed by `mvmctl` X.Y.Z. Install matching versions.

## Links

- Source & issues: https://github.com/tinylabscom/mvm
- TypeScript SDK: [`@runmvm/mvm`](https://www.npmjs.com/package/@runmvm/mvm)

## License

Apache-2.0 — see [LICENSE](./LICENSE).
