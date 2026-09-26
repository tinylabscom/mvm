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
mvmctl build compile app.py   # parse the script (no execution) → flake.nix + launch plan
mvmctl machine run --flake .     # build the image and boot the microVM
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

`mvmctl build compile` reads your file **statically** — the decorator and the
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

## Runtime SDK

`Sandbox` has explicit `record` and `live` modes. Record mode is the portable
authoring path; live mode boots or attaches to a development machine through
the host library (below) and exposes the generated process/filesystem
contract:

```python
import mvm

with mvm.Sandbox.create(image="python:3.12-slim") as sb:
    process = sb.commands.start(["python", "-c", "print('ready')"])
    result = process.wait(on_event=lambda event: print(event.stream, event.data))
    sb.files.write("/app/config.json", '{"ready": true}')
    print(sb.files.read("/app/config.json"))
```

Live mode boots from `image=` (an OCI reference, an absolute path, or
`flake:<ref>#<attr>`); a named `template` is recorded in record mode but
refused in live mode, because the host library launches images only.
`Sandbox.connect(name)` attaches to a machine that is already running.

Live process handles support `wait`, streamed stdout/stderr callbacks,
`send_stdin`, `signal`, and `kill`. The filesystem surface supports read,
write, list, stat, mkdir, remove, and move. `sb.shell(...)` is a convenience
for `/bin/sh -lc` in development only.

Process execution, shell, process control, filesystem access and copies fail
closed with `SandboxDevOnly` before any request leaves the process when the
machine is not a development build; the guest agent refuses them on a
production build too. Dynamic port forwarding is refused: declare ingress
with `network=` before boot. SSH is not part of the SDK or runtime contract.

## Machine lifecycle

`mv.Machine` covers the machine lifecycle for host automation. Admission,
OCI verification, audit and persistent machine state belong to the host
library, the same code `mvmctl` runs; the SDK validates arguments and shapes
requests.

```python
import mvm as mv

vm = mv.Machine.run("alpine:latest", allow_hosts=["example.com:443"], ttl_seconds=600)
print(vm.name, vm.build_mode, vm.inspect()["status"])
vm.stop()

devbox = mv.Machine.create("devbox", "alpine:latest", profile="dev")
devbox.start()
result = devbox.exec(["echo", "hello"])   # dev builds only
print(result.exit_code, result.stdout)
print(devbox.logs(lines=20))
devbox.stop()
devbox.rm()

for record in mv.Machine.ls():
    print(record["name"], record["build_mode"], record["status"])
```

## Host library

The SDK never runs `mvmctl` or any other program. Every live `Sandbox` and
`Machine` call goes to `libmvm_hostlib` (`.dylib` on macOS, `.so` on Linux),
loaded into the Python process and spoken to over its C ABI. It is found by
looking, in order, at:

1. `MVM_HOSTLIB_PATH` — the library file itself. If it is set and names
   nothing, that is an error; the SDK does not fall back to another copy.
2. `mvm/_native/` inside the installed package, for a package that bundles
   the library.
3. The directory holding `mvmctl` on `PATH`, and the directory of the file
   that path resolves to. `mvmctl` is only located, never run.

When none of these has it, calls raise `mv.MvmTransportError` naming all
three. A refusal from the library raises the typed error its code names —
`mv.MachineNotFoundError`, `mv.MachineSpecError`, `mv.MachineConflictError`,
`mv.MachineUnavailableError` (retryable), and so on, all subclasses of
`mv.HostLibraryError` carrying `code` and `retryable`.

What the library cannot do yet, the SDK refuses rather than working around:
the in-process launcher refuses a boot `command` or `env` override
(`MachineSpecError`), and function dispatch into a microVM (`await f(...)`,
`f.sync(...)`, `mv.session(...)`) raises `MvmTransportError`. Set
`MVM_NO_VM=1` to run decorated functions in the calling process through the
same encode, size-check and decode path a microVM call takes; inside that
mode `mv.session(...)` is a local scope.

## Experimental Obscura browser provider

`BrowserSandbox()` still defaults to Chromium. Obscura is an explicit,
experimental opt-in for live development:

```python
import mvm

browser = mvm.BrowserSandbox(
    "obscura",
    network={
        "mode": "none",
        "egress": {"allowlist": [{"host": "example.com", "port": 443}]},
    },
)
websocket_url = browser.wait_until_ready()
```

Set `MVM_SDK_MODE=live`. The provider uses `mvm.OBSCURA_IMAGE`, a digest-pinned
OCI reference; fixes CDP to guest loopback; explicitly routes browser traffic
through the mvm proxy; and rejects command overrides. It does not enable
private-network access, stealth behavior, or unrestricted egress. Obscura is
not a guaranteed drop-in replacement for every Playwright or Puppeteer flow.

Neither preset boots in live mode yet. Chromium and Chrome are named
templates, and the host library launches images only, so they are refused
with `SandboxModeError`; Obscura's fixed command is refused by the in-process
launcher with `MachineSpecError` until it supports command overrides. Both
still record normally.

## Local SDK development

When changing the Python SDK in this repo:

```sh
cargo build -p mvm-hostlib
export MVM_HOSTLIB_PATH="$PWD/target/debug/libmvm_hostlib.dylib"  # .so on Linux
export MVM_SDK_RUN_PROFILE=dev  # explicit opt-in for files/process verbs
uv venv
. .venv/bin/activate
uv pip install -e sdks/python
```

That gives you an editable SDK install from the checkout, with every
machine/sandbox call going to the worktree-built host library.

Useful local commands:

```sh
just sdk-build-python
uv run --directory sdks/python pytest
PYTHONPATH="$PWD/sdks/python" python3 app.py
```

Use `PYTHONPATH=...` when you want a zero-install checkout run; use the editable
install when you want a more normal virtualenv workflow.

## Optional extras

```sh
pip install 'mvm[schema]'   # pydantic-based schema derivation from type hints
```

## Versioning

Published SDK releases are cut explicitly from `sdk-vX.Y.Z` tags. The Python
package and the TypeScript package share that SDK release version and are
validated against `sdks/release.toml` before publishing.

## Links

- Source & issues: https://github.com/tinylabscom/mvm
- TypeScript SDK: [`@runmvm/mvm`](https://www.npmjs.com/package/@runmvm/mvm)

## License

Apache-2.0 — see [LICENSE](./LICENSE).
