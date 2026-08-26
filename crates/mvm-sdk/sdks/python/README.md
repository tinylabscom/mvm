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
authoring path; live mode attaches to or boots a development machine through
`mvmctl` and exposes the generated process/filesystem contract:

```python
import mvm

with mvm.Sandbox.create("python-3.12") as sb:
    process = sb.commands.start(["python", "-c", "print('ready')"])
    result = process.wait(on_event=lambda event: print(event.stream, event.data))
    sb.files.write("/app/config.json", '{"ready": true}')
    print(sb.files.read("/app/config.json"))
```

Live process handles support `wait`, streamed stdout/stderr callbacks,
`send_stdin`, `signal`, and `kill`. The filesystem surface supports read,
write, list, stat, mkdir, remove, and move. `sb.shell(...)` is a convenience
for `/bin/sh -lc` in development only.

Arbitrary process execution, shell, process control, filesystem RPC, and port
forwarding fail closed before CLI traffic for production templates. SSH is not
part of the SDK or runtime contract.

## Machine lifecycle wrappers

`mv.Machine` mirrors the beginner `mvmctl machine ...` command group for host
automation. These wrappers deliberately shell to `mvmctl machine ...`; OCI pull,
admission, artifact verification, receipts, audit, networking, and persistent
machine state stay owned by the CLI instead of being reimplemented in Python.

```python
import mvm as mv

result = mv.Machine.run(
    image="alpine:latest",
    command=["uname", "-a"],
    net=True,
    allow_hosts=["example.com:443"],
)
print(result.stdout)

artifact = mv.Machine.check_artifact(path="app.mvm", json=True)
print(artifact.stdout)

vm = mv.Machine.create(name="devbox", manifest="mvm.toml", profile="dev")
vm.start()
vm.exec(["echo", "hello"])
vm.stop()
```

The SDK resolves its CLI in this order: `MVM_CLI_BIN`, then `mvmctl`.
Published SDK packages use the ordinary `mvmctl` release; source-checkout
users can still point `MVM_CLI_BIN` at a locally built `mvmctl`. CLI process
failures raise `mv.MachineError` with `argv`,
`exit_code`, and captured `stderr`.

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

## Local SDK development

When changing the Python SDK in this repo:

```sh
cargo build -p mvm-cli
export MVM_CLI_BIN="$PWD/target/debug/mvmctl"
export MVM_SDK_RUN_PROFILE=dev  # explicit opt-in for files/process verbs
uv venv
. .venv/bin/activate
uv pip install -e sdks/python
```

That gives you an editable SDK install from the checkout while keeping all
machine/sandbox subprocess calls pinned to the worktree-built `mvmctl`.

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
