# mvm — Python SDK

Declare a microVM workload in Python. Write a function, decorate it, and the
`mvmctl` toolchain bakes it into a Nix-built Firecracker / libkrun microVM
image and boots it — no Dockerfile, no SSH, no agent code in your app.

```sh
pip install mvm
```

`mvmctl` (the Rust host CLI) is distributed separately and does the building,
booting, and signing. This package is the **authoring** surface it reads.

## Read the local checkpoint catalog

`mvm.checkpoint.list()` calls the client-owned `checkpoint.list` host-library
method (ABI 1.10); it never runs `mvmctl` or boots a VM. It returns complete
metadata dictionaries in checkpoint-ID order, with legacy omitted fields left
omitted. A missing catalog is empty. Invalid metadata, mismatched IDs, unsafe
metadata paths, non-regular metadata files, and metadata over 16 MiB fail the
whole operation with a host-library error, not a partial list. Staging,
non-directory entries and directories without metadata are ignored.

This is the same data as `mvmctl machine checkpoint ls --json`. Listing neither
opens checkpoint content nor authenticates lineage or grants restore authority.

## Verify checkpoint lineage

`mvm.checkpoint.verify_lineage(id)` calls the host-local
`checkpoint.verify_lineage` method (ABI 1.12), returning `None` on success.
It uses the same client-owned signed-audit ancestry verification as
`mvmctl machine checkpoint verify`. Missing, altered or unaudited ancestry
raises a nonretryable host error; invalid IDs are refused before anchor access.
No root or trust-key override, VM boot, HTTP server or subprocess is involved.

This verifies metadata lineage, not snapshot blob bytes, runtime compatibility
or permission to restore. Loading the existing host anchor may initialize its
identity when an audit directory exists.

## Prompt-step checkpoints (Linux/Firecracker)

On a running machine with a plan that grants prompts, call
`mvm.Machine(name).prompt("first", checkpoint=True)` to request an opt-in
`vm_full` step checkpoint. The reply has the agent's answer even if checkpoint
capture fails: check `checkpoint_failed` before using `checkpoint_id`. A
duplicate idempotency key does not send another prompt. An ID alone does not
verify lineage or authorize restore; call `mvm.checkpoint.verify_lineage(id)`
and restore under current admission.

The host-library path to an **existing HVF machine is currently refused**
before prompt delivery. This SDK operation is live-witnessed on
Linux/Firecracker, not yet supported through hostlib on macOS/HVF. The CLI's
native workflow is a different call path; it does not establish SDK parity.

## Quick start

```python
# app.py
import mvm as mv

@mv.func(name="adder")
def add(a: int, b: int) -> int:
    return a + b
```

```sh
mvmctl dev compile app.py   # parse the script (no execution) → flake.nix + launch plan
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

`mvmctl dev compile` reads your file **statically** — the decorator and the
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
| `mv.secrets.get("name", tenant="local")` | host-local metadata or `None` if absent; never reads the value |

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
`flake:<ref>#<attr>`) or from a named `template`, as a named machine started
the way `mvmctl machine run -d` starts one; `kill()` stops and removes it. A
template is one built on this host, found by the name its image was built
under; one nobody built is refused with `MachineSpecError` saying how to build
it. `command=` starts once
the machine is up, with `env=` as its environment (literal values only, and
the host's denylist refuses loader, shell and credential variables), and
`sb.process` is its handle. `Sandbox.connect(name)` attaches to a machine that
is already running.

Live process handles support `wait`, streamed stdout/stderr callbacks,
`send_stdin`, `signal`, and `kill`. The filesystem surface supports read,
write, list, stat, mkdir, remove, and move. `sb.shell(...)` is a convenience
for `/bin/sh -lc` in development only.

Process execution, shell, process control, filesystem access and copies fail
closed with `SandboxDevOnly` before any request leaves the process when the
machine is not a development build (a launch under any profile other
than the default `dev`, such as `--profile standard`, resolves to one); the guest agent refuses them on a
production build too. Dynamic port forwarding is refused: declare ingress
with `network=` before boot. SSH is not part of the SDK or runtime contract.

## In-guest actors and durable messages

`mvm.actor` and `mvm.mailbox` are the in-guest interfaces for the initial
**cold native HVF workflow**: one admitted controller and depth-one,
non-delegating workers. They are separate from host-local `Machine` and
`Sandbox` automation. Launch the parent with
`mvmctl actor launch MANIFEST [--json]`, using a host-authored exact manifest
with finite budgets and validity windows. The native HVF witness exercises the
shared actor/mailbox path with Rust guest fixtures. Python wrapper tests are
separate; that native witness is not evidence of a Python-guest end-to-end run.

### Lifecycle authority

The parent must have workflow membership, an explicit lifecycle grant, and
the admitted `host.actor.v1` service. A direct workload has no implicit actor
authority, and a worker cannot recursively launch another worker.

| Python API | Meaning |
| --- | --- |
| `mvm.actor.launch_child(grant_id, template_id, *, idempotency_key, timeout_secs=60.0)` | Select one exact template from the signed grant |
| `mvm.actor.observe_child(handle, *, timeout_secs=60.0)` | Observe the child bound to this authenticated controller |
| `mvm.actor.release_child(handle, *, idempotency_key, timeout_secs=60.0)` | Request destruction; do not assume cleanup has finished |

These calls use the admitted encrypted lifecycle channel. They carry no task
payload, arbitrary argv/environment, resource overrides, backend selection,
or placement. Templates determine what a child runs; task data travels through
the mailbox instead.

Each call returns one of the following typed outcomes:

- `Pending(request_id)`: durable intent exists, without a completed launch result.
- `Running(handle)`: the host confirmed the admitted child is running.
- `Released(request_id)`: child death, resource cleanup, and the terminal record
  are confirmed.
- `Refused(code)`: the operation was refused without granting authority.
- `Unknown(request_id)`: dispatch occurred but its result is uncertain.

`Unknown` is not permission to redispatch with a new idempotency key, and it
does not mean released. Retain the original operation identity when reconciling
an uncertain result. The SDK does not automatically retry lifecycle calls.
A transport exception or timeout also does not establish that no effect occurred.
Only `Released` confirms release; used children never reenter shared warm capacity.

`Running.handle` is an `ActorHandle`. Its opaque token is redacted from `repr`;
do not serialize it into logs. The host checks the token against its journal and
the authenticated controller boot. Constructing or copying a Python handle
does not mint authority. `handle.mailbox` returns the canonical mailbox address,
not a host route, and knowing that address does not grant permission to send.

### Explicit mailbox calls, replies, and acknowledgements

`mvm.mailbox` uses the dedicated encrypted mailbox channel and its existing
guest-local reader bridge, not the lifecycle broker. The boot projection pins
the canonical address, policy epoch, and reader identity; the guest does not
accept a replacement identity from a host handshake.

| Python API | Meaning |
| --- | --- |
| `mvm.mailbox.call(destination, payload, *, message_id, correlation_id, deadline_unix_ms, content_type, timeout_secs=60.0)` | Queue a call under explicit, retained message identities |
| `mvm.mailbox.receive(*, timeout_secs=60.0)` | Receive an authorized request without acknowledging its application effect |
| `mvm.mailbox.reply(request_message_id, payload, *, message_id, content_type, timeout_secs=60.0)` | Reply under that request's scoped reply authority, not an arbitrary reverse-send grant |
| `mvm.mailbox.receive_result(call_message_id, *, timeout_secs=60.0)` | Receive a reply correlated to the original call |
| `mvm.mailbox.ack_request(request_message_id, *, lease, timeout_secs=60.0)` | Acknowledge processing of the exact delivered request lease |
| `mvm.mailbox.ack_result(call_message_id, result_message_id, *, lease, timeout_secs=60.0)` | Acknowledge processing of the exact delivered reply lease |

Payloads are `bytes`. Message and correlation IDs are exactly 32-byte `bytes`
values; retain them across recovery rather than generating new IDs for an
uncertain operation. `destination` is a canonical address dictionary, such as
the one returned by `handle.mailbox`. `content_type` is a dictionary with
`name` and `version` fields selected from the workload's actual mailbox policy.
`deadline_unix_ms` is an explicit absolute deadline;
`timeout_secs` bounds the local operation and does not extend mailbox authority.
Mailbox timeouts must be finite and between 1 and 300 seconds; the shared C ABI
uses whole seconds. Python delegates framing to that Rust transport rather than
implementing a separate mailbox wire. Conversation wire version 2 carries the
remaining caller budget through the guest-local bridge and authenticated host
exchange. Queueing and handshake time consume that budget. Receive waits are
also capped by signed reader/enrollment expiry and the retained call deadline;
disconnecting the local caller cancels its wait, not the durable call itself.
Version 1 conversation frames refuse rather than being guessed or downgraded.
The current guest bridge admits one active exchange. Concurrent operations receive
an explicit unavailable refusal instead of waiting behind a long Receive. Cancel
or finish that observation before issuing a Reply, ACK, or another Call from the
same guest. Expiration ends the observation; it does not promise a `pending`
response after the response deadline or establish non-execution.
Freshly signed enrollment or delivery material can require a short bounded wait
for the guest clock to reach its issuance time. This consumes the existing caller
budget; it does not adjust clocks, accept future authority, or extend a lease.

Responses are dictionaries. A `queued` outcome from `call` means durable source
intent, not destination acceptance and not an application reply. Even destination
acceptance as durable is distinct from application processing. Only an outcome
of `delivery` carries a delivered message: its `payload` is decoded to `bytes`,
its `header` identifies the message, and its `lease` is the canonical delivery
lease needed for acknowledgement.

Process the delivered payload before acknowledging it. Pass the **exact**
`delivery["lease"]` to `ack_request` or `ack_result`, along with the matching
message IDs from the delivered header and original call. Convert header ID
arrays to `bytes`, for example `bytes(delivery["header"]["message_id"])`.
The guest bridge signs the canonical ACK; the SDK does not fabricate or replace
the lease. An `acknowledged` outcome confirms the ACK operation, not a separate application
reply. Receiving, replying, and acknowledging are separate calls; none implicitly
acknowledges another.

The transport is at-least-once, so applications must deduplicate effects.
`pending` and `timed_out` do not prove that the remote handler did not execute.
The SDK does not automatically retry, ACK, or treat an uncertain response as
permission to repeat application effects. These boundaries rely on the trusted
host and admitted policy; they do not provide confidentiality from a compromised
active host.

## Machine lifecycle

`mv.Machine` covers the machine lifecycle for host automation. Admission,
OCI verification, audit and persistent machine state belong to the host
library, the same code `mvmctl` runs; the SDK validates arguments and shapes
requests.

```python
import mvm as mv

# Boot, run one command, collect its output, stop and remove the machine. Dev builds only.
result = mv.Machine.run("alpine:latest", ["uname", "-a"], timeout=60)
print(result.exit_code, result.stdout)

vm = mv.Machine.launch("alpine:latest", allow_hosts=["example.com:443"], ttl_seconds=600)
print(vm.name, vm.build_mode, vm.inspect()["status"])
vm.stop()

devbox = mv.Machine.create("devbox", "alpine:latest", profile="dev")
devbox.start()
result = devbox.exec(["echo", "hello"])   # dev builds only
print(result.exit_code, result.stdout)
print(devbox.logs(lines=20))
for chunk in devbox.logs(follow=True):     # until the machine stops, or `break`
    print(chunk, end="")
devbox.stop()
devbox.rm()

for record in mv.Machine.ls():
    print(record["name"], record["build_mode"], record["status"])
```

## Host-local telemetry reads

```python
import mvm

status = mvm.telemetry.status("worker")
page = mvm.telemetry.records("worker", limit=100)
next_page = mvm.telemetry.records("worker", cursor=page["next_cursor"])
```

Each call reads once through the existing host ABI; it does not start a
collector, poll, retry, or run a CLI. Keep cursors with the machine and record
file that produced them. The host defaults to 256 records and clamps supplied
limits, including zero, to 1–1024. `exhausted` describes the current file end,
not completion of the workload. An empty page is not a health assertion.

Typed envelopes validate known fields and preserve collection state, loss counts,
omitted receive times, additive fields and opaque nested record JSON without
interpreting health. This is not full Rust record validation. Python preserves
unsigned 64-bit cursor integers. Invalid arguments raise `ValueError`; malformed
reply envelopes raise `mvm.telemetry.TelemetryError`. Host refusals retain the
existing typed `HostLibraryError` code and retryability. No automatic cursor
reset occurs on a host refusal.

## Host library

The SDK never runs `mvmctl` or any other program. Every live `Sandbox` and
`Machine` call goes to `libmvm_hostlib` (`.dylib` on macOS, `.so` on Linux),
loaded into the Python process and spoken to over its C ABI. It is found by
looking, in order, at:

1. `MVM_HOSTLIB_PATH` — the library file itself. If it is set and names
   nothing, that is an error; the SDK does not fall back to another copy.
2. `mvm/_native/` inside the installed package. Every published wheel
   carries it: `manylinux2014` (glibc 2.17 or newer) and `musllinux_1_2`
   wheels for x86_64 and aarch64 Linux, and an arm64 macOS wheel. The sdist
   does not, so an install from source falls through to the next entry.
3. The directory holding `mvmctl` on `PATH`, and the directory of the file
   that path resolves to. `mvmctl` is only located, never run.

When none of these has it, calls raise `mv.MvmTransportError` naming all
three. A refusal from the library raises the typed error its code names —
`mv.MachineNotFoundError`, `mv.MachineSpecError`, `mv.MachineConflictError`,
`mv.MachineUnavailableError` (retryable), and so on, all subclasses of
`mv.HostLibraryError` carrying `code` and `retryable`.

Function dispatch goes through the library too. `await f(...)`, `f.sync(...)`
and a `workload_ref` call run the workload's entrypoint in a transient
microVM through `entrypoint.call`, admitted under a signed plan and audited
exactly as `mvmctl machine run --entrypoint` is; `mv.session(...)` holds one
warm microVM across calls (`session.start`, `session.call`, `session.stop`).
The workload is found among the images built on this host by the name it was
declared with; build it first (`mvmctl dev compile`, then
`mvmctl machine build --flake <dir>`). An error the function raised arrives as
the generated `RemoteError` with its kind and id; a failure with no such
envelope is `MvmTransportError` with the exit code and the end of stderr. A
payload over one agent frame (62 KiB) travels on the streaming input plane for
a transient call and is refused for a session call, never truncated. The host
runs the workload's primary entrypoint: the guest protocol has no function
selector, so a non-primary function of a multi-function workload is not
reachable this way yet. Set `MVM_NO_VM=1` to run decorated functions in the
calling process through the same encode, size-check and decode path a
microVM call takes; inside that mode `mv.session(...)` is a local scope.

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

Every preset boots in live mode. Obscura boots its pinned image and starts its
fixed command once the machine is up. Chromium and Chrome boot the template
built on this host under that name; with no such template the launch is refused with `MachineSpecError`
saying how to build one. All of them still record normally.

## Workload packs

`mvm.packs` writes a `mvm.pack-spec/v1` document. The builder only assembles
and checks data: it reads no file, builds nothing and holds no key.

```python
from mvm.packs import pack

(
    pack("acme/hello", "1.0.0")
    .target("x86_64-linux")
    .source("app")
    .package("busybox")
    .copy("hello.txt", "/app/hello.txt")
    .entrypoint("cat", "/app/hello.txt")
    .resources(cpu_cores=1, memory_mib=256)
    .write("pack.json")
)
```

`mvmctl pack lock pack.json --mvm-revision <commit>` freezes it, and
`mvmctl build pack.json --out hello.mvmpkg` compiles, builds, health-boots
and signs it. The bytes are the canonical bytes every language SDK writes for
the same spec, and a mistake raises `PackSpecError` with
the same `code` in every language.

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
just build sdk python
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
