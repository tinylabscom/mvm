# @runmvm/mvm — TypeScript SDK

Declare a microVM workload in TypeScript. Describe an app, and the `mvmctl`
toolchain bakes it into a Nix-built Firecracker / libkrun microVM image and
boots it — no Dockerfile, no SSH, no agent code in your app.

```sh
npm install @runmvm/mvm
```

`mvmctl` (the Rust host CLI) is distributed separately and does the building,
booting, and signing. This package is the **authoring** surface it reads.

## Quick start

```ts
// app.ts
import * as mvm from "@runmvm/mvm";

mvm.workload({ id: "hello" });

export const greet = mvm.app({
  image: mvm.node_image({ node: "22" }),
  resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
})((name: string): string => `hello ${name}`);
```

```sh
mvmctl build compile app.ts   # parse the file (no execution) → flake.nix + launch plan
mvmctl machine run --flake .  # build the image and boot the microVM
```

`mvm.app({...})` is higher-order: it records the declaration and returns the
function unchanged, so the same file runs normally under `tsx` / `node` and is
also read statically by `mvmctl build compile`.

## How it builds

`mvmctl build compile` reads your file **statically** — the `mvm.app({...})` call and
the `import` are parsed as data, never executed, so nothing in your module runs
on the host. At image-build time the framework call and the `@runmvm/mvm` import
are **stripped** from the bundled source, so the guest runs your plain function
with no SDK dependency inside the microVM.

You can also emit the canonical Workload IR in-process, for inspection or tests:

```ts
import * as mvm from "@runmvm/mvm";
console.log(mvm.emitJson());   // the IR mvmctl would produce
```

## Lifecycle hooks

Four hook points, each a shell string or an argv list, passed as kwargs to
`mvm.app({...})`. Addons contribute their own hooks, merged at compile time:

| Hook | Runs |
| --- | --- |
| `before_build` | in the builder VM, before the image is assembled |
| `before_start` | in the guest, before the entrypoint |
| `after_start`  | in the guest, after the entrypoint is up |
| `before_stop`  | in the guest, on shutdown |

```ts
mvm.app({
  image: mvm.node_image({ node: "22" }),
  env: { API_KEY: mvm.secret("api-key") },
  before_start: mvm.hook("export TZ=UTC"),
  after_start: mvm.hook(["curl", "-fsS", "http://localhost:8080/health"]),
})((name: string) => `hello ${name}`);
```

## Building blocks

| Helper | Purpose |
| --- | --- |
| `mvm.nix_packages([...])`, `mvm.node_image({...})`, `mvm.python_image({...})` | base image |
| `mvm.resources({ cpu, memory_mb, rootfs_size_mb })` | per-VM budget |
| `mvm.network({ mode, ports })` | egress policy (default `none`) |
| `mvm.secret("name")`, `mvm.literal("v")` | env values — secrets resolve on the host, never baked into the image |
| `mvm.entrypoint({...})`, `mvm.entrypoint_function({...})` | explicit / multi-function entrypoints |

The IR types (`Workload`, `App`, `Resources`, …) are re-exported, so
`import { Workload } from "@runmvm/mvm"` works directly.

### Call schemas

`entrypoint_function` takes optional `args_schema` and `return_schema`:

```ts
mvm.entrypoint_function({
  module: "./handlers.js",
  function: "greet",
  args_schema: { type: "object", properties: { name: { type: "string" } } },
  return_schema: { type: "string" },
});
```

If you have used the Python SDK you may be looking for `derive_schema`,
which builds these from a function's type hints. **TypeScript has no
equivalent, and cannot.** Types are erased before the program runs, so by
the time a decorator could inspect your function the annotations no
longer exist — `(name: string) => string` and `(name: any) => any` are
the same value at runtime. This is a property of the language rather
than a gap in the SDK, so pass the schema explicitly. Both fields are
optional; omit them and the host derives what it can at compile time.

## Runtime SDK

`Sandbox` has explicit `record` and `live` modes. Record mode is the portable
authoring path; live mode boots or attaches to a development machine through
the host library (below) and exposes the generated process/filesystem
contract types:

```ts
import { Sandbox } from "@runmvm/mvm";

const sb = Sandbox.create({ image: "node:22-slim" });
const process = sb.commands.start(["node", "-e", "console.log('ready')"]);
const result = await process!.wait({ onEvent: (event) => console.log(event.stream, event.data) });
sb.files.write("/app/config.json", '{"ready":true}');
console.log(new TextDecoder().decode(sb.files.read("/app/config.json")));
sb.kill();
```

Live mode boots from `{ image }` (an OCI reference, an absolute path, or
`flake:<ref>#<attr>`); a template source is recorded in record mode but
refused in live mode, because the host library launches images only.
`Sandbox.connect(name)` attaches to a machine that is already running.

Live process handles support `wait`, streamed stdout/stderr callbacks,
`sendStdin`, `signal`, and `kill`. The filesystem surface supports read,
write, list, stat, mkdir, remove, and move. `sb.shell(...)` is a convenience
for `/bin/sh -lc` in development only.

Process execution, shell, process control, filesystem access and copies fail
closed with `SandboxDevOnly` before any request leaves the process when the
machine is not a development build; the guest agent refuses them on a
production build too. Dynamic port forwarding is refused: declare ingress
with `network` before boot. SSH is not part of the SDK or runtime contract.

## Machine lifecycle

`Machine` covers the machine lifecycle for host automation. Admission, OCI
verification, audit and persistent machine state belong to the host library,
the same code `mvmctl` runs; the SDK validates arguments and shapes requests.

```ts
import { Machine } from "@runmvm/mvm";

const vm = Machine.run("alpine:latest", { allowHosts: ["example.com:443"], ttlSeconds: 600 });
console.log(vm.name, vm.inspect().status);
vm.stop();

const devbox = Machine.create("devbox", "alpine:latest", { profile: "dev" });
devbox.start();
const result = devbox.exec(["echo", "hello"]); // dev builds only
console.log(result.exitCode, result.stdout);
console.log(devbox.logs({ lines: 20 }));
devbox.stop();
devbox.rm();

for (const record of Machine.ls()) {
  console.log(record.name, record.build_mode, record.status);
}
```

## Host library

The SDK never runs `mvmctl` or any other program. Every live `Sandbox` and
`Machine` call goes to `libmvm_hostlib` (`.dylib` on macOS, `.so` on Linux),
loaded into the Node process through `koffi` and spoken to over its C ABI. It
is found by looking, in order, at:

1. `MVM_HOSTLIB_PATH` — the library file itself. If it is set and names
   nothing, that is an error; the SDK does not fall back to another copy.
2. `native/` inside the installed package, for a package that bundles the
   library.
3. The directory holding `mvmctl` on `PATH`, and the directory of the file
   that path resolves to. `mvmctl` is only located, never run.

When none of these has it, calls throw `MvmTransportError` naming all three.
A refusal from the library throws the typed error its code names —
`MachineNotFoundError`, `MachineSpecError`, `MachineConflictError`,
`MachineUnavailableError` (retryable), and so on, all subclasses of
`HostLibraryError` carrying `code` and `retryable`.

What the library cannot do yet, the SDK refuses rather than working around:
the in-process launcher refuses a boot `command` or `env` override
(`MachineSpecError`), and function dispatch into a microVM throws
`MvmTransportError`. Set `MVM_NO_VM=1` to run decorated functions in the
calling process through the same encode, size-check and decode path a
microVM call takes; inside that mode `session(...)` is a local scope.

## Experimental Obscura browser provider

`new BrowserSandbox()` still defaults to Chromium. Obscura is an explicit,
experimental opt-in for live development:

```ts
import { BrowserSandbox } from "@runmvm/mvm";

const browser = new BrowserSandbox("obscura", {
  network: {
    mode: "none",
    egress: { allowlist: [{ host: "example.com", port: 443 }] },
  },
});
const websocketUrl = await browser.waitUntilReady();
```

Set `MVM_SDK_MODE=live`. The provider uses the exported `OBSCURA_IMAGE`, a
digest-pinned OCI reference; fixes CDP to guest loopback; explicitly routes
browser traffic through the mvm proxy; and rejects command overrides. It does
not enable private-network access, stealth behavior, or unrestricted egress.
Obscura is not a guaranteed drop-in replacement for every Playwright or
Puppeteer flow.

Neither preset boots in live mode yet. Chromium and Chrome are named
templates, and the host library launches images only, so they are refused
with `SandboxModeError`; Obscura's fixed command is refused by the in-process
launcher with `MachineSpecError` until it supports command overrides. Both
still record normally.

## Local SDK development

When changing the TypeScript SDK in this repo:

```sh
cargo build -p mvm-hostlib
export MVM_HOSTLIB_PATH="$PWD/target/debug/libmvm_hostlib.dylib"   # .so on Linux
export MVM_SDK_RUN_PROFILE=dev  # explicit opt-in for files/process verbs
just sdk-install-typescript
just sdk-build-typescript
```

That pins the SDK to the worktree-built host library while producing the
publishable package output in `sdks/typescript/dist/`.

Useful local commands:

```sh
npm --prefix sdks/typescript run test
npm --prefix sdks/typescript run build
npm install "$PWD/sdks/typescript"
```

For publish-shape rehearsal, prefer packing and installing the tarball instead
of importing source files directly:

```sh
npm --prefix sdks/typescript pack
```

## Versioning

Published SDK releases are cut explicitly from `sdk-vX.Y.Z` tags. The Python
package and the TypeScript package share that SDK release version and are
validated against `sdks/release.toml` before publishing.

## Links

- Source & issues: https://github.com/tinylabscom/mvm
- Python SDK: [`mvm`](https://pypi.org/project/mvm/)

## License

Apache-2.0
