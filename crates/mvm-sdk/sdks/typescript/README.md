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

`Sandbox` has explicit `record` and `live` modes. In live mode it uses
`mvmctl` to boot or attach to a development machine and exposes generated
process/filesystem contract types:

```ts
import { Sandbox } from "@runmvm/mvm";

const sb = Sandbox.create("node-22");
const process = sb.commands.start(["node", "-e", "console.log('ready')"]);
const result = await process!.wait({ onEvent: (event) => console.log(event.stream, event.data) });
sb.files.write("/app/config.json", '{"ready":true}');
console.log(new TextDecoder().decode(sb.files.read("/app/config.json")));
sb.kill();
```

Live process handles support `wait`, streamed stdout/stderr callbacks,
`sendStdin`, `signal`, and `kill`. The filesystem surface supports read,
write, list, stat, mkdir, remove, and move. `sb.shell(...)` is a convenience
for `/bin/sh -lc` in development only.

Arbitrary process execution, shell, process control, filesystem RPC, and port
forwarding fail closed before CLI traffic for production templates. SSH is not
part of the SDK or runtime contract.

## Machine lifecycle wrappers

`Machine` mirrors the beginner `mvmctl machine ...` command group for host
automation. These wrappers deliberately shell to `mvmctl machine ...`; OCI pull,
admission, artifact verification, receipts, audit, networking, and persistent
machine state stay owned by the CLI instead of being reimplemented in
TypeScript.

```ts
import { Machine } from "@runmvm/mvm";

const result = Machine.run({
  image: "alpine:latest",
  command: ["uname", "-a"],
  net: true,
  allowHosts: ["example.com:443"],
});
console.log(result.stdout);

const artifact = Machine.checkArtifact({ path: "app.mvm", json: true });
console.log(artifact.stdout);

const vm = Machine.create({ name: "devbox", manifest: "mvm.toml", profile: "dev" });
vm.start();
vm.exec(["echo", "hello"]);
vm.stop();
```

The SDK resolves its CLI in this order: `MVM_CLI_BIN`, then `mvmctl`.
Published SDK packages use the ordinary `mvmctl` release; source-checkout
users can still point `MVM_CLI_BIN` at a locally built `mvmctl`. CLI process
failures raise `MachineError` with `argv`, `exitCode`, and captured `stderr`.

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

## Local SDK development

When changing the TypeScript SDK in this repo:

```sh
cargo build -p mvm-cli
export MVM_CLI_BIN="$PWD/target/debug/mvmctl"
export MVM_SDK_RUN_PROFILE=dev  # explicit opt-in for files/process verbs
just sdk-install-typescript
just sdk-build-typescript
```

That keeps SDK subprocess calls pinned to the worktree-built `mvmctl` while
producing the publishable package output in `sdks/typescript/dist/`.

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
