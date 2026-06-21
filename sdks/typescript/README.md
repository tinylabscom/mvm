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
mvmctl compile app.ts     # parse the file (no execution) → flake.nix + launch plan
mvmctl up --flake .       # build the image and boot the microVM
```

`mvm.app({...})` is higher-order: it records the declaration and returns the
function unchanged, so the same file runs normally under `tsx` / `node` and is
also read statically by `mvmctl compile`.

## How it builds

`mvmctl compile` reads your file **statically** — the `mvm.app({...})` call and
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

Set `MVM_CLI_BIN=/path/to/mvmctl` to point the SDK at a local or test CLI
binary. CLI process failures raise `MachineError` with `argv`, `exitCode`, and
captured `stderr`.

## Versioning

The SDK version tracks the `mvmctl` toolchain version: a workload emitted by
`@runmvm/mvm` X.Y.Z is consumed by `mvmctl` X.Y.Z. Install matching versions.

## Links

- Source & issues: https://github.com/tinylabscom/mvm
- Python SDK: [`mvm`](https://pypi.org/project/mvm/)

## License

Apache-2.0
