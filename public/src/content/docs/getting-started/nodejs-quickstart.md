---
title: Node.js quickstart
description: Use the current TypeScript SDK runtime surface and static workload declarations.
---

This page shows the current TypeScript SDK shape for local sandbox lifecycle and static workload declarations.

> **Status:** The TypeScript package in `crates/mvm-sdk/sdks/typescript` has `Sandbox.create(...)`, `commands.start(...)`, `files.write(...)`, record mode, live mode, and `Symbol.dispose` cleanup. Higher-level runtime methods are parity work.

## Imperative runtime

```ts
import { Sandbox } from "@runmvm/mvm";

using sandbox = Sandbox.create("node-22", { workloadId: "quickstart" });
sandbox.files.write("/app/main.js", "console.log('hello from mvm')");
sandbox.commands.start(["node", "/app/main.js"]);
```

Plan-check the script:

```sh
mvmctl run --mode plan ./quickstart.ts
```

Run it against a local microVM:

```sh
mvmctl run --mode live ./quickstart.ts
```

## Static declaration

```ts
import * as mvm from "@runmvm/mvm";

export const hello = mvm.app({
  image: mvm.nix_packages(["nodejs_22"]),
  resources: mvm.resources({ cpu_cores: 1, memory_mb: 512 }),
  network: mvm.network({ mode: "none" }),
})((name: string): string => `hello ${name}`);
```

The static compiler reads the declaration from source. It rejects non-literal values in declaration position so build-time behavior stays inspectable.

```sh
mvmctl build compile ./app.ts --out /tmp/hello-node
mvmctl machine build --flake /tmp/hello-node
```

## Security checklist

- Keep application inputs separate from host-side SDK code.
- Use immutable image inputs or Nix package sets for production builds.
- Treat runtime mode as host-executed SDK code.
- Keep egress closed unless the workload explicitly needs it.
