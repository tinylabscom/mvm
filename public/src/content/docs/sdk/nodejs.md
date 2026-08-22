---
title: Node.js SDK
description: TypeScript and Node.js runtime and decorator SDK status.
---

The TypeScript SDK currently exposes both runtime and declarative surfaces.

## Runtime

Current:

- `Sandbox.create(template, options)`
- `sandbox.commands.start(argv, options)`
- `sandbox.files.write(path, content)`
- `using` cleanup through `Symbol.dispose`
- record mode for plan/build flows;
- live mode through `mvmctl run --mode live`

Planned:

- command result capture through `commands.run(...)`;
- file read/list/remove;
- logs and event streams;
- port helpers;
- snapshot, cold, resume, detach, destroy;
- additional lifecycle result types once the local runtime transport supports them.

## Declaration

```ts
import * as mvm from "mvm-sdk";

export const worker = mvm.app({
  image: mvm.nix_packages(["nodejs_22"]),
  resources: mvm.resources({ cpu_cores: 1, memory_mb: 512 }),
  network: mvm.network({ mode: "deny" }),
})((input: string): string => input.toUpperCase());
```

The AST compiler accepts the supported literal declaration shape and lowers it into Workload IR.


### AI egress budget

```ts
export const llmWorker = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  network: mvm.network({
    mode: "bridge",
    egress: mvm.egress([mvm.hostPort("api.openai.com", 443)]),
    ai: mvm.aiPolicy({
      metering: true,
      budget: mvm.aiBudget({ maxTotalTokens: 100_000 }),
    }),
  }),
})((prompt: string): string => {
  ...
});
```

## Security notes

- Runtime scripts execute host-side SDK code.
- Prefer static declarations for deployable workloads.
- Do not place raw credentials in source examples.
- Keep egress explicit and narrow.

See [Runtime modes](/sdk/runtime-modes/) before using live mode in automation.
See [Operations cookbook](/sdk/operations-cookbook/) for current calls, target helpers, and CLI fallbacks.
