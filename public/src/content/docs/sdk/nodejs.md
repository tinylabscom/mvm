---
title: Node.js SDK
description: TypeScript and Node.js runtime and decorator SDK status.
---

The TypeScript SDK currently exposes both runtime and declarative surfaces.

## Runtime

Current:

- `Sandbox.create(template, options)`
- `sandbox.commands.start(argv, options)` — the only method on `commands`
- `sandbox.exec(argv, options)` / `sandbox.shell(command, options)` — one-shot with a captured `ExecResult` (live mode only)
- `sandbox.files.write/read/list/stat/mkdir/remove/move(...)` — everything but `write` is live mode only
- `sandbox.copyIn(...)` / `sandbox.copyOut(...)`
- `using` cleanup through `Symbol.dispose`
- record mode for plan/build flows;
- live mode through `mvmctl run --mode live`

Planned:

- logs and event streams;
- snapshot, cold, resume, detach, destroy;
- additional lifecycle result types once the local runtime transport supports them.

There is no `commands.run(...)`. `sandbox.forward(...)` exists only to refuse:
ingress is declared before boot through `network({ ports: [...] })`.

## Declaration

```ts
import * as mvm from "@runmvm/mvm";

export const worker = mvm.app({
  image: mvm.nix_packages(["nodejs_22"]),
  resources: mvm.resources({ cpu_cores: 1, memory_mb: 512 }),
  network: mvm.network({ mode: "none" }),
})((input: string): string => input.toUpperCase());
```

The AST compiler accepts the supported literal declaration shape and lowers it into Workload IR.


### AI egress budget

```ts
export const llmWorker = mvm.app({
  image: mvm.python_image({ python: "3.12" }),
  // The TypeScript `network()` surface is mode + ports + ai today; an egress
  // allow-list is declared from Python or in mvm.toml.
  network: mvm.network({
    mode: "bridge",
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
