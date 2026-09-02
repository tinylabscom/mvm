---
title: Any language
description: Run non-Python and non-Node workloads with Nix packages and command entrypoints.
---

The runtime is language-agnostic. Python and TypeScript SDKs are authoring surfaces; the guest workload can be any language packaged into the microVM image.

## Pattern

1. Add the runtime package through Nix.
2. Copy source into the guest image or write it through the runtime SDK.
3. Set an argv entrypoint or start command.
4. Declare network and resource limits explicitly.

Example command entrypoint in Workload IR authoring:

```rust,ignore
// illustrative: one builder call shown on its own, without the surrounding workload
entrypoint_command(["bash", "-lc", "your-runtime your-program"])
```

## Security notes

- Prefer pinned package sets.
- Avoid install-at-runtime workflows for production artifacts.
- Use digest-pinned OCI inputs only when the Nix path is not practical.
