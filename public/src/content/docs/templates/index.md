---
title: Templates
description: Reusable mvm project blueprints built from manifests and Nix flakes.
---

The `mvmctl template` mutation verbs are gone; `mvmctl template` survives as a
read-only registry browser (`list`, `search`, `info`). The current reusable
blueprint is a project directory with:

- `mvm.toml` or `Mvmfile.toml` for build input and runtime sizing;
- `flake.nix` for the guest rootfs, packages, users, services, and kernel/rootfs content;
- optional source files used by the guest image.

This keeps the boundary small: the manifest says what to build and how large
the runtime sandbox should be; the flake says what goes inside the microVM.

## Everyday flow

```sh
mvmctl init my-worker --preset worker
cd my-worker
$EDITOR mvm.toml
mvmctl machine build
mvmctl machine run --manifest . -d
```

`machine run` needs either a trailing `-- <cmd>` or `-d`/`--detach`; `--name`
alone does not make the machine persist.

The build produces a manifest-keyed slot in the local registry. Subsequent
`mvmctl machine build` calls re-read `mvm.toml`, rebuild the selected flake/profile,
and update the current revision for that slot.

## What makes a good template

- Pin Nix inputs in `flake.lock`.
- Keep `mvm.toml` small: `flake`, `profile`, `vcpus`, `mem`, `data_disk`, and optional `name`.
- Put guest packages and services in the flake, not in ad-hoc host scripts.
- Treat network, secrets, and state retention as explicit runtime policy.
- Avoid mutable OCI tags for production examples; resolve to immutable digests.

## Related pages

- [Create a template](/templates/create/) for scaffolding and presets.
- [Build & list](/templates/build/) for local registry commands.
- [Lifecycle](/templates/lifecycle/) for rebuilds, drift, pruning, and deletion.
- [Manifests](/guides/manifests/) for the complete command reference.
