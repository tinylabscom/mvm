---
title: Templates
description: Reusable mvm project blueprints built from manifests, Nix flakes, or OCI images.
---

Templates are reusable workload bases. There are two kinds:

- **Project templates** — a project directory with an `mvm.toml` / `Mvmfile.toml`
  and a `flake.nix` that defines the guest rootfs.
- **Image templates** — a named OCI image reference, either built-in
  (`python`, `node`, `rust`, `go`, `ruby`, `java`, `shell`, `data-science`,
  `web-dev`) or created with `mvmctl template build --image <ref>`.

The current reusable blueprint is a project directory with:

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
mvmctl build
mvmctl machine run --manifest .
```

The build produces a manifest-keyed slot in the local registry. Subsequent
`mvmctl build` calls re-read `mvm.toml`, rebuild the selected flake/profile,
and update the current revision for that slot.

## What makes a good template

- Pin Nix inputs in `flake.lock`.
- Keep `mvm.toml` small: `flake`, `profile`, `vcpus`, `mem`, `data_disk`, and optional `name`.
- Put guest packages and services in the flake, not in ad-hoc host scripts.
- Treat network, secrets, and state retention as explicit runtime policy.
- Avoid mutable OCI tags for production examples; resolve to immutable digests.

## Image templates

For one-shot runs that do not need a custom Nix flake, use an image template:

```sh
mvmctl run --template python script.py
mvmctl template build --image python:3.12-alpine --name my-python
mvmctl run --template my-python script.py
```

`--template` is mutually exclusive with `--image`, `--manifest`, and
`--launch-plan`. The name resolves first to a user-built template, then to a
built-in language template, then to a bundled project template.

## Related pages

- [Create a template](/templates/create/) for scaffolding and presets.
- [Build & list](/templates/build/) for local registry commands.
- [Lifecycle](/templates/lifecycle/) for rebuilds, drift, pruning, and deletion.
- [Manifests](/guides/manifests/) for the complete command reference.
