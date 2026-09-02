---
title: Create a template
description: Scaffold a reusable mvm project from a manifest and Nix flake.
---

Use `mvmctl init` to create a reusable project directory:

```sh
mvmctl init my-worker --preset worker
cd my-worker
```

The generated directory contains `mvm.toml` and `flake.nix`. Commit both.
They are the reproducible source for future builds.

## Presets

```sh
mvmctl init my-vm --preset minimal
mvmctl init my-api --preset python
mvmctl init my-web --preset http
mvmctl init my-job --preset worker
mvmctl init my-db --preset postgres
```

Presets choose a starting flake and conservative resources. Edit the files
after scaffolding; the next build reads the current contents from disk.

## Manifest fields

```toml
flake = "."
profile = "default"
vcpus = 2
mem = "1024M"
data_disk = "0"
name = "my-worker"
```

Use the flake for guest content and services. Use the manifest for the build
input pointer, profile selector, and local runtime sizing.

## Prompt-assisted scaffolding

When available, `mvmctl init --prompt` turns a short description into a fixed
preset plan:

```sh
mvmctl init my-api --prompt "Python HTTP API with a background worker"
```

The prompt planner should choose from known scaffolds. It should not emit
free-form shell or unreviewed Nix that bypasses the security model.

## Security checklist

- Review generated files before running `mvmctl machine build`.
- Keep `flake.lock` pinned and committed.
- Do not put credentials in `mvm.toml`, `flake.nix`, or source examples.
- Prefer secret references and explicit runtime grants.
- Keep initial resources small; increase only when the workload needs it.
