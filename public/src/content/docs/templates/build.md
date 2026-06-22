---
title: Build & list
description: Build manifest-backed templates and inspect the local mvm registry.
---

Build from the current project:

```sh
mvmctl build
```

Or point at a project directory or manifest file:

```sh
mvmctl build ./my-worker
mvmctl build ./my-worker/mvm.toml
```

`mvmctl build` discovers `mvm.toml` or `Mvmfile.toml`, runs the Nix build
through the builder VM where Linux build work belongs, and stores artifacts in
a local slot keyed by the canonical manifest path.

## Build options

```sh
mvmctl build --force
mvmctl build --update-hash
mvmctl build --vcpus 4 --mem 2G --data-disk 8G
mvmctl build --snapshot
mvmctl build --json
```

Snapshot builds are backend-specific. Do not present snapshot availability or
latency as universal unless the backend and readiness boundary are named.

## Inspect built slots

```sh
mvmctl manifest ls
mvmctl manifest ls --json
mvmctl manifest info
mvmctl manifest info ./my-worker --json
mvmctl manifest verify
```

Use `mvmctl ls`, `mvmctl info`, `mvmctl machine logs`, and `mvmctl machine stop` for running
VMs. Use `mvmctl manifest *` for build slots and registry state.

## Boot after build

```sh
mvmctl up
mvmctl exec ./my-worker -- uname -a
```

If there is no built revision for the manifest, `mvmctl up` should fail with a
hint to run `mvmctl build`.

## Security checklist

- Build Linux artifacts through the builder VM.
- Treat `--force` as an intentional overwrite of the current slot revision.
- Use `manifest verify` when moving artifacts between hosts or debugging cache state.
- Keep mutable registry inputs out of production examples unless they are labeled local-only.
