---
title: Build & list
description: Build manifest-backed templates and inspect the local mvm registry.
---

Build from the current project:

```sh
mvmctl machine build
```

Or point at a project directory or manifest file:

```sh
mvmctl machine build ./my-worker
mvmctl machine build ./my-worker/mvm.toml
```

`--flake <ref>` is a different mode: it forces a flake-only build and skips
manifest discovery entirely.

`mvmctl machine build` discovers `mvm.toml` or `Mvmfile.toml`, runs the Nix build
through the builder VM where Linux build work belongs, and stores artifacts in
a local slot keyed by the canonical manifest path.

## Build options

```sh
mvmctl machine build --force
mvmctl machine build --update-hash
mvmctl machine run --flake . --cpus 4 --memory 2G -d
mvmctl machine checkpoint create my-machine --class vm-full
mvmctl machine build --json
```

`machine checkpoint` is an advanced verb: it works, but it is hidden from
`machine --help`.

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

Use `mvmctl machine ls`, `mvmctl machine inspect`, `mvmctl machine logs`, and `mvmctl machine stop` for running
VMs. Use `mvmctl manifest *` for build slots and registry state.

## Boot after build

```sh
mvmctl machine run --manifest . -d
mvmctl machine run --manifest ./my-worker -- uname -a
```

If there is no built revision for the manifest, `mvmctl machine run` should fail with a
hint to run `mvmctl machine build`.

## Security checklist

- Build Linux artifacts through the builder VM.
- Treat `--force` as an intentional overwrite of the current slot revision.
- Use `manifest verify` when moving artifacts between hosts or debugging cache state.
- Keep mutable registry inputs out of production examples unless they are labeled local-only.
