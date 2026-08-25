---
title: Template lifecycle
description: Rebuild, verify, prune, and remove manifest-backed mvm templates.
---

A template's source is the project directory. A template's built state is the
manifest-keyed slot in the local registry.

## Rebuild

Edit `flake.nix`, source files, or `mvm.toml`, then run:

```sh
mvmctl machine build
```

Resource changes such as `vcpus`, `mem`, and `data_disk` update the slot
record. Identity-shaping changes such as `flake` and `profile` can trigger
drift detection; pass `--force` only when overwriting the existing slot is
intentional.

## Verify

```sh
mvmctl manifest verify
mvmctl manifest verify ./my-worker
mvmctl manifest verify --revision <hash>
```

Verification checks the local slot's recorded checksums. Signature verification
is separate and should stay labeled planned until the release-signing path is
wired end to end.

## Prune

```sh
mvmctl manifest prune --orphans --dry-run
mvmctl manifest prune --orphans
mvmctl cache prune --orphan-builds
```

Orphans are slots whose source manifest no longer exists on disk. Use dry-run
first when cleaning shared development machines.

## Remove

```sh
mvmctl manifest rm ./my-worker
mvmctl manifest rm ./my-worker --force
mvmctl manifest rm ./my-worker --manifest-file
```

Removing a manifest slot deletes local registry state and build artifacts for
that slot. `--manifest-file` also removes the source manifest from disk, so use
it only when retiring the project source as well.

## State and snapshots

Build slots are not the same as running VM state. Running VMs, volumes,
snapshots, and cold-mode artifacts may contain sensitive runtime data. Clean
them through the relevant lifecycle commands before assuming a project has
been fully retired.
