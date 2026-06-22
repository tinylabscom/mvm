---
title: macOS sandbox debugging
description: Debug local macOS workflows while keeping Linux runtime work in the builder VM.
---

macOS is a supported local development target. Linux-specific build and runtime work still belongs inside the builder VM.

## Checklist

- Use host cargo for checks that compile cleanly.
- Use the builder VM for Nix builds and microVM operations.
- Keep worktree state isolated with `MVM_DATA_DIR`, `CARGO_TARGET_DIR`, and `CARGO_HOME`.
- Do not use a Lima VM for this repo's Nix or microVM work.

## Useful commands

```sh
mvmctl dev status
mvmctl doctor
mvmctl machine logs <name>
mvmctl boot-report <name>
```

When debugging runtime behavior, name the backend and platform in bug reports.
